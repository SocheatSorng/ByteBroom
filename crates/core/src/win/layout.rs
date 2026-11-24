//! Where Windows keeps its own folders, for the hard floor.
//!
//! Environment variables can be changed by any program running as the user (`HKCU\Environment`),
//! so they are never the only source (security review, should-fix 4). The primary values come
//! from Windows APIs and `HKLM`; environment values and the standard literal paths are only ever
//! **added** as extra protected areas, so steering them can make ByteBroom refuse more, never less.

use super::list_children;
use crate::paths::WinPath;
use crate::policy::SystemLayout;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_Profile, FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86,
    FOLDERID_UserProfiles, SHGetKnownFolderPath,
};
use windows_sys::core::{GUID, PWSTR};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn parse(text: &str) -> Option<WinPath> {
    WinPath::parse(text).ok()
}

/// `GetSystemWindowsDirectoryW`: the real Windows folder, not the `SystemRoot` variable.
fn windows_dir() -> Option<WinPath> {
    let mut buf = vec![0u16; 512];
    // SAFETY: `buf` is writable for its length.
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    (n > 0 && n < buf.len())
        .then(|| String::from_utf16(&buf[..n]).ok())
        .flatten()
        .and_then(|s| parse(&s))
}

fn known_folder(id: &GUID) -> Option<WinPath> {
    let mut out: PWSTR = std::ptr::null_mut();
    // SAFETY: `id` is a valid GUID; `out` receives a CoTaskMem string we free below.
    let hr = unsafe {
        SHGetKnownFolderPath(
            id,
            0,
            std::ptr::null_mut::<core::ffi::c_void>() as HANDLE,
            &mut out,
        )
    };
    if out.is_null() {
        return None;
    }
    let text = if hr == 0 {
        // SAFETY: on success `out` is a NUL-terminated UTF-16 string.
        let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
        // SAFETY: `len` units were just read as valid.
        String::from_utf16(unsafe { std::slice::from_raw_parts(out, len) }).ok()
    } else {
        None
    };
    // SAFETY: `out` came from SHGetKnownFolderPath and is freed exactly once.
    unsafe { CoTaskMemFree(out.cast()) };
    text.and_then(|t| parse(&t))
}

/// Every profile folder listed in `HKLM\...\ProfileList`, on any drive. `%SystemDrive%` is
/// expanded from the real Windows folder, never from the environment.
fn registry_profiles(windows: Option<&WinPath>) -> Vec<WinPath> {
    let key_path = wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList");
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: valid NUL-terminated key path; `key` receives an open key closed below.
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path.as_ptr(), 0, KEY_READ, &mut key) } != 0 {
        return Vec::new();
    }
    let drive = windows.map_or('C', WinPath::drive);
    let mut found = Vec::new();
    for index in 0..4096u32 {
        let mut name = vec![0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: `name` is writable for `len` units; the other out-pointers are optional (null).
        let status = unsafe {
            RegEnumKeyExW(
                key,
                index,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            break;
        }
        name.truncate(len as usize);
        name.push(0);
        let value = wide("ProfileImagePath");
        let mut data = vec![0u16; 1024];
        let mut size = (data.len() * 2) as u32;
        // SAFETY: `data` is writable for `size` bytes; subkey and value names are NUL-terminated.
        let status = unsafe {
            RegGetValueW(
                key,
                name.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND,
                std::ptr::null_mut(),
                data.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status != 0 {
            continue;
        }
        let units = (size as usize / 2).min(data.len());
        let text = String::from_utf16_lossy(&data[..units]);
        let text = text.trim_end_matches('\0');
        let expanded = replace_ignore_ascii_case(text, "%SystemDrive%", &format!("{drive}:"));
        if !expanded.contains('%')
            && let Some(p) = parse(&expanded)
        {
            found.push(p);
        }
    }
    // SAFETY: `key` was opened above and is closed exactly once.
    unsafe { RegCloseKey(key) };
    found
}

fn replace_ignore_ascii_case(text: &str, pattern: &str, with: &str) -> String {
    let lower = text.to_ascii_lowercase();
    match lower.find(&pattern.to_ascii_lowercase()) {
        Some(at) => format!("{}{}{}", &text[..at], with, &text[at + pattern.len()..]),
        None => text.to_string(),
    }
}

fn env_path(name: &str) -> Option<WinPath> {
    std::env::var(name).ok().and_then(|v| parse(&v))
}

fn push_unique(list: &mut Vec<WinPath>, path: Option<WinPath>) {
    if let Some(p) = path
        && !list.iter().any(|q| q.eq_ignore_case(&p))
    {
        list.push(p);
    }
}

/// Where Windows keeps its own folders on this PC (see the module comment for the sources).
pub fn system_layout() -> SystemLayout {
    let api_windows = windows_dir();
    let system_root = api_windows
        .clone()
        .or_else(|| parse("C:\\Windows"))
        .unwrap_or_else(|| WinPath::drive_root('C'));

    let mut program_files = Vec::new();
    for p in [
        known_folder(&FOLDERID_ProgramFiles),
        known_folder(&FOLDERID_ProgramFilesX86),
        env_path("ProgramFiles"),
        env_path("ProgramFiles(x86)"),
        env_path("ProgramW6432"),
        parse("C:\\Program Files"),
        parse("C:\\Program Files (x86)"),
    ] {
        push_unique(&mut program_files, p);
    }

    let program_data = known_folder(&FOLDERID_ProgramData)
        .or_else(|| parse("C:\\ProgramData"))
        .unwrap_or_else(|| WinPath::drive_root('C'));
    let profiles_dir = known_folder(&FOLDERID_UserProfiles)
        .or_else(|| parse("C:\\Users"))
        .unwrap_or_else(|| WinPath::drive_root('C'));

    let mut profile_roots = Vec::new();
    for p in registry_profiles(api_windows.as_ref()) {
        push_unique(&mut profile_roots, Some(p));
    }
    for name in list_children(&profiles_dir).unwrap_or_default() {
        push_unique(&mut profile_roots, profiles_dir.join(&name).ok());
    }
    push_unique(&mut profile_roots, known_folder(&FOLDERID_Profile));
    push_unique(&mut profile_roots, env_path("USERPROFILE"));

    // Anything the environment or the literals say that differs from the APIs is protected too.
    let mut extra_denied = Vec::new();
    for p in [
        env_path("SystemRoot"),
        env_path("windir"),
        parse("C:\\Windows"),
    ] {
        if let Some(p) = p
            && !p.eq_ignore_case(&system_root)
        {
            push_unique(&mut extra_denied, Some(p));
        }
    }
    for p in [env_path("ProgramData"), parse("C:\\ProgramData")] {
        if let Some(p) = p
            && !p.eq_ignore_case(&program_data)
        {
            push_unique(&mut extra_denied, Some(p));
        }
    }

    SystemLayout {
        system_root,
        program_files,
        program_data,
        profiles_dir,
        profile_roots,
        extra_denied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_comes_from_the_api_and_matches_the_real_folder() {
        let layout = system_layout();
        assert!(
            layout.system_root.parts().len() == 1,
            "{}",
            layout.system_root
        );
        assert!(!layout.profile_roots.is_empty());
        assert!(!layout.program_files.is_empty());
    }

    #[test]
    fn system_drive_is_expanded_without_the_environment() {
        assert_eq!(
            replace_ignore_ascii_case("%SYSTEMDRIVE%\\Users\\Ann", "%SystemDrive%", "C:"),
            "C:\\Users\\Ann"
        );
        assert_eq!(
            replace_ignore_ascii_case("D:\\Ann", "%SystemDrive%", "C:"),
            "D:\\Ann"
        );
    }
}
