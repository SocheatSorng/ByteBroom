//! Windows side of the elevated helper (phase 4): reading who owns and may change a file or
//! folder, whether this process is elevated, where the helper lives, and starting it through
//! UAC. The rules are in [`crate::admin`].

use super::{Access, OpenError, Opened, layout::known_folder, open_no_follow};
use crate::admin::{Ace, AdminAction, Exit, Place, Security, problem};
use crate::paths::WinPath;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{ERROR_CANCELLED, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetTokenInformation,
    INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSID, TOKEN_ELEVATION, TOKEN_QUERY,
    TokenElevation,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramFiles, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    ShellExecuteExW,
};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const INFINITE: u32 = u32::MAX;
const SW_HIDE: i32 = 0;

/// The helper's folder name under Program Files, and its file name.
pub const HELPER_FOLDER: &str = "ByteBroom";
/// The helper's file name.
pub const HELPER_EXE: &str = "bytebroom-admin.exe";

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(Some(0)).collect()
}

/// A SID as text (`S-1-...`), or `"?"`.
///
/// # Safety
/// `sid` must point to a valid SID (or be null).
unsafe fn sid_text(sid: PSID) -> String {
    if sid.is_null() {
        return "?".into();
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is valid (caller); `text` receives a LocalAlloc'd string freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return "?".into();
    }
    // SAFETY: the string is NUL-terminated.
    let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
    // SAFETY: `len` units were just read as valid.
    let s = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })
        .unwrap_or_else(|_| "?".into());
    // SAFETY: allocated by ConvertSidToStringSidW with LocalAlloc; freed once.
    unsafe { LocalFree(text as HLOCAL) };
    s
}

/// The owner and access list of the object behind `opened` (opened with [`Access::Security`]).
pub fn security_of(opened: &Opened) -> Option<Security> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: the handle is open with READ_CONTROL; the out pointers are valid. `owner` and
    // `dacl` point into `sd`, which is freed once at the end.
    let err = unsafe {
        GetSecurityInfo(
            opened.handle.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return None;
    }
    // SAFETY: `owner` points into `sd`, which is alive.
    let owner_text = unsafe { sid_text(owner) };
    let aces = if dacl.is_null() {
        None
    } else {
        // SAFETY: `dacl` points to a valid ACL inside `sd`.
        let count = unsafe { (*dacl).AceCount };
        let mut list = Vec::with_capacity(usize::from(count));
        for i in 0..u32::from(count) {
            let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `i` is below the ACL's count; `ace` receives a pointer into the ACL.
            if unsafe { GetAce(dacl, i, &mut ace) } == 0 || ace.is_null() {
                list.push(unknown_allow());
                continue;
            }
            // SAFETY: every ACE starts with an ACE_HEADER.
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            let inherit_only = u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0;
            match header.AceType {
                ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE => {
                    // SAFETY: both types share ACCESS_ALLOWED_ACE's layout; the SID starts at
                    // `SidStart` and lies within the ACE.
                    let a = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                    let sid = (&raw const a.SidStart)
                        .cast_mut()
                        .cast::<std::ffi::c_void>();
                    list.push(Ace {
                        // SAFETY: `sid` points to the ACE's SID, inside the live descriptor.
                        sid: unsafe { sid_text(sid) },
                        mask: a.Mask,
                        allow: header.AceType == ACCESS_ALLOWED_ACE_TYPE,
                        inherit_only,
                    });
                }
                // A kind this code doesn't read (object or callback ACEs): never trusted.
                _ if inherit_only => {}
                _ => list.push(unknown_allow()),
            }
        }
        Some(list)
    };
    // SAFETY: `sd` was allocated by GetSecurityInfo with LocalAlloc; freed once, after use.
    unsafe { LocalFree(sd as HLOCAL) };
    Some(Security {
        owner: owner_text,
        dacl: aces,
    })
}

fn unknown_allow() -> Ace {
    Ace {
        sid: "?".into(),
        mask: u32::MAX,
        allow: true,
        inherit_only: false,
    }
}

/// Why the file `exe` is not in an admin-owned place, or `None` if it is: the file and its
/// folder ([`Place::Own`]) and every folder above it up to the drive root ([`Place::Above`]).
/// Each is opened without following links and must be exactly where expected.
pub fn location_problem(exe: &WinPath) -> Option<String> {
    let parts = exe.parts();
    if parts.is_empty() {
        return Some("no file name".into());
    }
    let mut chain = vec![(exe.clone(), Place::Own)];
    let mut current = WinPath::drive_root(exe.drive());
    let mut folders = vec![(current.clone(), Place::Above)];
    for (i, part) in parts[..parts.len() - 1].iter().enumerate() {
        current = match current.join(part) {
            Ok(p) => p,
            Err(e) => return Some(e.to_string()),
        };
        let place = if i + 2 == parts.len() {
            Place::Own
        } else {
            Place::Above
        };
        folders.push((current.clone(), place));
    }
    chain.extend(folders);
    for (path, place) in chain {
        let opened = match open_no_follow(&path, Access::Security) {
            Ok(o) => o,
            Err(e) => return Some(format!("{path}: {e}")),
        };
        if opened.resolved.is_reparse_point || opened.resolved.final_path != path {
            return Some(format!("{path} is reached through a link"));
        }
        let Some(sec) = security_of(&opened) else {
            return Some(format!("{path}: its permissions can't be read"));
        };
        if let Some(why) = problem(&sec, place) {
            return Some(format!("{path}: {why}"));
        }
    }
    None
}

/// Is this process running with administrator rights (an elevated token)?
pub fn is_elevated() -> bool {
    let mut raw = std::ptr::null_mut();
    // SAFETY: the current-process pseudo handle needs no closing; `raw` receives a token handle
    // we own.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return false;
    }
    // SAFETY: OpenProcessToken succeeded; the OwnedHandle closes it once.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: the token is open for query; `elevation` is the right type and size.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&raw mut elevation).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    ok != 0 && elevation.TokenIsElevated != 0
}

/// Load later DLLs only from System32 (no planting next to the program or in the current
/// folder). Called first thing by the helper.
pub fn load_dlls_from_system32_only() -> bool {
    // SAFETY: plain flag call.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != 0 }
}

/// This program's own file, opened without following links.
pub fn own_exe() -> Option<WinPath> {
    let mut buf = vec![0u16; 1024];
    loop {
        let cap = u32::try_from(buf.len()).ok()?;
        // SAFETY: `buf` is writable for `cap` units; a null module means this program.
        let len =
            unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), cap) } as usize;
        if len == 0 {
            return None;
        }
        if len < buf.len() {
            let text = String::from_utf16(&buf[..len]).ok()?;
            let text = text.strip_prefix("\\\\?\\").unwrap_or(&text).to_string();
            let asked = WinPath::parse(&text).ok()?;
            let opened = open_no_follow(&asked, Access::Inspect).ok()?;
            return (!opened.resolved.is_reparse_point).then_some(opened.resolved.final_path);
        }
        if buf.len() >= 32 * 1024 {
            return None;
        }
        buf.resize(buf.len() * 2, 0);
    }
}

/// Where the installed helper lives: `<Program Files>\ByteBroom\bytebroom-admin.exe`.
pub fn helper_path() -> Option<WinPath> {
    known_folder(&FOLDERID_ProgramFiles)?
        .join(HELPER_FOLDER)
        .ok()?
        .join(HELPER_EXE)
        .ok()
}

/// Why starting the helper didn't give an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchError {
    /// The helper isn't installed (or can't be found).
    NotInstalled,
    /// The helper is in a place ordinary users could change, so it isn't started.
    Untrusted(String),
    /// The owner answered No at the UAC prompt.
    Cancelled,
    /// Windows couldn't start it or wait for it.
    Failed(String),
}

/// Start the installed helper as administrator for `action` (Windows shows the UAC prompt,
/// owned by `parent`, a window handle or 0), wait for it, and read its answer. The helper's
/// place is checked first; it checks again itself.
pub fn run_elevated(action: AdminAction, parent: isize) -> Result<Exit, LaunchError> {
    let exe = helper_path().ok_or(LaunchError::NotInstalled)?;
    match open_no_follow(&exe, Access::Inspect) {
        Ok(o) if !o.is_directory => {}
        Ok(_) | Err(OpenError::NotFound) => return Err(LaunchError::NotInstalled),
        Err(e) => return Err(LaunchError::Failed(e.to_string())),
    }
    if let Some(why) = location_problem(&exe) {
        return Err(LaunchError::Untrusted(why));
    }
    let verb = wide("runas");
    let file = wide(&exe.to_string());
    let params = wide(action.arg());
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        hwnd: parent as _,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: params.as_ptr(),
        nShow: SW_HIDE,
        // SAFETY: SHELLEXECUTEINFOW is plain data; all-zero is its documented empty state.
        ..unsafe { std::mem::zeroed() }
    };
    // SAFETY: `info` and every string it points to live until the call returns.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let err = std::io::Error::last_os_error();
        return Err(if err.raw_os_error() == Some(ERROR_CANCELLED as i32) {
            LaunchError::Cancelled
        } else {
            LaunchError::Failed(err.to_string())
        });
    }
    if info.hProcess.is_null() {
        return Err(LaunchError::Failed("no process handle".into()));
    }
    // SAFETY: SEE_MASK_NOCLOSEPROCESS gives us the process handle to close.
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    let mut code = 0u32;
    // SAFETY: the handle is a live process handle we own.
    let ok = unsafe {
        WaitForSingleObject(process.as_raw_handle(), INFINITE);
        GetExitCodeProcess(process.as_raw_handle(), &mut code)
    };
    if ok == 0 {
        return Err(LaunchError::Failed(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(Exit::from_code(code))
}
