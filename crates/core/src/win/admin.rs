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
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW,
};
use windows_sys::Win32::System::SystemInformation::{
    GetSystemDirectoryW, GetSystemWindowsDirectoryW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramFiles, SEE_MASK_CLASSKEY, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
    SHELLEXECUTEINFOW, ShellExecuteExW,
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
            return Some(format!(
                "{path} is not exactly where expected (a link, or a different name)"
            ));
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

/// `HKLM\SOFTWARE\Classes\exefile`, opened read-only: the machine-wide class for programs.
struct MachineClass(HKEY);

impl MachineClass {
    fn open() -> Option<Self> {
        let sub = wide("SOFTWARE\\Classes\\exefile");
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: `sub` is NUL-terminated; `key` receives a key handle closed in Drop.
        let err = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut key) };
        (err == 0 && !key.is_null()).then_some(Self(key))
    }
}

impl Drop for MachineClass {
    fn drop(&mut self) {
        // SAFETY: the key was opened by RegOpenKeyExW and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Windows' System32 folder, from the API (not an environment variable).
pub fn system32() -> Option<WinPath> {
    let mut buf = vec![0u16; 512];
    // SAFETY: `buf` is writable for its length.
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len == 0 || len >= buf.len() {
        return None;
    }
    WinPath::parse(&String::from_utf16(&buf[..len]).ok()?).ok()
}

/// Windows' own folder, from the API (`GetSystemWindowsDirectoryW`), not the environment.
pub fn windows_dir() -> Option<WinPath> {
    let mut buf = vec![0u16; 512];
    // SAFETY: `buf` is writable for its length.
    let len = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if len == 0 || len >= buf.len() {
        return None;
    }
    WinPath::parse(&String::from_utf16(&buf[..len]).ok()?).ok()
}

/// Replace this process's whole environment with [`crate::admin::fixed_environment`] (review
/// of task 2, S2). The helper calls it first thing, while it is the only thread; it must not be
/// called once other threads may read the environment.
pub fn reset_environment() -> bool {
    let (Some(windows), Some(system32)) = (windows_dir(), system32()) else {
        return false;
    };
    let fixed = crate::admin::fixed_environment(&windows.to_string(), &system32.to_string());
    let old: Vec<std::ffi::OsString> = std::env::vars_os().map(|(k, _)| k).collect();
    for key in old {
        // SAFETY: called at the start of the helper's `main`, before any other thread exists,
        // so nothing reads the environment meanwhile.
        unsafe { std::env::remove_var(&key) };
    }
    for (key, value) in fixed {
        // SAFETY: as above.
        unsafe { std::env::set_var(key, value) };
    }
    true
}

/// Make System32 this process's current folder, so nothing is looked up in a folder the user
/// chose (review S4). Called by the helper before anything else.
pub fn enter_system32() -> bool {
    system32().is_some_and(|dir| std::env::set_current_dir(dir.to_string()).is_ok())
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
    // The verb is looked up in the machine's own program class, never the per-user one, which
    // the user's account could override to start another program at the prompt (review S2).
    let class = MachineClass::open()
        .ok_or_else(|| LaunchError::Failed("Windows' program class can't be read".into()))?;
    // The elevated helper starts in System32, not in a folder the user chose (review S4).
    let dir = system32().ok_or_else(|| LaunchError::Failed("System32 can't be found".into()))?;
    let verb = wide("runas");
    let file = wide(&exe.to_string());
    let params = wide(action.arg());
    let directory = wide(&dir.to_string());
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_CLASSKEY,
        hwnd: parent as _,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: params.as_ptr(),
        lpDirectory: directory.as_ptr(),
        nShow: SW_HIDE,
        hkeyClass: class.0,
        // SAFETY: SHELLEXECUTEINFOW is plain data; all-zero is its documented empty state.
        ..unsafe { std::mem::zeroed() }
    };
    // SAFETY: `info`, every string it points to and the class key live until the call returns.
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
