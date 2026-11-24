//! Thin Windows adapter: the only module allowed to use `unsafe`.
//!
//! Every target is opened **without following it** (`FILE_FLAG_OPEN_REPARSE_POINT`), and the
//! facts the policy needs are read from that open handle: the real path Windows reports
//! (`GetFinalPathNameByHandleW`), the attributes and the hard-link count. Deletion then happens
//! through the same handle, so what was checked is what gets deleted.
#![allow(unsafe_code)]

pub mod recycle;

use crate::paths::{PathError, WinPath};
use crate::policy::{ResolvedPath, SystemLayout};
use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
    ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfo, FileDispositionInfoEx,
    GetFileInformationByHandle, GetFinalPathNameByHandleW, OPEN_EXISTING, SYNCHRONIZE,
    SetFileInformationByHandle, VOLUME_NAME_DOS,
};

/// What the handle is opened for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read attributes only.
    Inspect,
    /// Read attributes and delete.
    Delete,
}

/// Why a target could not be opened.
#[derive(Debug)]
pub enum OpenError {
    /// Another program holds it open without sharing.
    InUse,
    /// It does not exist (any more).
    NotFound,
    /// Windows refused access (needs administrator rights, or protected).
    AccessDenied,
    /// Windows reported a path that ByteBroom refuses to act on.
    UnsupportedPath(PathError),
    /// Any other Windows error.
    Other(io::Error),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InUse => write!(f, "in use by another program"),
            Self::NotFound => write!(f, "no longer exists"),
            Self::AccessDenied => write!(f, "access denied"),
            Self::UnsupportedPath(e) => write!(f, "unsupported path: {e}"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OpenError {}

fn classify(err: io::Error) -> OpenError {
    match err.raw_os_error().map(|c| c as u32) {
        Some(ERROR_SHARING_VIOLATION) => OpenError::InUse,
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => OpenError::NotFound,
        Some(ERROR_ACCESS_DENIED) => OpenError::AccessDenied,
        _ => OpenError::Other(err),
    }
}

/// A target opened without following it, plus what Windows says about it.
#[derive(Debug)]
pub struct Opened {
    handle: OwnedHandle,
    /// The real path and whether it is a reparse point.
    pub resolved: ResolvedPath,
    /// A folder (or a junction, which also has the directory attribute).
    pub is_directory: bool,
    /// Size in bytes (0 for folders).
    pub size: u64,
    /// Number of hard links (names) the file has.
    pub link_count: u32,
}

fn wide_verbatim(path: &WinPath) -> Vec<u16> {
    let text = format!("\\\\?\\{path}");
    OsStr::new(&text).encode_wide().chain(Some(0)).collect()
}

/// Open `path` without following it, and read the facts the policy needs from the handle.
pub fn open_no_follow(path: &WinPath, access: Access) -> Result<Opened, OpenError> {
    let wide = wide_verbatim(path);
    let rights =
        FILE_READ_ATTRIBUTES | SYNCHRONIZE | if access == Access::Delete { DELETE } else { 0 };
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call; the other
    // arguments are plain flags and null pointers, which CreateFileW accepts.
    let raw: HANDLE = unsafe {
        CreateFileW(
            wide.as_ptr(),
            rights,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(classify(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a valid handle we own; OwnedHandle closes it exactly once.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };

    let mut info = BY_HANDLE_FILE_INFORMATION {
        dwFileAttributes: 0,
        ftCreationTime: zero_time(),
        ftLastAccessTime: zero_time(),
        ftLastWriteTime: zero_time(),
        dwVolumeSerialNumber: 0,
        nFileSizeHigh: 0,
        nFileSizeLow: 0,
        nNumberOfLinks: 0,
        nFileIndexHigh: 0,
        nFileIndexLow: 0,
    };
    // SAFETY: the handle is open and `info` is a valid, writable struct of the right type.
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &mut info) } == 0 {
        return Err(classify(io::Error::last_os_error()));
    }
    let final_path = final_path(&handle)?;
    let attrs = info.dwFileAttributes;
    let is_directory = attrs & FILE_ATTRIBUTE_DIRECTORY != 0;
    Ok(Opened {
        handle,
        resolved: ResolvedPath {
            final_path,
            is_reparse_point: attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        },
        is_directory,
        size: if is_directory {
            0
        } else {
            (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow)
        },
        link_count: info.nNumberOfLinks,
    })
}

fn zero_time() -> windows_sys::Win32::Foundation::FILETIME {
    windows_sys::Win32::Foundation::FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    }
}

fn final_path(handle: &OwnedHandle) -> Result<WinPath, OpenError> {
    let mut buf: Vec<u16> = vec![0; 512];
    loop {
        let cap = u32::try_from(buf.len()).map_err(|_| OpenError::NotFound)?;
        // SAFETY: `buf` is writable for `cap` UTF-16 units; the handle is open.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                handle.as_raw_handle(),
                buf.as_mut_ptr(),
                cap,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if len == 0 {
            return Err(classify(io::Error::last_os_error()));
        }
        if len < buf.len() {
            let text = String::from_utf16(&buf[..len])
                .map_err(|_| OpenError::UnsupportedPath(PathError::NotAbsolute))?;
            return WinPath::parse(&text).map_err(OpenError::UnsupportedPath);
        }
        // Too small: `len` is the size needed, including the terminating NUL.
        buf.resize(len + 1, 0);
    }
}

/// Delete the file or (empty) folder behind `opened`, through its own handle. The handle must
/// have been opened with [`Access::Delete`]. POSIX semantics remove the name at once; on file
/// systems without them, Windows' classic "delete on close" is used.
pub fn delete_by_handle(opened: Opened) -> io::Result<()> {
    let ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    let raw = opened.handle.as_raw_handle();
    // SAFETY: the handle is open with DELETE access; `ex` is the struct this class expects.
    let ok = unsafe {
        SetFileInformationByHandle(
            raw,
            FileDispositionInfoEx,
            (&ex as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if ok != 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if !matches!(
        err.raw_os_error().map(|c| c as u32),
        Some(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED)
    ) {
        return Err(err);
    }
    let classic = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: as above, with the older struct for the older class.
    let ok = unsafe {
        SetFileInformationByHandle(
            raw,
            FileDispositionInfo,
            (&classic as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if ok != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
    // `opened` drops here; closing the handle completes a classic delete.
}

/// The names of a folder's direct children. Path-based, so callers re-open and re-check each
/// child before acting on it.
pub fn list_children(dir: &WinPath) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(format!("\\\\?\\{dir}"))? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    Ok(names)
}

fn env_path(name: &str) -> Option<WinPath> {
    std::env::var(name)
        .ok()
        .and_then(|v| WinPath::parse(&v).ok())
}

/// Where Windows keeps its own folders on this PC, read from the environment. Missing values
/// fall back to the standard locations, so the hard floor is never empty.
pub fn system_layout() -> SystemLayout {
    let fallback = |s: &str| WinPath::parse(s).ok();
    let system_root = env_path("SystemRoot")
        .or_else(|| fallback("C:\\Windows"))
        .unwrap_or_else(|| unreachable_layout("SystemRoot"));
    let mut program_files: Vec<WinPath> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .filter_map(|n| env_path(n))
        .collect();
    program_files.extend(fallback("C:\\Program Files"));
    program_files.extend(fallback("C:\\Program Files (x86)"));
    let program_data = env_path("ProgramData")
        .or_else(|| fallback("C:\\ProgramData"))
        .unwrap_or_else(|| unreachable_layout("ProgramData"));
    let profile = env_path("USERPROFILE");
    let profiles_dir = profile
        .as_ref()
        .and_then(parent)
        .or_else(|| fallback("C:\\Users"))
        .unwrap_or_else(|| unreachable_layout("profiles"));
    let mut profile_roots: Vec<WinPath> = list_children(&profiles_dir)
        .unwrap_or_default()
        .iter()
        .filter_map(|name| profiles_dir.join(name).ok())
        .collect();
    profile_roots.extend(profile);
    SystemLayout {
        system_root,
        program_files,
        program_data,
        profiles_dir,
        profile_roots,
    }
}

fn parent(path: &WinPath) -> Option<WinPath> {
    let parts = path.parts();
    let (_, head) = parts.split_last()?;
    WinPath::parse(&format!("{}:\\{}", path.drive(), head.join("\\"))).ok()
}

/// The fallbacks above are fixed, valid literals, so this is never reached; it exists so the
/// code needs no `unwrap`. `C:\` is the most protective answer: the whole drive counts as Windows.
fn unreachable_layout(_what: &str) -> WinPath {
    WinPath::drive_root('C')
}
