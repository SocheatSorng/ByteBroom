//! Thin Windows adapter: the only module allowed to use `unsafe`.
//!
//! Every target is opened **without following it** (`FILE_FLAG_OPEN_REPARSE_POINT`), and the
//! facts the policy needs are read from that open handle: the real path Windows reports
//! (`GetFinalPathNameByHandleW`), the attributes and the hard-link count. Deletion then happens
//! through the same handle, so what was checked is what gets deleted.
#![allow(unsafe_code)]

pub mod dir;
pub mod fileop;
pub mod hash;
mod layout;
pub mod locations;
pub mod recycle;
pub mod red;
pub mod taskdialog;
pub mod walk;

use crate::paths::{PathError, WinPath};
use crate::policy::ResolvedPath;
pub use layout::system_layout;
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
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfo,
    FileDispositionInfoEx, GetFileInformationByHandle, GetFinalPathNameByHandleW, OPEN_EXISTING,
    SYNCHRONIZE, SetFileInformationByHandle, VOLUME_NAME_DOS,
};

/// What the handle is opened for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read attributes only.
    Inspect,
    /// Read attributes and delete.
    Delete,
    /// Read attributes and contents, and delete (for moving).
    Move,
    /// Read attributes and list a folder's entries (for scanning).
    List,
    /// Read attributes and contents (for hashing while scanning), sharing everything.
    Read,
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
    /// Serial number of the volume the object lives on.
    pub volume_serial: u32,
    /// When its contents last changed (the same clock the walk reports).
    pub modified: std::time::SystemTime,
}

fn wide_verbatim(path: &WinPath) -> Vec<u16> {
    let text = format!("\\\\?\\{path}");
    OsStr::new(&text).encode_wide().chain(Some(0)).collect()
}

/// Open `path` without following it, and read the facts the policy needs from the handle.
pub fn open_no_follow(path: &WinPath, access: Access) -> Result<Opened, OpenError> {
    let wide = wide_verbatim(path);
    let rights = FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
        | match access {
            Access::Inspect => 0,
            Access::Delete => DELETE,
            Access::Move => DELETE | FILE_READ_DATA,
            Access::List => FILE_LIST_DIRECTORY,
            Access::Read => FILE_READ_DATA,
        };
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call; the other
    // arguments are plain flags and null pointers, which CreateFileW accepts.
    let raw: HANDLE = unsafe {
        CreateFileW(
            wide.as_ptr(),
            rights,
            // A move must not lose bytes another program writes after the copy, so it refuses
            // to share write access: a file open for writing is "in use" (security review).
            if access == Access::Move {
                FILE_SHARE_READ | FILE_SHARE_DELETE
            } else {
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            },
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
        volume_serial: info.dwVolumeSerialNumber,
        modified: crate::walk::from_file_time(
            ((i64::from(info.ftLastWriteTime.dwHighDateTime)) << 32)
                | i64::from(info.ftLastWriteTime.dwLowDateTime),
        ),
    })
}

fn zero_time() -> windows_sys::Win32::Foundation::FILETIME {
    windows_sys::Win32::Foundation::FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    }
}

pub(crate) fn final_path(handle: &OwnedHandle) -> Result<WinPath, OpenError> {
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

impl Opened {
    /// Windows' number for this file or folder, read from the open handle; the same numbering the
    /// walk reports (`None` on file systems without file IDs, e.g. FAT).
    pub fn file_id(&self) -> Option<crate::walk::FileId> {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
        };
        let mut info = FILE_ID_INFO {
            VolumeSerialNumber: 0,
            FileId: windows_sys::Win32::Storage::FileSystem::FILE_ID_128 {
                Identifier: [0; 16],
            },
        };
        // SAFETY: the handle is open; `info` is a writable FILE_ID_INFO of exactly the size given.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                self.handle.as_raw_handle(),
                FileIdInfo,
                (&raw mut info).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        };
        let id = info.FileId.Identifier;
        (ok != 0 && id.iter().any(|b| *b != 0)).then_some(crate::walk::FileId {
            volume: self.volume_serial,
            id,
        })
    }

    /// Where the object behind this handle is now, read from the handle (it follows the file if
    /// it was moved or renamed since it was opened).
    pub fn current_path(&self) -> Result<WinPath, OpenError> {
        final_path(&self.handle)
    }

    /// A reader for the file's contents, on a duplicate of the checked handle, so the bytes
    /// read are those of the file that passed the check. Needs [`Access::Move`] or [`Access::Read`].
    ///
    /// Duplicated handles share one file position, so the reader is rewound to the start:
    /// without that, a second reader would begin at the end and read nothing.
    pub fn reader(&self) -> io::Result<std::fs::File> {
        use std::io::{Seek, SeekFrom};
        let mut file = std::fs::File::from(self.handle.try_clone()?);
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }
}

/// Delete the file or (empty) folder behind `opened`, through its own handle. The handle must
/// have been opened with [`Access::Delete`]. POSIX semantics remove the name at once; on file
/// systems without them, Windows' classic "delete on close" is used.
pub fn delete_by_handle(opened: Opened) -> io::Result<()> {
    dispose(&opened.handle)
    // `opened` drops here; closing the handle completes a classic delete.
}

/// Mark the object behind `handle` (opened with DELETE access) for deletion.
pub(crate) fn dispose(handle: &OwnedHandle) -> io::Result<()> {
    let ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    let raw = handle.as_raw_handle();
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
}

/// The names of a folder's direct children. Path-based, so callers re-open and re-check each
/// child before acting on it.
///
/// A name that is not valid Unicode can't be represented exactly (a lossy copy could name a
/// different file), so such a folder is refused as a whole and kept (security review note).
pub fn list_children(dir: &WinPath) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(format!("\\\\?\\{dir}"))? {
        let name = entry?.file_name().into_string().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "it holds a name that is not valid Unicode",
            )
        })?;
        names.push(name);
    }
    Ok(names)
}
