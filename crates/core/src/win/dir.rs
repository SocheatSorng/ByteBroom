//! Folders held open so they can't be swapped, and new files created *inside* those handles.
//!
//! The security review (must-fix 1-3) showed that any step done by path after a check can be
//! redirected: rename a checked folder away, put a junction in its place, and the next write or
//! delete lands somewhere else, which matters once ByteBroom runs as administrator. So:
//!
//! - [`lock_dir`] opens a folder without following it and **without delete-sharing**. While the
//!   handle is held, nobody can rename, move or replace that folder.
//! - [`LockedDir::create_file`] and [`LockedDir::create_dir`] create a new object relative to the
//!   held handle (`NtCreateFile` with `RootDirectory`), with `FILE_CREATE` and
//!   `FILE_OPEN_REPARSE_POINT`: an existing name, including a planted link, is a collision, never
//!   something to follow or overwrite.
//! - A [`Created`] file is written, read back and, if needed, deleted through its own handle.

use super::{OpenError, dispose, final_path};
use crate::paths::WinPath;
use std::ffi::OsStr;
use std::io::{self, Seek, SeekFrom};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    RtlNtStatusToDosErrorNoTeb,
};
use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE,
    STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_COLLISION, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, GetFileInformationByHandle, OPEN_EXISTING, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

/// A folder held open without delete-sharing: it can't be renamed, moved or replaced.
#[derive(Debug)]
pub struct LockedDir {
    handle: OwnedHandle,
    /// The folder's real path, read from the held handle.
    pub path: WinPath,
    /// Serial number of the folder's volume.
    pub volume_serial: u32,
}

/// Why a create failed.
#[derive(Debug)]
pub enum CreateError {
    /// Something (a file, folder or link) already has that name.
    Exists,
    /// The name is not a single valid path part.
    BadName(String),
    /// Any other error.
    Other(io::Error),
}

impl std::fmt::Display for CreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exists => write!(f, "that name is already taken"),
            Self::BadName(why) => write!(f, "bad name: {why}"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

fn info(handle: &OwnedHandle) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open and `info` is a valid, writable struct of the right type.
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

/// Hold `path` (a real folder, not a link) open without delete-sharing.
pub fn lock_dir(path: &WinPath) -> Result<LockedDir, OpenError> {
    let wide: Vec<u16> = OsStr::new(&format!("\\\\?\\{path}"))
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: NUL-terminated string that outlives the call; flags and null pointers are valid.
    let raw: HANDLE = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE,
            // No FILE_SHARE_DELETE: while held, nobody can rename or remove this folder.
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(super::classify(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a valid handle we own.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let facts = info(&handle).map_err(super::classify)?;
    if facts.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || facts.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(OpenError::UnsupportedPath(
            crate::paths::PathError::BadComponent("not a real folder".into()),
        ));
    }
    let real = final_path(&handle)?;
    Ok(LockedDir {
        handle,
        path: real,
        volume_serial: facts.dwVolumeSerialNumber,
    })
}

impl LockedDir {
    fn nt_create(
        &self,
        name: &str,
        access: u32,
        share: u32,
        options: u32,
    ) -> Result<(OwnedHandle, WinPath), CreateError> {
        // The same strict rules as every other path part: no "..", no streams, no separators.
        let expected = self
            .path
            .join(name)
            .map_err(|e| CreateError::BadName(e.to_string()))?;
        let (status, raw) = self.raw_open(name, access, share, FILE_CREATE, options)?;
        if status == STATUS_OBJECT_NAME_COLLISION {
            return Err(CreateError::Exists);
        }
        if (status < 0 || raw.is_null()) && self.name_taken(name) {
            // Some existing objects (e.g. a junction) make a create fail with "access denied"
            // instead of "name collision"; either way the name is taken, so try another.
            return Err(CreateError::Exists);
        }
        if status < 0 || raw.is_null() {
            // SAFETY: plain conversion of a status code.
            let code = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
            return Err(CreateError::Other(io::Error::from_raw_os_error(
                code as i32,
            )));
        }
        // SAFETY: NtCreateFile succeeded, so `raw` is a handle we own.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        // Belt and braces: the new object must sit exactly where we asked.
        let real =
            final_path(&handle).map_err(|e| CreateError::Other(io::Error::other(e.to_string())))?;
        if real != expected {
            let _ = dispose(&handle);
            return Err(CreateError::Other(io::Error::other(
                "the new item did not land where expected",
            )));
        }
        Ok((handle, real))
    }

    /// Is anything (file, folder or link) named `name` in this folder? Opened relative to the
    /// held handle, without following it, and closed at once.
    fn name_taken(&self, name: &str) -> bool {
        match self.raw_open(
            name,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            0,
        ) {
            Ok((status, raw)) if status >= 0 && !raw.is_null() => {
                // SAFETY: the open succeeded, so `raw` is a handle we own; dropping closes it.
                drop(unsafe { OwnedHandle::from_raw_handle(raw) });
                true
            }
            // Can't even look (e.g. access denied on the name itself): treat it as taken.
            Ok((status, _)) => status == STATUS_ACCESS_DENIED,
            Err(_) => false,
        }
    }

    /// `NtCreateFile` relative to the held handle, never following a reparse point.
    fn raw_open(
        &self,
        name: &str,
        access: u32,
        share: u32,
        disposition: u32,
        options: u32,
    ) -> Result<(i32, HANDLE), CreateError> {
        let mut units: Vec<u16> = name.encode_utf16().collect();
        let bytes = u16::try_from(units.len() * 2)
            .map_err(|_| CreateError::BadName("name too long".into()))?;
        let unicode = UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: units.as_mut_ptr(),
        };
        let attrs = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: self.handle.as_raw_handle(),
            ObjectName: &unicode,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut io_status = IO_STATUS_BLOCK::default();
        let mut raw: HANDLE = std::ptr::null_mut();
        // SAFETY: every pointer refers to a live local; `units` outlives the call; the root
        // directory handle is open; FILE_OPEN_REPARSE_POINT means no link is ever followed.
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                access,
                &attrs,
                &mut io_status,
                std::ptr::null(),
                FILE_ATTRIBUTE_NORMAL,
                share,
                disposition,
                options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null(),
                0,
            )
        };
        Ok((status, raw))
    }

    /// Create a new, empty file named `name` in this folder. While the returned [`Created`] is
    /// alive, nobody else can write to or delete the file.
    pub fn create_file(&self, name: &str) -> Result<Created, CreateError> {
        let (handle, path) = self.nt_create(
            name,
            GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
            FILE_SHARE_READ,
            FILE_NON_DIRECTORY_FILE,
        )?;
        Ok(Created { handle, path })
    }

    /// Create a new folder named `name` in this folder and hold it locked.
    pub fn create_dir(&self, name: &str) -> Result<LockedDir, CreateError> {
        let (handle, path) = self.nt_create(
            name,
            FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_READ_ATTRIBUTES
                | DELETE
                | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_DIRECTORY_FILE,
        )?;
        let volume_serial = info(&handle).map(|i| i.dwVolumeSerialNumber).unwrap_or(0);
        Ok(LockedDir {
            handle,
            path,
            volume_serial,
        })
    }

    /// Remove this folder if it is empty (it was created by [`Self::create_dir`]).
    pub fn remove_if_empty(self) -> io::Result<()> {
        dispose(&self.handle)
    }

    /// Open `name` in this folder if it exists, or create it, relative to the held handle and
    /// never following a link (security review note 7). Whatever is found must be a real
    /// object of the asked kind, at exactly the expected path, or it is refused and left alone:
    /// nothing found here is ever deleted.
    fn open_or_create(
        &self,
        name: &str,
        access: u32,
        share: u32,
        options: u32,
    ) -> Result<(OwnedHandle, WinPath, BY_HANDLE_FILE_INFORMATION), CreateError> {
        let expected = self
            .path
            .join(name)
            .map_err(|e| CreateError::BadName(e.to_string()))?;
        let (status, raw) = self.raw_open(name, access, share, FILE_OPEN_IF, options)?;
        if status < 0 || raw.is_null() {
            // SAFETY: plain conversion of a status code.
            let code = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
            return Err(CreateError::Other(io::Error::from_raw_os_error(
                code as i32,
            )));
        }
        // SAFETY: NtCreateFile succeeded, so `raw` is a handle we own.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let facts = info(&handle).map_err(CreateError::Other)?;
        if facts.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(CreateError::Other(io::Error::other(format!(
                "{expected} is a link; ByteBroom never follows links"
            ))));
        }
        let real =
            final_path(&handle).map_err(|e| CreateError::Other(io::Error::other(e.to_string())))?;
        if real != expected {
            return Err(CreateError::Other(io::Error::other(format!(
                "{expected} is not where it should be"
            ))));
        }
        Ok((handle, real, facts))
    }

    /// Open the folder `name` in this folder, creating it if needed, and hold it locked. A link
    /// (junction or symlink) in its place is refused, never followed.
    pub fn open_or_create_dir(&self, name: &str) -> Result<LockedDir, CreateError> {
        let (handle, path, facts) = self.open_or_create(
            name,
            FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_ADD_FILE
                | FILE_ADD_SUBDIRECTORY
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE,
            // No FILE_SHARE_DELETE: held like every other locked folder.
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_DIRECTORY_FILE,
        )?;
        Ok(LockedDir {
            handle,
            path,
            volume_serial: facts.dwVolumeSerialNumber,
        })
    }

    /// Rename the file `from` in this folder to `to` in this same folder, replacing a file of
    /// that name. Both names are relative to the held handle; `from` is opened without following
    /// a link and must be a plain file with no other names (used to start a new log).
    pub fn replace_name(&self, from: &str, to: &str) -> io::Result<()> {
        use windows_sys::Wdk::Storage::FileSystem::{
            FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
        };
        let bad = |e: CreateError| io::Error::other(e.to_string());
        self.path
            .join(to)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let (status, raw) = self
            .raw_open(
                from,
                DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
            )
            .map_err(bad)?;
        if status < 0 || raw.is_null() {
            // SAFETY: plain conversion of a status code.
            let code = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        // SAFETY: the open succeeded, so `raw` is a handle we own.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let facts = info(&handle)?;
        if facts.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || facts.nNumberOfLinks != 1 {
            return Err(io::Error::other("not a plain file with one name"));
        }
        let name: Vec<u16> = to.encode_utf16().collect();
        let name_bytes = name.len() * 2;
        let size = size_of::<FILE_RENAME_INFORMATION>() + name_bytes;
        // u64 storage keeps the struct aligned.
        let mut buf = vec![0u64; size.div_ceil(8)];
        let info_ptr = buf.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let mut io_status = IO_STATUS_BLOCK::default();
        // The native call, because only it takes the new name relative to the held folder
        // (the Win32 wrapper refuses a root directory). SAFETY: `buf` is large enough for the
        // struct plus the name (written from FileName on) and aligned for it; every field is
        // written before the call reads it; both handles are open.
        let status = unsafe {
            (*info_ptr).Anonymous.ReplaceIfExists = true;
            (*info_ptr).RootDirectory = self.handle.as_raw_handle();
            (*info_ptr).FileNameLength = name_bytes as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                (&raw mut (*info_ptr).FileName).cast::<u16>(),
                name.len(),
            );
            NtSetInformationFile(
                handle.as_raw_handle(),
                &mut io_status,
                info_ptr.cast(),
                size as u32,
                FileRenameInformation,
            )
        };
        if status < 0 {
            // SAFETY: plain conversion of a status code.
            let code = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(())
    }

    /// Delete the file `name` in this folder, opened relative to the held handle without
    /// following a link. It must be a plain file with one name; a link, a folder or a file with
    /// other hard links is refused and left alone. A name that is not there is not an error.
    pub fn remove_file(&self, name: &str) -> io::Result<()> {
        self.path
            .join(name)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let (status, raw) = self
            .raw_open(
                name,
                DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
            )
            .map_err(|e| io::Error::other(e.to_string()))?;
        if status < 0 || raw.is_null() {
            // SAFETY: plain conversion of a status code.
            let code = unsafe { RtlNtStatusToDosErrorNoTeb(status) };
            let err = io::Error::from_raw_os_error(code as i32);
            return match err.kind() {
                io::ErrorKind::NotFound => Ok(()),
                _ => Err(err),
            };
        }
        // SAFETY: the open succeeded, so `raw` is a handle we own.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let facts = info(&handle)?;
        if facts.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || facts.nNumberOfLinks != 1 {
            return Err(io::Error::other("not a plain file with one name"));
        }
        dispose(&handle)
    }

    /// Open the file `name` in this folder for appending (and reading back), creating it if
    /// needed. A link in its place is refused, and so is a file with other hard links, which
    /// could be another file's contents under this name.
    pub fn open_append(&self, name: &str) -> Result<(std::fs::File, WinPath), CreateError> {
        let (handle, path, facts) = self.open_or_create(
            name,
            FILE_APPEND_DATA | FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ,
            FILE_NON_DIRECTORY_FILE,
        )?;
        if facts.nNumberOfLinks != 1 {
            return Err(CreateError::Other(io::Error::other(format!(
                "{path} has other names (hard links); ByteBroom won't write to it"
            ))));
        }
        Ok((std::fs::File::from(handle), path))
    }
}

/// A file this process created, held open without write- or delete-sharing.
#[derive(Debug)]
pub struct Created {
    handle: OwnedHandle,
    /// Where it is.
    pub path: WinPath,
}

impl Created {
    /// The file, positioned at the start, for writing or reading back.
    pub fn file(&self) -> io::Result<std::fs::File> {
        let mut file = std::fs::File::from(self.handle.try_clone()?);
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }

    /// Delete the file through its own handle (never by path).
    pub fn delete(self) -> io::Result<()> {
        dispose(&self.handle)
    }
}
