//! Red-tier sizes on this PC, read-only (see [`crate::red`]).
//!
//! - The Recycle Bin: `SHQueryRecycleBinW`, a query only.
//! - `hiberfil.sys` and `pagefile.sys`: their sizes come from the folder listing
//!   (`FindFirstFileExW`), so the files are never opened; Windows holds them open anyway.
//! - `Windows.old`: summed by the walker, which never follows links; marked incomplete when some
//!   folders can't be read, and "needs admin" when the folder itself can't.
//! - The Windows Update store, Delivery Optimization files and restore points live inside
//!   protected Windows folders the walker refuses to enter: they say "needs admin".

use super::walk::walk;
use crate::locations::Locations;
use crate::paths::WinPath;
use crate::policy::SystemLayout;
use crate::red::{RedFinding, RedSize, red_rules};
use crate::rules::RedItem;
use crate::walk::{Step, WalkOptions};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FindClose, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW,
    WIN32_FIND_DATAW,
};
use windows_sys::Win32::UI::Shell::{SHQUERYRBINFO, SHQueryRecycleBinW};

/// What the folder listing says about one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listed {
    /// No such file (or it is a folder).
    Absent,
    /// The file's length.
    Size(u64),
    /// The listing could not be read.
    Denied,
}

/// The length of the file at `path`, read from its folder's listing without opening the file.
pub fn listed_size(path: &WinPath) -> Listed {
    let wide: Vec<u16> = format!("\\\\?\\{path}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: an all-zero WIN32_FIND_DATAW is valid (integers and arrays of integers).
    let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    // SAFETY: `wide` is NUL-terminated and outlives the call; `data` is writable and of the type
    // FindExInfoBasic fills. WinPath parts never hold `*` or `?`, so this matches one name.
    let handle = unsafe {
        FindFirstFileExW(
            wide.as_ptr(),
            FindExInfoBasic,
            (&mut data as *mut WIN32_FIND_DATAW).cast(),
            FindExSearchNameMatch,
            std::ptr::null(),
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: no arguments; reads this thread's last error.
        return match unsafe { GetLastError() } {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Listed::Absent,
            _ => Listed::Denied,
        };
    }
    // SAFETY: `handle` came from FindFirstFileExW and is closed exactly once.
    unsafe { FindClose(handle) };
    if data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Listed::Absent;
    }
    Listed::Size((u64::from(data.nFileSizeHigh) << 32) | u64::from(data.nFileSizeLow))
}

/// What is in the Recycle Bin on every drive, for the user running ByteBroom. A query only.
pub fn recycle_bin_size() -> Option<u64> {
    let mut info = SHQUERYRBINFO {
        cbSize: size_of::<SHQUERYRBINFO>() as u32,
        i64Size: 0,
        i64NumItems: 0,
    };
    // SAFETY: a null root means "all drives"; `info` is writable with cbSize set.
    let hr = unsafe { SHQueryRecycleBinW(std::ptr::null(), &mut info) };
    (hr == 0).then(|| u64::try_from(info.i64Size).unwrap_or(0))
}

/// Where the red-tier items are looked for.
#[derive(Debug, Clone)]
pub struct RedPlaces {
    /// The root of the drive Windows is on (a fake folder in tests).
    pub system_drive: WinPath,
    /// Roots of the other fixed drives (page files can live there too).
    pub other_drives: Vec<WinPath>,
}

fn file_size(listed: Listed) -> RedSize {
    match listed {
        Listed::Size(bytes) => RedSize::Bytes {
            bytes,
            complete: true,
        },
        Listed::Absent => RedSize::Absent,
        Listed::Denied => RedSize::NeedsAdmin,
    }
}

fn pagefiles(places: &RedPlaces) -> RedSize {
    let mut total = 0u64;
    let mut any = false;
    let mut complete = true;
    for root in std::iter::once(&places.system_drive).chain(&places.other_drives) {
        let Ok(path) = root.join("pagefile.sys") else {
            continue;
        };
        match listed_size(&path) {
            Listed::Size(n) => {
                total += n;
                any = true;
            }
            Listed::Absent => {}
            Listed::Denied => complete = false,
        }
    }
    match (any, complete) {
        (true, _) => RedSize::Bytes {
            bytes: total,
            complete,
        },
        (false, true) => RedSize::Absent,
        (false, false) => RedSize::NeedsAdmin,
    }
}

fn windows_old(places: &RedPlaces, layout: &SystemLayout, opts: &WalkOptions) -> RedSize {
    let Ok(path) = places.system_drive.join("Windows.old") else {
        return RedSize::Absent;
    };
    match walk(&path, layout, opts, |_| Step::Enter) {
        Ok(s) => RedSize::Bytes {
            bytes: s.bytes,
            complete: s.unreadable == 0 && s.changed == 0 && !s.cancelled,
        },
        Err(super::OpenError::NotFound) => RedSize::Absent,
        Err(_) => RedSize::NeedsAdmin,
    }
}

/// Every red-tier item's size at `places`. `recycle_bin` is the Recycle Bin query (the real one
/// for the owner's PC; tests pass a stand-in, so they never ask about the real Recycle Bin).
pub fn red_sizes_at(
    places: &RedPlaces,
    layout: &SystemLayout,
    opts: &WalkOptions,
    recycle_bin: impl FnOnce() -> Option<u64>,
) -> Vec<RedFinding> {
    let mut recycle_bin = Some(recycle_bin);
    red_rules()
        .map(|(rule, item)| {
            let size = match item {
                RedItem::RecycleBin => match recycle_bin.take().and_then(|q| q()) {
                    Some(bytes) => RedSize::Bytes {
                        bytes,
                        complete: true,
                    },
                    None => RedSize::NeedsAdmin,
                },
                RedItem::Hiberfil => places
                    .system_drive
                    .join("hiberfil.sys")
                    .map_or(RedSize::Absent, |p| file_size(listed_size(&p))),
                RedItem::Pagefile => pagefiles(places),
                RedItem::WindowsOld => windows_old(places, layout, opts),
                RedItem::UpdateStore | RedItem::DeliveryOptimization | RedItem::RestorePoints => {
                    RedSize::NeedsAdmin
                }
            };
            RedFinding { rule, size }
        })
        .collect()
}

/// Every red-tier item's size on this PC. Only reads.
pub fn red_sizes(at: &Locations, layout: &SystemLayout, opts: &WalkOptions) -> Vec<RedFinding> {
    let places = RedPlaces {
        system_drive: WinPath::drive_root(layout.system_root.drive()),
        other_drives: at.other_drives.clone(),
    };
    red_sizes_at(&places, layout, opts, recycle_bin_size)
}
