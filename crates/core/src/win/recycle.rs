//! Windows side of the Recycle Bin: drive facts, the bin's size, and the shell call.

use crate::paths::WinPath;
use crate::recycle::BinFacts;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, GetDiskFreeSpaceExW, GetDriveTypeW,
    GetVolumeNameForVolumeMountPointW, QueryDosDeviceW,
};
use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows_sys::Win32::UI::Shell::{
    FO_DELETE, FOF_ALLOWUNDO, FOF_NO_UI, SHFILEOPSTRUCTW, SHFileOperationW, SHQUERYRBINFO,
    SHQueryRecycleBinW,
};

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(Some(0)).collect()
}

/// Windows' own default when no maximum is set: a share of the drive. Kept conservative.
const DEFAULT_SHARE_PERCENT: u64 = 5;

/// What Windows says about the Recycle Bin of drive `letter`.
pub fn bin_facts(letter: char) -> BinFacts {
    let root = format!("{letter}:\\");
    let root_w = wide(&root);
    // SAFETY: NUL-terminated string that outlives the call.
    let fixed_local = unsafe { GetDriveTypeW(root_w.as_ptr()) } == DRIVE_FIXED;

    // A subst drive maps to "\??\C:\folder"; a real volume to "\Device\HarddiskVolumeN".
    let device = wide(&format!("{letter}:"));
    let mut target = vec![0u16; 1024];
    // SAFETY: `target` is writable for its length; `device` is NUL-terminated.
    let n = unsafe { QueryDosDeviceW(device.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
    let subst = n == 0 || String::from_utf16_lossy(&target[..n as usize]).starts_with("\\??\\");

    let mut info = SHQUERYRBINFO {
        cbSize: size_of::<SHQUERYRBINFO>() as u32,
        i64Size: 0,
        i64NumItems: 0,
    };
    // SAFETY: `info` has cbSize set as the API requires; `root_w` is NUL-terminated.
    let bin_present = unsafe { SHQueryRecycleBinW(root_w.as_ptr(), &mut info) } == 0;

    let (nuke_on_delete, max_mb) = match volume_guid(&root_w) {
        Some(guid) => {
            let key = format!(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume\\{guid}"
            );
            (
                read_dword(&key, "NukeOnDelete").unwrap_or(0) == 1,
                read_dword(&key, "MaxCapacity"),
            )
        }
        None => (true, None), // unknown volume: treat the bin as off (refuse to recycle)
    };
    let max_bytes = match max_mb {
        Some(mb) => u64::from(mb) * 1024 * 1024,
        None => drive_total(&root_w) / 100 * DEFAULT_SHARE_PERCENT,
    };
    BinFacts {
        fixed_local,
        subst,
        bin_present,
        nuke_on_delete,
        max_bytes,
    }
}

/// `{xxxxxxxx-...}` for the volume mounted at `root` (NUL-terminated wide string).
fn volume_guid(root: &[u16]) -> Option<String> {
    let mut buf = vec![0u16; 64];
    // SAFETY: `buf` is writable for its length; `root` is NUL-terminated and ends with '\'.
    let ok = unsafe {
        GetVolumeNameForVolumeMountPointW(root.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
    };
    if ok == 0 {
        return None;
    }
    let text = String::from_utf16_lossy(&buf);
    let start = text.find('{')?;
    let end = text.find('}')?;
    (end > start).then(|| text[start..=end].to_string())
}

fn read_dword(key: &str, value: &str) -> Option<u32> {
    let key_w = wide(key);
    let value_w = wide(value);
    let mut data: u32 = 0;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: strings are NUL-terminated; `data` is a writable u32 and `size` says so.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key_w.as_ptr(),
            value_w.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    };
    (status == 0).then_some(data)
}

fn drive_total(root: &[u16]) -> u64 {
    let (mut free, mut total, mut total_free) = (0u64, 0u64, 0u64);
    // SAFETY: three writable u64s; `root` is NUL-terminated.
    let ok = unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut free, &mut total, &mut total_free) };
    if ok == 0 { 0 } else { total }
}

/// Total bytes in drive `letter`'s Recycle Bin, if Windows can say.
pub fn bin_size(letter: char) -> Option<u64> {
    let root = wide(&format!("{letter}:\\"));
    let mut info = SHQUERYRBINFO {
        cbSize: size_of::<SHQUERYRBINFO>() as u32,
        i64Size: 0,
        i64NumItems: 0,
    };
    // SAFETY: as in `bin_facts`.
    let hr = unsafe { SHQueryRecycleBinW(root.as_ptr(), &mut info) };
    (hr == 0).then(|| u64::try_from(info.i64Size).unwrap_or(0))
}

/// Ask the shell to move `path` to the Recycle Bin, with no UI. `Err` carries the shell's code.
pub fn shell_recycle(path: &WinPath) -> Result<(), i32> {
    // pFrom is a list ending with an empty string: the path, NUL, then a second NUL.
    let mut from: Vec<u16> = OsStr::new(&path.to_string()).encode_wide().collect();
    from.extend([0, 0]);
    let mut op = SHFILEOPSTRUCTW {
        hwnd: std::ptr::null_mut(),
        wFunc: FO_DELETE,
        pFrom: from.as_ptr(),
        pTo: std::ptr::null(),
        fFlags: (FOF_ALLOWUNDO | FOF_NO_UI) as u16,
        fAnyOperationsAborted: 0,
        hNameMappings: std::ptr::null_mut(),
        lpszProgressTitle: std::ptr::null(),
    };
    // SAFETY: `op` is fully initialised and `from` is double-NUL-terminated and outlives the call.
    let code = unsafe { SHFileOperationW(&mut op) };
    if code == 0 && op.fAnyOperationsAborted == 0 {
        Ok(())
    } else {
        Err(code)
    }
}

/// Does anything (file, folder or link) exist at `path`? Does not follow links.
pub fn exists(path: &WinPath) -> bool {
    std::fs::symlink_metadata(format!("\\\\?\\{path}")).is_ok()
}

/// Total size of the files under `dir`, without entering links. Used only for the bin-size
/// checks, so a file that vanishes meanwhile simply doesn't count.
pub fn measure(dir: &WinPath) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![format!("\\\\?\\{dir}")];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                continue;
            }
            if meta.is_dir() {
                stack.push(entry.path().to_string_lossy().into_owned());
            } else {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}
