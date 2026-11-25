//! The folder walk (see [`crate::walk`] for what it promises).
//!
//! Each folder is opened without following it, checked (a real folder, at exactly the path
//! expected), and then listed **through that same handle** with
//! `GetFileInformationByHandleEx(FileIdExtdDirectoryInfo)`. One call returns a batch of entries with
//! their attributes, reparse tag, length, times and file ID, so no file is ever opened and hard
//! links are recognised by file ID without extra calls. File systems without file IDs (FAT,
//! exFAT, which have no hard links) fall back to `FileFullDirectoryInfo`.

use super::{Access, OpenError, Opened, open_no_follow};
use crate::paths::WinPath;
use crate::policy::{SystemLayout, denied_reason};
use crate::rules::is_never_listed;
use crate::walk::{
    CLOUD_ATTRIBUTES, FileEntry, FileId, Item, Step, WalkOptions, WalkSummary, from_file_time,
    is_cloud_tag,
};
use std::collections::HashSet;
use std::io;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, ERROR_NOT_SUPPORTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FULL_DIR_INFO,
    FILE_ID_EXTD_DIR_INFO, FileFullDirectoryInfo, FileIdExtdDirectoryInfo,
    GetFileInformationByHandleEx,
};

/// One entry as the folder listing reports it.
struct RawEntry {
    /// `None` when the name is not valid Unicode.
    name: Option<String>,
    attributes: u32,
    reparse_tag: u32,
    len: u64,
    modified: i64,
    /// The latest of its creation, last-write and change times.
    activity: i64,
    /// `None` on file systems without file IDs.
    id: Option<[u8; 16]>,
}

/// The listing buffer: 64 KB, 8-byte aligned as the entry structs need.
const BUFFER_WORDS: usize = 8192;

/// Every entry in the folder behind `dir` (opened with [`Access::List`]).
fn list(dir: &Opened) -> io::Result<Vec<RawEntry>> {
    let mut buf = vec![0u64; BUFFER_WORDS];
    let bytes = size_of_val(buf.as_slice());
    let mut extended = true;
    let mut out = Vec::new();
    loop {
        let class = if extended {
            FileIdExtdDirectoryInfo
        } else {
            FileFullDirectoryInfo
        };
        // SAFETY: the handle is open with FILE_LIST_DIRECTORY; `buf` is writable for `bytes`
        // bytes and 8-byte aligned.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                dir.handle.as_raw_handle(),
                class,
                buf.as_mut_ptr().cast(),
                bytes as u32,
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error().map(|c| c as u32) {
                Some(ERROR_NO_MORE_FILES) => return Ok(out),
                Some(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED)
                    if extended && out.is_empty() =>
                {
                    extended = false;
                    continue;
                }
                _ => return Err(err),
            }
        }
        parse(&buf, extended, &mut out);
    }
}

/// Read the chain of entries in `buf`. Stops at the first entry that would not fit, so a
/// malformed buffer can only shorten the listing, never read outside it.
fn parse(buf: &[u64], extended: bool, out: &mut Vec<RawEntry>) {
    let base = buf.as_ptr().cast::<u8>();
    let total = size_of_val(buf);
    let header = if extended {
        std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileName)
    } else {
        std::mem::offset_of!(FILE_FULL_DIR_INFO, FileName)
    };
    let mut offset = 0usize;
    loop {
        if offset.checked_add(header).is_none_or(|end| end > total) {
            return;
        }
        // SAFETY: `offset + header` is within `buf`, and Windows wrote an entry here.
        let entry = unsafe { base.add(offset) };
        let (next, name_len, attributes, reparse_tag, len, modified, activity, id) = if extended {
            // SAFETY: the header bytes are in bounds (checked above); read_unaligned copies them.
            let e = unsafe { entry.cast::<FILE_ID_EXTD_DIR_INFO>().read_unaligned() };
            (
                e.NextEntryOffset,
                e.FileNameLength,
                e.FileAttributes,
                e.ReparsePointTag,
                e.EndOfFile,
                e.LastWriteTime,
                e.CreationTime.max(e.LastWriteTime).max(e.ChangeTime),
                Some(e.FileId.Identifier),
            )
        } else {
            // SAFETY: as above.
            let e = unsafe { entry.cast::<FILE_FULL_DIR_INFO>().read_unaligned() };
            // For reparse points this class puts the reparse tag in EaSize.
            (
                e.NextEntryOffset,
                e.FileNameLength,
                e.FileAttributes,
                e.EaSize,
                e.EndOfFile,
                e.LastWriteTime,
                e.CreationTime.max(e.LastWriteTime).max(e.ChangeTime),
                None,
            )
        };
        let name_len = name_len as usize;
        if offset + header + name_len > total {
            return;
        }
        let mut units = vec![0u16; name_len / 2];
        // SAFETY: `name_len` bytes after the header are in bounds (checked above); the copy is
        // byte-wise, so alignment does not matter.
        unsafe {
            std::ptr::copy_nonoverlapping(
                entry.add(header),
                units.as_mut_ptr().cast::<u8>(),
                units.len() * 2,
            );
        }
        out.push(RawEntry {
            name: String::from_utf16(&units).ok(),
            attributes,
            reparse_tag,
            len: u64::try_from(len).unwrap_or(0),
            modified,
            activity,
            id: id.filter(|bytes| bytes.iter().any(|b| *b != 0)),
        });
        if next == 0 {
            return;
        }
        offset += next as usize;
    }
}

fn not_a_folder() -> OpenError {
    OpenError::Other(io::Error::new(
        io::ErrorKind::InvalidInput,
        "not a real folder (a link, a junction or a file)",
    ))
}

/// Walk the folder `root`, reporting what it holds to `visit`. Only reads. Fails only when the
/// root itself can't be opened as a real folder; everything below is counted, never fatal.
pub fn walk(
    root: &WinPath,
    layout: &SystemLayout,
    opts: &WalkOptions,
    mut visit: impl FnMut(&Item) -> Step,
) -> Result<WalkSummary, OpenError> {
    let opened = open_no_follow(root, Access::List)?;
    if opened.resolved.is_reparse_point || !opened.is_directory {
        return Err(not_a_folder());
    }
    let mut summary = WalkSummary::default();
    let mut seen: HashSet<(u32, [u8; 16])> = HashSet::new();
    let root_path = opened.resolved.final_path.clone();
    let mut stack: Vec<(WinPath, usize, Option<Opened>)> = vec![(root_path, 0, Some(opened))];

    while let Some((path, depth, held)) = stack.pop() {
        if opts.cancelled() {
            summary.cancelled = true;
            break;
        }
        let dir = match held {
            Some(dir) => dir,
            None => match open_no_follow(&path, Access::List) {
                Ok(d)
                    if d.resolved.is_reparse_point
                        || !d.is_directory
                        || !d.resolved.final_path.eq_ignore_case(&path) =>
                {
                    summary.changed += 1;
                    visit(&Item::Incomplete { path: &path, depth });
                    continue;
                }
                Ok(d) => d,
                Err(OpenError::NotFound) => {
                    summary.changed += 1;
                    visit(&Item::Incomplete { path: &path, depth });
                    continue;
                }
                Err(_) => {
                    summary.unreadable += 1;
                    visit(&Item::Incomplete { path: &path, depth });
                    continue;
                }
            },
        };
        let Ok(entries) = list(&dir) else {
            summary.unreadable += 1;
            visit(&Item::Incomplete { path: &path, depth });
            continue;
        };
        let volume = dir.volume_serial;
        drop(dir);

        for entry in entries {
            if opts.cancelled() {
                summary.cancelled = true;
                return Ok(summary);
            }
            let Some(name) = entry.name else {
                summary.odd_names += 1;
                continue;
            };
            if name == "." || name == ".." {
                continue;
            }
            if is_never_listed(&name) {
                summary.protected_skipped += 1;
                continue;
            }
            let is_dir = entry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            let is_reparse = entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
            let cloud_file = !is_dir && is_reparse && is_cloud_tag(entry.reparse_tag);
            if is_reparse && !cloud_file {
                summary.links_skipped += 1;
                continue;
            }
            let Ok(child) = path.join(&name) else {
                summary.odd_names += 1;
                continue;
            };
            if denied_reason(&child, layout).is_some() {
                summary.protected_skipped += 1;
                continue;
            }
            let child_depth = depth + 1;
            if is_dir {
                summary.folders += 1;
                let step = visit(&Item::Folder {
                    path: &child,
                    depth: child_depth,
                    modified: from_file_time(entry.modified),
                    activity: from_file_time(entry.activity),
                });
                if step == Step::Enter {
                    if child_depth >= opts.max_depth {
                        summary.depth_limited += 1;
                        visit(&Item::Incomplete {
                            path: &child,
                            depth: child_depth,
                        });
                    } else {
                        stack.push((child, child_depth, None));
                    }
                }
            } else {
                let repeat = entry.id.is_some_and(|id| !seen.insert((volume, id)));
                summary.files += 1;
                if repeat {
                    summary.hard_link_repeats += 1;
                } else {
                    summary.bytes += entry.len;
                }
                let file = FileEntry {
                    path: child,
                    len: entry.len,
                    modified: from_file_time(entry.modified),
                    activity: from_file_time(entry.activity),
                    cloud: cloud_file || entry.attributes & CLOUD_ATTRIBUTES != 0,
                    repeat,
                    depth: child_depth,
                    id: entry.id.map(|id| FileId { volume, id }),
                };
                visit(&Item::File(&file));
            }
        }
    }
    Ok(summary)
}
