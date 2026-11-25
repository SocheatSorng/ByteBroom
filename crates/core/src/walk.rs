//! What a folder walk reports, and the pure decisions it makes. The walk itself is in
//! `win::walk`; it only reads, never opens a file's contents and never changes anything.
//!
//! - Links, junctions and other reparse points are never entered or reported, except cloud
//!   placeholder files (OneDrive), which are reported with `cloud` set.
//! - "Never listed" names (`rules::is_never_listed`) are never reported or entered.
//! - Anything on the hard floor below the walk's root is never reported or entered.
//! - Folders that can't be opened or listed are counted, not fatal.
//! - A file with several hard links is counted once in the totals.

use crate::paths::WinPath;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How deep a walk goes unless told otherwise. Deeper folders are counted, not entered.
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// Settings for one walk.
#[derive(Debug, Clone, Copy)]
pub struct WalkOptions<'a> {
    /// Folders at this depth (the root's children are depth 1) are reported but not entered.
    pub max_depth: usize,
    /// When set to `true` (from another thread), the walk stops before its next folder.
    pub cancel: Option<&'a AtomicBool>,
}

impl Default for WalkOptions<'_> {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            cancel: None,
        }
    }
}

impl WalkOptions<'_> {
    /// True once the caller asked the walk to stop.
    pub fn cancelled(&self) -> bool {
        self.cancel.is_some_and(|c| c.load(Ordering::Relaxed))
    }
}

/// A file the walk found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Its path, spelled as Windows lists it.
    pub path: WinPath,
    /// Its length in bytes (not space on disk).
    pub len: u64,
    /// When its contents last changed.
    pub modified: SystemTime,
    /// The latest of its creation, last-write and change times: when anything last happened to
    /// it. A file extracted today from an old archive has an old `modified` but a new `activity`.
    pub activity: SystemTime,
    /// A cloud placeholder (e.g. OneDrive): its length may not be on this disk.
    pub cloud: bool,
    /// Another name of a file already reported in this walk (a hard link). Its bytes are not
    /// counted again, and deleting this name alone frees nothing.
    pub repeat: bool,
    /// How deep it is (the root's children are depth 1).
    pub depth: usize,
    /// Which file this is, as Windows numbers it (`None` on file systems without file IDs).
    pub id: Option<FileId>,
}

/// Windows' number for a file: the same file keeps it when renamed, and another file put in its
/// place gets a different one. Lets a clean check that a path still names the file the scan saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    /// The volume's serial number.
    pub volume: u32,
    /// The file's ID on that volume (128-bit, as NTFS and ReFS report it).
    pub id: [u8; 16],
}

/// One thing the walk reports to its visitor.
#[derive(Debug)]
pub enum Item<'a> {
    /// A real folder (never a link). The visitor's answer decides whether it is entered.
    Folder {
        /// Its path, spelled as Windows reports it.
        path: &'a WinPath,
        /// How deep it is (the root's children are depth 1).
        depth: usize,
        /// When it last changed.
        modified: SystemTime,
        /// The latest of its creation, last-write and change times.
        activity: SystemTime,
    },
    /// A file.
    File(&'a FileEntry),
    /// A folder whose contents were not all seen: it could not be listed, changed during the
    /// walk, or is at the depth limit. Sizes and dates below it are incomplete.
    Incomplete {
        /// The folder.
        path: &'a WinPath,
        /// How deep it is.
        depth: usize,
    },
}

/// The visitor's answer for a folder (ignored for files).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Enter the folder (within the depth limit).
    Enter,
    /// Don't enter it.
    Skip,
}

/// Totals for a walk. Counts only: the summary never names a skipped item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkSummary {
    /// Files reported, hard-link repeats included.
    pub files: u64,
    /// Folders reported.
    pub folders: u64,
    /// Bytes of the files reported, each hard-linked file once.
    pub bytes: u64,
    /// Files reported as another name of a file already seen.
    pub hard_link_repeats: u64,
    /// Folders that could not be opened or listed ("access denied" and the like).
    pub unreadable: u64,
    /// Links, junctions and other reparse points that were not entered or reported.
    pub links_skipped: u64,
    /// Items on the hard floor or on the "never listed" list.
    pub protected_skipped: u64,
    /// Names that can't be represented safely (not valid Unicode, or a name Windows treats
    /// specially, such as one ending in a dot).
    pub odd_names: u64,
    /// Folders not entered because they are at the depth limit.
    pub depth_limited: u64,
    /// Folders that changed between being listed and being opened (renamed, or replaced by a
    /// link), and so were not entered.
    pub changed: u64,
    /// The walk stopped early because it was cancelled.
    pub cancelled: bool,
}

/// Reparse tags for cloud files (`IO_REPARSE_TAG_CLOUD` and `IO_REPARSE_TAG_CLOUD_1`..`_F`).
pub fn is_cloud_tag(tag: u32) -> bool {
    tag & 0xFFFF_0FFF == 0x9000_001A
}

/// Windows' file-time attributes that mark a file as not (fully) on this disk.
pub const CLOUD_ATTRIBUTES: u32 = 0x0000_1000 /* OFFLINE */
    | 0x0004_0000 /* RECALL_ON_OPEN */
    | 0x0040_0000 /* RECALL_ON_DATA_ACCESS */;

/// A Windows file time (100 ns units since 1601) as a `SystemTime`. Times before 1970 or
/// invalid (negative) give the Unix epoch, which only ever makes a file look old-but-known.
pub fn from_file_time(ft: i64) -> SystemTime {
    const EPOCH_DIFF: i64 = 116_444_736_000_000_000;
    match ft.checked_sub(EPOCH_DIFF) {
        Some(since) if since > 0 => {
            let since = since.unsigned_abs();
            UNIX_EPOCH + Duration::new(since / 10_000_000, ((since % 10_000_000) * 100) as u32)
        }
        _ => UNIX_EPOCH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_tags_are_recognised_and_links_are_not() {
        assert!(is_cloud_tag(0x9000_001A));
        assert!(is_cloud_tag(0x9000_101A));
        assert!(is_cloud_tag(0x9000_F01A));
        assert!(!is_cloud_tag(0xA000_000C)); // symlink
        assert!(!is_cloud_tag(0xA000_0003)); // junction / mount point
        assert!(!is_cloud_tag(0x8000_0013)); // dedup
        assert!(!is_cloud_tag(0));
    }

    #[test]
    fn file_times_convert_to_unix_time() {
        // 2024-01-01T00:00:00Z = 1_704_067_200 s since 1970.
        let ft = 116_444_736_000_000_000 + 1_704_067_200 * 10_000_000 + 5;
        let t = from_file_time(ft);
        assert_eq!(
            t.duration_since(UNIX_EPOCH).ok(),
            Some(Duration::new(1_704_067_200, 500))
        );
        assert_eq!(from_file_time(0), UNIX_EPOCH);
        assert_eq!(from_file_time(-1), UNIX_EPOCH);
        assert_eq!(from_file_time(i64::MIN), UNIX_EPOCH);
    }

    #[test]
    fn cancel_is_seen_through_the_options() {
        let flag = AtomicBool::new(false);
        let opts = WalkOptions {
            cancel: Some(&flag),
            ..WalkOptions::default()
        };
        assert!(!opts.cancelled());
        flag.store(true, Ordering::Relaxed);
        assert!(opts.cancelled());
        assert!(!WalkOptions::default().cancelled());
        assert_eq!(WalkOptions::default().max_depth, DEFAULT_MAX_DEPTH);
    }
}
