//! Phase 5: what ByteBroom moved and recycled, and putting moves back.
//!
//! - **Moves** come from the move journal ([`crate::relocate`]). A move is "put back" once an
//!   `bytebroom-undone-v1` line for it follows it in the journal.
//! - **Putting back** ([`undo_entries`]) re-reads the journal for every item, so only a move that
//!   is still in the journal and not yet put back is acted on, then runs [`undo_move`] (which
//!   checks everything again on disk) and only then records "put back".
//! - **Recycled items** are recorded in their own journal ([`RecycledJournal`]), from the item the
//!   shell reported it created in the bin. ByteBroom never restores them itself (decision 3): the
//!   owner uses Windows' own Restore.
//!
//! Both journals are user-writable, so nothing read from them is trusted, and nothing elevated
//! ever acts on them (phase 4, rule S3). They list file names: they stay in local app data and
//! are never logged, committed or sent.

use crate::locations::Locations;
use crate::paths::WinPath;
use crate::policy::{Policy, ResolvedPath, SystemLayout};
use crate::relocate::{Journal, JournalEntry, JournalLine, Undone, now_secs};
use crate::win::dir::LockedDir;
use crate::win::{Access, open_no_follow};
use std::fs::File;
use std::io::{self, Read, Write};

/// A move from the journal, and whether it was put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveRecord {
    /// The move.
    pub entry: JournalEntry,
    /// When it was put back (seconds since 1970), or `None` if it is still moved.
    pub undone: Option<u64>,
}

/// Every move in `lines`, oldest first, each marked put back by the first "undone" line after it
/// that matches it and was not already used for an earlier one. A file moved, put back and moved
/// again has two moves; only the first is put back.
pub fn move_history(lines: &[JournalLine]) -> Vec<MoveRecord> {
    let mut out: Vec<MoveRecord> = Vec::new();
    for line in lines {
        match line {
            JournalLine::Move(entry) => out.push(MoveRecord {
                entry: entry.clone(),
                undone: None,
            }),
            JournalLine::Undone(u) => {
                if let Some(rec) = out
                    .iter_mut()
                    .find(|r| r.undone.is_none() && u.matches(&r.entry))
                {
                    rec.undone = Some(u.time);
                }
            }
        }
    }
    out
}

/// What happened to one move asked to be put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoResult {
    /// The file is back where it was, and the moved copy is gone.
    PutBack,
    /// The file is back, but the journal could not record it: the history still shows it as
    /// moved, and a second try is refused safely (the moved copy is gone).
    PutBackNotRecorded(String),
    /// Nothing was changed.
    Refused(String),
}

/// The words for a move that was already put back.
pub const ALREADY_PUT_BACK: &str = "it was already put back";

/// Put back each of `wanted`, in order. For every item the journal is read again, through the
/// held handle: an item that is no longer there, or already put back, is refused. Otherwise
/// `undo` runs under the policy `policy_for` gives (the real one: [`undo_policy`] and
/// [`undo_move`]), and only after it succeeded is "put back" appended.
pub fn undo_entries(
    journal: &Journal,
    wanted: &[JournalEntry],
    policy_for: &dyn Fn(&JournalEntry) -> Result<Policy, String>,
    undo: &dyn Fn(&Policy, &JournalEntry) -> Result<(), String>,
) -> Vec<UndoResult> {
    wanted
        .iter()
        .map(|entry| undo_one(journal, entry, policy_for, undo))
        .collect()
}

fn undo_one(
    journal: &Journal,
    entry: &JournalEntry,
    policy_for: &dyn Fn(&JournalEntry) -> Result<Policy, String>,
    undo: &dyn Fn(&Policy, &JournalEntry) -> Result<(), String>,
) -> UndoResult {
    let lines = match journal.lines() {
        Ok(l) => l,
        Err(e) => return UndoResult::Refused(format!("the history can't be read: {e}")),
    };
    let history = move_history(&lines);
    let mut found = history.iter().filter(|r| r.entry == *entry);
    let Some(first) = found.next() else {
        return UndoResult::Refused("it is no longer in the history".into());
    };
    if first.undone.is_some() && !found.any(|r| r.undone.is_none()) {
        return UndoResult::Refused(ALREADY_PUT_BACK.into());
    }
    let policy = match policy_for(entry) {
        Ok(p) => p,
        Err(why) => return UndoResult::Refused(why),
    };
    if let Err(why) = undo(&policy, entry) {
        return UndoResult::Refused(why);
    }
    match journal.append_undone(&Undone::of(entry, now_secs())) {
        Ok(()) => UndoResult::PutBack,
        Err(e) => UndoResult::PutBackNotRecorded(e),
    }
}

/// The policy a move is put back under. The nearest folder above the original that still exists
/// becomes the one allowed root, if it is a real folder (not a link) inside a place ByteBroom
/// scans (the Downloads folder, the profile, or another fixed drive) and passes the hard floor.
/// Files can't go back directly into a profile folder or a drive root, which are never roots.
pub fn undo_policy(
    at: &Locations,
    layout: &SystemLayout,
    entry: &JournalEntry,
) -> Result<Policy, String> {
    let scanned = |p: &WinPath| {
        at.downloads
            .as_ref()
            .is_some_and(|d| p.is_at_or_inside_ignore_case(d))
            || at.profile.as_ref().is_some_and(|r| p.is_strictly_inside(r))
            || at.other_drives.iter().any(|r| p.is_strictly_inside(r))
    };
    let mut folder = parent(&entry.source).ok_or("the original path has no folder")?;
    loop {
        if !scanned(&folder) {
            return Err(
                "the original folder is not in a place ByteBroom cleans; move it back by hand"
                    .into(),
            );
        }
        match open_no_follow(&folder, Access::Inspect) {
            Ok(o) => {
                if o.resolved.is_reparse_point || !o.is_directory {
                    return Err("the original folder is not a real folder any more".into());
                }
                if !o.resolved.final_path.eq_ignore_case(&folder) {
                    return Err("the original folder is reached through a link".into());
                }
                return Policy::new(
                    vec![ResolvedPath {
                        final_path: o.resolved.final_path,
                        is_reparse_point: false,
                    }],
                    layout.clone(),
                )
                .map_err(|r| format!("the original folder: {r}"));
            }
            Err(crate::win::OpenError::NotFound) => {
                folder = parent(&folder).ok_or("the original folder is gone")?;
            }
            Err(e) => return Err(format!("the original folder: {e}")),
        }
    }
}

fn parent(path: &WinPath) -> Option<WinPath> {
    let (_, head) = path.parts().split_last()?;
    head.iter()
        .try_fold(WinPath::drive_root(path.drive()), |acc, part| {
            acc.join(part)
        })
        .ok()
}

/// One clean's moves, newest clean first, for the window. A move from before phase 5 has no
/// clean number and is a group of its own.
pub fn group_by_clean(records: &[MoveRecord]) -> Vec<Vec<MoveRecord>> {
    let mut groups: Vec<(Option<u64>, Vec<MoveRecord>)> = Vec::new();
    for rec in records {
        match rec.entry.clean {
            Some(c) => match groups.iter_mut().find(|(k, _)| *k == Some(c)) {
                Some((_, g)) => g.push(rec.clone()),
                None => groups.push((Some(c), vec![rec.clone()])),
            },
            None => groups.push((None, vec![rec.clone()])),
        }
    }
    groups.reverse();
    groups.into_iter().map(|(_, g)| g).collect()
}

/// An item ByteBroom sent to the Recycle Bin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecycledRecord {
    /// Which clean.
    pub clean: u64,
    /// Seconds since 1970 (UTC).
    pub time: u64,
    /// Its size in bytes.
    pub size: u64,
    /// Where it was.
    pub original: WinPath,
    /// The item the shell reported it created in the bin.
    pub in_bin: WinPath,
}

/// The recycled journal's line tag.
pub const RECYCLED_V1: &str = "bytebroom-recycled-v1";

impl RecycledRecord {
    /// One tab-separated line.
    pub fn to_line(&self) -> String {
        format!(
            "{RECYCLED_V1}\t{}\t{}\t{}\t{}\t{}",
            self.clean, self.time, self.size, self.original, self.in_bin
        )
    }

    /// Parse a line written by [`Self::to_line`]. Anything else gives `None`.
    pub fn parse(line: &str) -> Option<Self> {
        let mut f = line.trim_end_matches(['\r', '\n']).split('\t');
        if f.next()? != RECYCLED_V1 {
            return None;
        }
        let rec = Self {
            clean: f.next()?.parse().ok()?,
            time: f.next()?.parse().ok()?,
            size: f.next()?.parse().ok()?,
            original: WinPath::parse(f.next()?).ok()?,
            in_bin: WinPath::parse(f.next()?).ok()?,
        };
        f.next().is_none().then_some(rec)
    }
}

/// `ByteBroom\recycled.journal`, held open for appending like the move journal: opened inside the
/// held app folder without following a link, and never a hard link.
#[derive(Debug)]
pub struct RecycledJournal {
    file: File,
}

impl RecycledJournal {
    /// The file's name in ByteBroom's app folder.
    pub const NAME: &'static str = "recycled.journal";

    /// Open (or create) it inside the held app folder.
    pub fn open(dir: &LockedDir) -> Result<Self, String> {
        let (file, _) = dir.open_append(Self::NAME).map_err(|e| e.to_string())?;
        Ok(Self { file })
    }

    /// Add records and make sure they are on disk.
    pub fn append(&self, records: &[RecycledRecord]) -> Result<(), String> {
        if records.is_empty() {
            return Ok(());
        }
        let mut file = &self.file;
        let text: String = records.iter().map(|r| r.to_line() + "\n").collect();
        file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        self.file.sync_all().map_err(|e| e.to_string())
    }

    /// Every valid record, oldest first.
    pub fn records(&self) -> io::Result<Vec<RecycledRecord>> {
        use std::io::{Seek, SeekFrom};
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        Ok(text.lines().filter_map(RecycledRecord::parse).collect())
    }
}

/// Every item one clean recycled, as the shell reported it, for the recycled journal.
pub fn recycled_records(clean: u64, results: &[crate::act::ActionResult]) -> Vec<RecycledRecord> {
    let time = now_secs();
    results
        .iter()
        .flat_map(|r| r.outcome.recycled.iter())
        .map(|r| RecycledRecord {
            clean,
            time,
            size: r.bytes,
            original: r.original.clone(),
            in_bin: r.in_bin.clone(),
        })
        .collect()
}

/// The two history files, by name. Clearing removes both: the files they name stay exactly
/// where they are (decision 5), but moves can no longer be put back from ByteBroom.
pub const HISTORY_FILES: [&str; 2] = ["moves.journal", RecycledJournal::NAME];

/// Clear the history: delete both journals inside the held app folder, each opened relative to
/// it without following a link and only if it is a plain file with one name. A file that is not
/// there is fine. Nothing else is touched. No journal may be open while this runs.
///
/// A file just written can be held for a moment by another program (an antivirus scan, seen in
/// the tests), so a "file in use" is tried again a few times before it is reported.
pub fn clear_history(dir: &LockedDir) -> Result<(), String> {
    const SHARING_VIOLATION: i32 = 32;
    for name in HISTORY_FILES {
        let mut tries = 0;
        loop {
            match dir.remove_file(name) {
                Ok(()) => break,
                Err(e) if e.raw_os_error() == Some(SHARING_VIOLATION) && tries < 10 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(format!("{name} could not be cleared: {e}")),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u8, clean: Option<u64>) -> JournalEntry {
        JournalEntry {
            clean,
            time: 1_795_000_000 + u64::from(n),
            sha256: format!("{n:02X}").repeat(32),
            size: u64::from(n),
            source: WinPath::parse(&format!("C:\\Users\\Ann\\Downloads\\f{n}.iso")).unwrap(),
            dest: WinPath::parse(&format!("D:\\Moved\\f{n}.iso")).unwrap(),
        }
    }

    #[test]
    fn an_undone_line_marks_only_the_first_unmarked_matching_move() {
        let a = entry(1, Some(5));
        let again = JournalEntry {
            clean: Some(6),
            ..a.clone()
        };
        let lines = vec![
            JournalLine::Move(a.clone()),
            JournalLine::Move(entry(2, Some(5))),
            JournalLine::Undone(Undone::of(&a, 10)),
            JournalLine::Move(again.clone()),
        ];
        let h = move_history(&lines);
        assert_eq!(h.len(), 3);
        assert_eq!(h[0].undone, Some(10));
        assert_eq!(h[1].undone, None);
        assert_eq!(
            h[2].undone, None,
            "a later move of the same file is still moved"
        );
        // An "undone" line before any move marks nothing.
        let h = move_history(&[JournalLine::Undone(Undone::of(&a, 1)), JournalLine::Move(a)]);
        assert_eq!(h[0].undone, None);
    }

    #[test]
    fn moves_group_by_clean_newest_first_and_old_lines_stand_alone() {
        let rec = |e| MoveRecord {
            entry: e,
            undone: None,
        };
        let groups = group_by_clean(&[
            rec(entry(1, None)),
            rec(entry(2, None)),
            rec(entry(3, Some(7))),
            rec(entry(4, Some(7))),
            rec(entry(5, Some(9))),
        ]);
        let sizes: Vec<Vec<u64>> = groups
            .iter()
            .map(|g| g.iter().map(|r| r.entry.size).collect())
            .collect();
        assert_eq!(sizes, vec![vec![5], vec![3, 4], vec![2], vec![1]]);
    }

    #[test]
    fn recycled_lines_round_trip_and_reject_anything_else() {
        let r = RecycledRecord {
            clean: 7,
            time: 1_795_000_000,
            size: 12,
            original: WinPath::parse("C:\\Users\\Ann\\Downloads\\old.msi").unwrap(),
            in_bin: WinPath::parse("C:\\$Recycle.Bin\\S-1-5-21-1\\$RAB12CD.msi").unwrap(),
        };
        assert_eq!(RecycledRecord::parse(&r.to_line()), Some(r.clone()));
        assert_eq!(
            RecycledRecord::parse(&format!("{}\r\n", r.to_line())),
            Some(r.clone())
        );
        for bad in [
            String::new(),
            r.to_line().replace(RECYCLED_V1, "bytebroom-recycled-v2"),
            format!("{}\textra", r.to_line()),
            r.to_line().replace("\t12\t", "\tx\t"),
            entry(1, Some(1)).to_line(),
        ] {
            assert_eq!(RecycledRecord::parse(&bad), None, "{bad:?}");
        }
        // And a recycled line is never a move.
        assert_eq!(JournalLine::parse(&r.to_line()), None);
    }
}
