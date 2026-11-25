//! Moving items to another folder or drive: copy, verify, journal, and only then delete.
//!
//! The order is fixed in [`run_move`] and tested with a fake that fails at every step: the
//! original is deleted only after the copy matched it byte for byte (size and SHA-256, the
//! owner's decision 2) and the journal line that allows an undo is safely on disk. If any step
//! fails, the copy ByteBroom made is removed and the original stays.
//!
//! Nothing here works by path after a check (security review, must-fix 1 and 2): the
//! destination folder is held locked for the whole move, every copy is created inside that held
//! handle, and copies are verified and removed through their own handles.

use crate::engine::{MAX_DEPTH, Outcome, SkipReason, Skipped, Target, not_as_expected};
use crate::paths::WinPath;
use crate::policy::{Policy, denied_reason};
use crate::scan::FileIdentity;
use crate::win::dir::{CreateError, Created, LockedDir, lock_dir};
use crate::win::hash::Sha256;
use crate::win::{self, Access, Opened};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// One move, as recorded in the journal so it can be undone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    /// Seconds since 1970 (UTC) when the move was recorded.
    pub time: u64,
    /// SHA-256 of the file, upper-case hex.
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
    /// Where the file was.
    pub source: WinPath,
    /// Where it is now.
    pub dest: WinPath,
}

const JOURNAL_VERSION: &str = "bytebroom-move-v1";

impl JournalEntry {
    /// One tab-separated line. Paths can't contain tabs: [`WinPath`] refuses control characters.
    pub fn to_line(&self) -> String {
        format!(
            "{JOURNAL_VERSION}\t{}\t{}\t{}\t{}\t{}",
            self.time, self.sha256, self.size, self.source, self.dest
        )
    }

    /// Parse a line written by [`Self::to_line`]. Anything else gives `None`.
    pub fn parse(line: &str) -> Option<Self> {
        let mut fields = line.trim_end_matches(['\r', '\n']).split('\t');
        if fields.next()? != JOURNAL_VERSION {
            return None;
        }
        let time = fields.next()?.parse().ok()?;
        let sha256 = fields.next()?.to_string();
        if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let size = fields.next()?.parse().ok()?;
        let source = WinPath::parse(fields.next()?).ok()?;
        let dest = WinPath::parse(fields.next()?).ok()?;
        if fields.next().is_some() {
            return None;
        }
        Some(Self {
            time,
            sha256,
            size,
            source,
            dest,
        })
    }
}

/// Every valid entry in a journal file, oldest first. Unreadable lines are skipped. The
/// journal is user-writable, so entries are treated as untrusted: see [`undo_move`].
pub fn read_journal(path: &Path) -> io::Result<Vec<JournalEntry>> {
    let text = std::fs::read_to_string(path)?;
    Ok(text.lines().filter_map(JournalEntry::parse).collect())
}

/// The move journal, held open for appending. It is opened inside a held folder without
/// following any link, and must not be a hard link (security review note 7): run as
/// administrator, ByteBroom must never be steered into writing somewhere else.
#[derive(Debug)]
pub struct Journal {
    file: File,
    /// Where it is.
    pub path: WinPath,
}

impl Journal {
    /// Open (or create) the journal `name` inside the held folder `dir`.
    pub fn open(dir: &LockedDir, name: &str) -> Result<Self, String> {
        let (file, path) = dir.open_append(name).map_err(|e| e.to_string())?;
        Ok(Self { file, path })
    }

    /// Add one entry and make sure it is on disk.
    pub fn append(&self, entry: &JournalEntry) -> Result<(), String> {
        let mut file = &self.file;
        writeln!(file, "{}", entry.to_line()).map_err(|e| e.to_string())?;
        self.file.sync_all().map_err(|e| e.to_string())
    }

    /// Every valid entry, oldest first, read through the held handle.
    pub fn entries(&self) -> io::Result<Vec<JournalEntry>> {
        use std::io::{Seek, SeekFrom};
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        Ok(text.lines().filter_map(JournalEntry::parse).collect())
    }
}

/// ByteBroom's own folder, `<base>\ByteBroom` (base: the owner's local app data), reached
/// without following any link and held locked. `base` itself must be a real folder at exactly
/// that path, so a junction anywhere on the way is refused (security review note 7).
pub fn app_folder(base: &WinPath) -> Result<LockedDir, String> {
    let held = lock_dir(base).map_err(|e| format!("{base}: {e}"))?;
    if held.path != *base {
        return Err(format!(
            "{base} is reached through a link; ByteBroom won't use it"
        ));
    }
    held.open_or_create_dir("ByteBroom")
        .map_err(|e| e.to_string())
}

/// The steps of one file move. The real implementation is [`RealMove`]; tests use fakes.
pub trait MoveSteps {
    /// Copy the original to a new file; return its size and SHA-256.
    fn copy(&mut self) -> Result<(u64, String), String>;
    /// Check the copy has exactly this size and hash.
    fn verify(&mut self, size: u64, sha256: &str) -> Result<(), String>;
    /// Append the journal line and make sure it is on disk.
    fn journal(&mut self, size: u64, sha256: &str) -> Result<(), String>;
    /// Delete the original.
    fn delete_source(&mut self) -> Result<(), String>;
    /// Remove the copy this move created (never a file it did not create).
    fn remove_copy(&mut self);
}

/// Which step of a move failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Copying.
    Copy,
    /// Checking the copy.
    Verify,
    /// Writing the journal.
    Journal,
    /// Deleting the original.
    DeleteSource,
}

/// The result of one file move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoveResult {
    /// Copied, checked, journalled and the original deleted.
    Moved {
        /// Bytes moved.
        size: u64,
    },
    /// Stopped at `step`; the original is still in place and the copy was removed.
    Failed {
        /// The step that failed.
        step: Step,
        /// What went wrong.
        why: String,
    },
}

/// Run the steps in the only safe order.
pub fn run_move(steps: &mut impl MoveSteps) -> MoveResult {
    let fail = |steps: &mut dyn MoveSteps, step, why| {
        steps.remove_copy();
        MoveResult::Failed { step, why }
    };
    let (size, sha256) = match steps.copy() {
        Ok(v) => v,
        Err(why) => return fail(steps, Step::Copy, why),
    };
    if let Err(why) = steps.verify(size, &sha256) {
        return fail(steps, Step::Verify, why);
    }
    if let Err(why) = steps.journal(size, &sha256) {
        return fail(steps, Step::Journal, why);
    }
    if let Err(why) = steps.delete_source() {
        return fail(steps, Step::DeleteSource, why);
    }
    MoveResult::Moved { size }
}

/// Hash a reader's contents, optionally copying them; returns (size, SHA-256).
fn hash_reader(
    mut reader: impl Read,
    mut sink: Option<&mut File>,
) -> Result<(u64, String), String> {
    let mut hash = Sha256::new().ok_or("Windows could not start a SHA-256 hash")?;
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        if !hash.update(&buf[..n]) {
            return Err("hashing failed".into());
        }
        if let Some(out) = sink.as_deref_mut() {
            out.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        }
        total += n as u64;
    }
    let hex = hash.finish_hex().ok_or("hashing failed")?;
    Ok((total, hex))
}

fn numbered(name: &str, n: u32, keep_extension: bool) -> String {
    if n == 1 {
        return name.to_string();
    }
    match name.rsplit_once('.') {
        Some((stem, ext)) if keep_extension && !stem.is_empty() => format!("{stem} ({n}).{ext}"),
        _ => format!("{name} ({n})"),
    }
}

/// Create a new file in `dir` named like `name`, never overwriting or following anything:
/// "a.txt", then "a (2).txt", "a (3).txt", ...
fn create_unique_file(dir: &LockedDir, name: &str) -> Result<Created, String> {
    for n in 1..=1000u32 {
        match dir.create_file(&numbered(name, n, true)) {
            Ok(created) => return Ok(created),
            Err(CreateError::Exists) => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("no free name in the destination folder".into())
}

/// Create a new folder in `dir` named like `name`, never reusing an existing one.
fn create_unique_dir(dir: &LockedDir, name: &str) -> Result<LockedDir, String> {
    for n in 1..=1000u32 {
        match dir.create_dir(&numbered(name, n, false)) {
            Ok(created) => return Ok(created),
            Err(CreateError::Exists) => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("no free name in the destination folder".into())
}

/// The real move of one checked file into a held destination folder.
pub struct RealMove<'a> {
    source: Option<Opened>,
    source_path: WinPath,
    dest_dir: &'a LockedDir,
    name: String,
    journal: &'a Journal,
    /// Only a file this move created; removed through its own handle.
    created: Option<Created>,
}

impl<'a> RealMove<'a> {
    /// `source` must have been opened with [`Access::Move`] and checked against the policy.
    pub fn new(
        source: Opened,
        name: String,
        dest_dir: &'a LockedDir,
        journal: &'a Journal,
    ) -> Self {
        let source_path = source.resolved.final_path.clone();
        Self {
            source: Some(source),
            source_path,
            dest_dir,
            name,
            journal,
            created: None,
        }
    }
}

impl MoveSteps for RealMove<'_> {
    fn copy(&mut self) -> Result<(u64, String), String> {
        let source = self
            .source
            .as_ref()
            .ok_or("the original is no longer open")?;
        let reader = source.reader().map_err(|e| e.to_string())?;
        let created = create_unique_file(self.dest_dir, &self.name)?;
        let mut file = created.file().map_err(|e| e.to_string())?;
        self.created = Some(created);
        let result = hash_reader(reader, Some(&mut file))?;
        file.sync_all().map_err(|e| e.to_string())?;
        Ok(result)
    }

    fn verify(&mut self, size: u64, sha256: &str) -> Result<(), String> {
        let created = self.created.as_ref().ok_or("no copy to check")?;
        let file = created.file().map_err(|e| e.to_string())?;
        let (copy_size, copy_hash) = hash_reader(file, None)?;
        if copy_size != size || copy_hash != sha256 {
            return Err("the copy does not match the original".into());
        }
        Ok(())
    }

    fn journal(&mut self, size: u64, sha256: &str) -> Result<(), String> {
        let dest = self
            .created
            .as_ref()
            .map(|c| c.path.clone())
            .ok_or("no copy to record")?;
        let entry = JournalEntry {
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            sha256: sha256.to_string(),
            size,
            source: self.source_path.clone(),
            dest,
        };
        self.journal.append(&entry)
    }

    fn delete_source(&mut self) -> Result<(), String> {
        let source = self.source.take().ok_or("the original is no longer open")?;
        win::delete_by_handle(source).map_err(|e| e.to_string())
    }

    fn remove_copy(&mut self) {
        if let Some(created) = self.created.take() {
            let _ = created.delete();
        }
    }
}

/// Move each target into `dest_dir` (files, or folders with everything inside), within
/// `policy`, recording every file in `journal`. Space comes back only when the destination is
/// on another drive and the file had no other hard links.
pub fn move_to(
    policy: &Policy,
    targets: &[WinPath],
    dest_dir: &WinPath,
    journal: &Journal,
) -> Outcome {
    let targets: Vec<Target> = targets.iter().map(Target::any).collect();
    move_targets(policy, &targets, dest_dir, journal)
}

/// Like [`move_to`], and each file with a recorded identity must still have it on the handle
/// the copy is read from and the original deleted through.
pub fn move_targets(
    policy: &Policy,
    targets: &[Target],
    dest_dir: &WinPath,
    journal: &Journal,
) -> Outcome {
    let mut out = Outcome::default();
    let paths: Vec<WinPath> = targets.iter().map(|t| t.path.clone()).collect();
    let dest = match check_destination(policy, &paths, dest_dir) {
        Ok(d) => d,
        Err(why) => {
            for t in &paths {
                out.skipped.push(Skipped {
                    path: t.clone(),
                    reason: SkipReason::Unsupported(why.clone()),
                });
            }
            return out;
        }
    };
    for target in targets {
        move_one(
            policy,
            &target.path,
            target.expect.as_ref(),
            &dest,
            journal,
            0,
            &mut out,
        );
    }
    out
}

/// Lock the destination (a real folder, not a link), outside the hard floor and not inside
/// anything being moved. It stays locked until the whole move is done.
fn check_destination(
    policy: &Policy,
    targets: &[WinPath],
    dest: &WinPath,
) -> Result<LockedDir, String> {
    let locked = lock_dir(dest).map_err(|e| format!("destination folder: {e}"))?;
    if let Some(why) = denied_reason(&locked.path, policy.layout()) {
        return Err(format!("the destination is a protected area: {why}"));
    }
    for t in targets {
        if locked.path.is_at_or_inside_ignore_case(t) {
            return Err("the destination is inside something being moved".into());
        }
    }
    Ok(locked)
}

fn skip(out: &mut Outcome, path: &WinPath, reason: SkipReason) {
    out.skipped.push(Skipped {
        path: path.clone(),
        reason,
    });
}

fn move_one(
    policy: &Policy,
    path: &WinPath,
    expect: Option<&FileIdentity>,
    dest_dir: &LockedDir,
    journal: &Journal,
    depth: usize,
    out: &mut Outcome,
) -> bool {
    if depth > MAX_DEPTH {
        skip(out, path, SkipReason::TooDeep);
        return false;
    }
    let opened = match win::open_no_follow(path, Access::Move) {
        Ok(o) => o,
        Err(e) => {
            skip(out, path, e.into());
            return false;
        }
    };
    if let Err(r) = policy.check_target(&opened.resolved) {
        skip(out, path, SkipReason::Refused(r));
        return false;
    }
    // On the handle the copy is read from: it refuses write-sharing, so the bytes copied are
    // those of the file that matched.
    if let Some(what) = expect.and_then(|e| not_as_expected(&opened, e)) {
        skip(out, path, SkipReason::ChangedSinceScan(what));
        return false;
    }
    let real = opened.resolved.final_path.clone();
    let Some(name) = real.parts().last().cloned() else {
        skip(out, path, SkipReason::Unsupported("no file name".into()));
        return false;
    };

    if !opened.is_directory {
        let other_volume = opened.volume_serial != dest_dir.volume_serial;
        let frees = other_volume && opened.link_count <= 1;
        let mut steps = RealMove::new(opened, name, dest_dir, journal);
        return match run_move(&mut steps) {
            MoveResult::Moved { size } => {
                out.removed.push(real);
                out.bytes_moved += size;
                if frees {
                    out.bytes_freed += size;
                }
                true
            }
            MoveResult::Failed { step, why } => {
                skip(
                    out,
                    path,
                    SkipReason::Failed(format!("{why} (at {step:?}; the original is kept)")),
                );
                false
            }
        };
    }

    // A folder: recreate it inside the held destination, move its children, then remove the
    // original if it is empty.
    drop(opened);
    let new_dir = match create_unique_dir(dest_dir, &name) {
        Ok(d) => d,
        Err(why) => {
            skip(out, path, SkipReason::Failed(why));
            return false;
        }
    };
    let names = match win::list_children(&real) {
        Ok(n) => n,
        Err(e) => {
            let _ = new_dir.remove_if_empty();
            skip(out, path, SkipReason::Failed(e.to_string()));
            return false;
        }
    };
    let mut all_gone = true;
    let mut moved_any = false;
    for child_name in names {
        match real.join(&child_name) {
            Ok(child) => {
                let gone = move_one(policy, &child, None, &new_dir, journal, depth + 1, out);
                all_gone &= gone;
                moved_any |= gone;
            }
            Err(e) => {
                all_gone = false;
                skip(
                    out,
                    &real,
                    SkipReason::Unsupported(format!("{child_name:?}: {e}")),
                );
            }
        }
    }
    if !all_gone {
        if !moved_any {
            // Leave no empty copy behind, removed through its own handle.
            let _ = new_dir.remove_if_empty();
        }
        skip(out, path, SkipReason::NotEmpty);
        return false;
    }
    let again = match win::open_no_follow(path, Access::Delete) {
        Ok(o) => o,
        Err(e) => {
            skip(out, path, e.into());
            return false;
        }
    };
    if policy.check_target(&again.resolved).is_err() || again.resolved.final_path != real {
        skip(
            out,
            path,
            SkipReason::Unsupported("the folder changed while it was being moved".into()),
        );
        return false;
    }
    match win::delete_by_handle(again) {
        Ok(()) => {
            out.removed.push(real);
            true
        }
        Err(e) => {
            skip(out, path, SkipReason::Failed(e.to_string()));
            false
        }
    }
}

fn parent_of(path: &WinPath) -> Option<(WinPath, String)> {
    let (name, head) = path.parts().split_last()?;
    let parent = head
        .iter()
        .try_fold(WinPath::drive_root(path.drive()), |acc, part| {
            acc.join(part)
        })
        .ok()?;
    Some((parent, name.clone()))
}

/// Put a moved file back where it came from.
///
/// The journal is user-writable, so its entries are untrusted (security review, must-fix 2):
/// the original's folder must be a real folder inside `policy`'s allowed roots; it is held
/// locked while the file is recreated *inside* it, never overwriting anything; and the moved
/// copy is deleted only after the restored file matched the recorded size and SHA-256.
pub fn undo_move(policy: &Policy, entry: &JournalEntry) -> Result<(), String> {
    let (parent, name) = parent_of(&entry.source).ok_or("the original path has no folder")?;
    let folder = lock_dir(&parent).map_err(|e| format!("the original folder: {e}"))?;
    policy
        .check_container(&crate::policy::ResolvedPath {
            final_path: folder.path.clone(),
            is_reparse_point: false,
        })
        .map_err(|r| format!("the original folder: {r}"))?;

    let moved = win::open_no_follow(&entry.dest, Access::Move)
        .map_err(|e| format!("the moved file: {e}"))?;
    if moved.resolved.is_reparse_point || moved.is_directory {
        return Err("the moved file is not a plain file any more".into());
    }
    let (size, hash) = hash_reader(moved.reader().map_err(|e| e.to_string())?, None)?;
    if size != entry.size || hash != entry.sha256 {
        return Err("the moved file has changed since it was moved".into());
    }

    let restored = match folder.create_file(&name) {
        Ok(c) => c,
        Err(CreateError::Exists) => return Err("something is already at the original place".into()),
        Err(e) => return Err(format!("cannot recreate the original: {e}")),
    };
    let copied = restored
        .file()
        .map_err(|e| e.to_string())
        .and_then(|mut f| {
            let r = hash_reader(moved.reader().map_err(|e| e.to_string())?, Some(&mut f))?;
            f.sync_all().map_err(|e| e.to_string())?;
            Ok(r)
        });
    let checked = restored
        .file()
        .map_err(|e| e.to_string())
        .and_then(|f| hash_reader(f, None));
    match (copied, checked) {
        (Ok(_), Ok((s, h))) if s == entry.size && h == entry.sha256 => {
            drop(restored);
            win::delete_by_handle(moved).map_err(|e| e.to_string())
        }
        _ => {
            let _ = restored.delete();
            Err("restoring failed; the moved file was left where it is".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records which steps ran, and fails at the chosen one.
    struct Fake {
        fail_at: Option<Step>,
        log: Vec<&'static str>,
    }

    impl Fake {
        fn result(&mut self, step: Step, name: &'static str) -> Result<(), String> {
            self.log.push(name);
            if self.fail_at == Some(step) {
                Err(format!("{name} broke"))
            } else {
                Ok(())
            }
        }
    }

    impl MoveSteps for Fake {
        fn copy(&mut self) -> Result<(u64, String), String> {
            self.result(Step::Copy, "copy")
                .map(|()| (3, "AB".repeat(32)))
        }
        fn verify(&mut self, _: u64, _: &str) -> Result<(), String> {
            self.result(Step::Verify, "verify")
        }
        fn journal(&mut self, _: u64, _: &str) -> Result<(), String> {
            self.result(Step::Journal, "journal")
        }
        fn delete_source(&mut self) -> Result<(), String> {
            self.result(Step::DeleteSource, "delete")
        }
        fn remove_copy(&mut self) {
            self.log.push("remove-copy");
        }
    }

    #[test]
    fn a_clean_run_deletes_the_original_last() {
        let mut fake = Fake {
            fail_at: None,
            log: vec![],
        };
        assert_eq!(run_move(&mut fake), MoveResult::Moved { size: 3 });
        assert_eq!(fake.log, ["copy", "verify", "journal", "delete"]);
    }

    #[test]
    fn a_failure_at_any_step_keeps_the_original_and_removes_the_copy() {
        let cases = [
            (Step::Copy, vec!["copy", "remove-copy"]),
            (Step::Verify, vec!["copy", "verify", "remove-copy"]),
            (
                Step::Journal,
                vec!["copy", "verify", "journal", "remove-copy"],
            ),
            (
                Step::DeleteSource,
                vec!["copy", "verify", "journal", "delete", "remove-copy"],
            ),
        ];
        for (step, want) in cases {
            let mut fake = Fake {
                fail_at: Some(step),
                log: vec![],
            };
            let got = run_move(&mut fake);
            assert!(
                matches!(got, MoveResult::Failed { step: s, .. } if s == step),
                "{got:?}"
            );
            assert_eq!(fake.log, want, "failing at {step:?}");
            // The original is only ever deleted after copy, verify and journal all succeeded.
            if step != Step::DeleteSource {
                assert!(!fake.log.contains(&"delete"));
            }
        }
    }

    #[test]
    fn journal_lines_round_trip_and_reject_anything_else() {
        let entry = JournalEntry {
            time: 1_795_000_000,
            sha256: "0F".repeat(32),
            size: 42,
            source: WinPath::parse("C:\\Users\\Ann\\Downloads\\big file.iso").unwrap(),
            dest: WinPath::parse("D:\\Moved\\big file.iso").unwrap(),
        };
        assert_eq!(JournalEntry::parse(&entry.to_line()), Some(entry.clone()));
        assert_eq!(
            JournalEntry::parse(&format!("{}\r\n", entry.to_line())),
            Some(entry.clone())
        );
        for bad in [
            String::new(),
            "bytebroom-move-v0\t1\t00\t1\tC:\\a\tD:\\b".into(),
            entry.to_line().replace("\tD:\\", "\tD:\\..\\"),
            entry.to_line().replace(&"0F".repeat(32), "xyz"),
            format!("{}\textra", entry.to_line()),
        ] {
            assert_eq!(JournalEntry::parse(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn numbered_names_keep_the_extension() {
        assert_eq!(numbered("a.tmp", 1, true), "a.tmp");
        assert_eq!(numbered("a.tmp", 2, true), "a (2).tmp");
        assert_eq!(numbered(".hidden", 2, true), ".hidden (2)");
        assert_eq!(numbered("folder.v2", 3, false), "folder.v2 (3)");
    }
}
