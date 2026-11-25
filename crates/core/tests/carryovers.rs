//! Phase 3's security notes, fixed before phase 4 (elevation), on fake trees in temp folders:
//!
//! - **note 3:** a file's identity (file ID, size, date) is compared on the very handle that
//!   deletes, copies or recycles it. Each test swaps or rewrites the file *after* the check
//!   right before acting, then calls the engine directly, as a fast attacker would.
//! - **note 7:** the move journal's folder and file are opened without following links.
//!
//! The Recycle Bin tests pass a stand-in for the shell; no real bin is ever used.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::engine::{SkipReason, Target, delete_targets};
use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::Policy;
use bytebroom_core::recycle::{is_in_recycle_bin, is_same_open_file, recycle_with};
use bytebroom_core::relocate::{Journal, JournalEntry, app_folder, move_targets, read_journal};
use bytebroom_core::scan::FileIdentity;
use bytebroom_core::win::dir::lock_dir;
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::*;
use std::cell::RefCell;
use std::fs::{self, File};
use std::path::Path;
use std::time::{Duration, SystemTime};

fn wp(path: &Path) -> WinPath {
    WinPath::parse(path.to_str().unwrap()).unwrap()
}

fn real(path: &Path) -> WinPath {
    open_no_follow(&wp(path), Access::Inspect)
        .unwrap()
        .resolved
        .final_path
}

/// The identity the scan would have recorded for `path`.
fn identity_of(path: &Path) -> FileIdentity {
    let o = open_no_follow(&wp(path), Access::Inspect).unwrap();
    FileIdentity {
        id: o.file_id().unwrap(),
        len: o.size,
        modified: o.modified,
    }
}

fn dated(path: &Path, bytes: &[u8], when: SystemTime) {
    write_file(path, bytes);
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

/// A fresh root with two files, `a.tmp` and `b.tmp`, and the policy for it.
struct Root {
    dir: CleanDir,
    root: std::path::PathBuf,
    policy: Policy,
}

impl Root {
    fn new(tag: &str) -> Self {
        let dir = CleanDir::new(tag);
        let root = dir.0.join("root");
        let when = SystemTime::now() - Duration::from_secs(40 * 24 * 3600);
        dated(&root.join("a.tmp"), &[1; 300], when);
        dated(&root.join("b.tmp"), &[2; 400], when);
        let resolved = open_no_follow(&wp(&root), Access::Inspect)
            .unwrap()
            .resolved;
        let policy = Policy::new(vec![resolved], system_layout()).unwrap();
        Self { dir, root, policy }
    }

    fn file(&self, name: &str) -> std::path::PathBuf {
        self.root.join(name)
    }

    /// Put another file in `name`'s place: same name, size and date; only the file ID differs.
    fn swap(&self, name: &str) {
        let path = self.file(name);
        let seen = identity_of(&path);
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        dated(&path, &bytes, seen.modified);
        assert_ne!(
            identity_of(&path).id,
            seen.id,
            "the swap must change the file ID"
        );
    }

    fn target(&self, name: &str, expect: FileIdentity) -> Target {
        Target {
            path: real(&self.file(name)),
            expect: Some(expect),
        }
    }
}

// ---- note 3: delete ----

#[test]
fn delete_refuses_a_file_swapped_after_the_check_on_its_own_handle() {
    let r = Root::new("hid-del-swap");
    let seen = identity_of(&r.file("a.tmp"));
    let keep = identity_of(&r.file("b.tmp"));
    r.swap("a.tmp");
    let out = delete_targets(
        &r.policy,
        &[r.target("a.tmp", seen), r.target("b.tmp", keep)],
    );
    assert!(r.file("a.tmp").exists(), "the swapped-in file must stay");
    assert!(!r.file("b.tmp").exists(), "the unchanged file still goes");
    assert_eq!(out.skipped.len(), 1, "{:?}", out.skipped);
    assert_eq!(
        out.skipped[0].reason,
        SkipReason::ChangedSinceScan("another file is in its place")
    );
    assert_eq!(out.bytes_freed, 400);
}

#[test]
fn delete_refuses_a_file_rewritten_after_the_check() {
    let r = Root::new("hid-del-rewrite");
    let seen = identity_of(&r.file("a.tmp"));
    // Same file (same ID), new contents.
    fs::write(r.file("a.tmp"), [7; 50]).unwrap();
    let out = delete_targets(&r.policy, &[r.target("a.tmp", seen)]);
    assert!(r.file("a.tmp").exists());
    assert_eq!(
        out.skipped[0].reason,
        SkipReason::ChangedSinceScan("its contents changed")
    );
}

#[test]
fn delete_refuses_a_folder_put_where_a_file_was() {
    let r = Root::new("hid-del-folder");
    let seen = identity_of(&r.file("a.tmp"));
    fs::remove_file(r.file("a.tmp")).unwrap();
    write_file(&r.file("a.tmp").join("inside.txt"), b"x");
    let out = delete_targets(&r.policy, &[r.target("a.tmp", seen)]);
    assert!(r.file("a.tmp").join("inside.txt").exists());
    assert_eq!(
        out.skipped[0].reason,
        SkipReason::ChangedSinceScan("it is no longer a plain file")
    );
}

// ---- note 3: move ----

#[test]
fn move_refuses_a_swapped_file_and_copies_nothing() {
    let r = Root::new("hid-move-swap");
    let dest = r.dir.0.join("dest");
    fs::create_dir_all(&dest).unwrap();
    let journal_path = r.dir.0.join("app").join("moves.journal");
    let journal = journal_at(&journal_path);
    let seen = identity_of(&r.file("a.tmp"));
    let keep = identity_of(&r.file("b.tmp"));
    r.swap("a.tmp");
    let out = move_targets(
        &r.policy,
        &[r.target("a.tmp", seen), r.target("b.tmp", keep)],
        &real(&dest),
        &journal,
    );
    assert!(r.file("a.tmp").exists());
    assert!(
        !dest.join("a.tmp").exists(),
        "nothing of the swapped file is copied"
    );
    assert!(dest.join("b.tmp").exists() && !r.file("b.tmp").exists());
    assert_eq!(
        out.skipped[0].reason,
        SkipReason::ChangedSinceScan("another file is in its place")
    );
    let entries = read_journal(&journal_path).unwrap();
    assert_eq!(entries.len(), 1, "only the real move is journalled");
    assert!(entries[0].source.to_string().ends_with("b.tmp"));
}

// ---- note 3: Recycle Bin (stand-in shell only) ----

#[test]
fn recycle_refuses_a_swapped_file_before_the_shell_is_called() {
    let r = Root::new("hid-bin-swap");
    let seen = identity_of(&r.file("a.tmp"));
    let keep = identity_of(&r.file("b.tmp"));
    r.swap("a.tmp");
    let asked = RefCell::new(Vec::new());
    let shell = |p: &WinPath| {
        asked.borrow_mut().push(p.clone());
        Ok(None) // a stand-in: moves nothing
    };
    let out = recycle_with(
        &r.policy,
        &[r.target("a.tmp", seen), r.target("b.tmp", keep)],
        &shell,
    );
    assert_eq!(asked.into_inner(), vec![real(&r.file("b.tmp"))]);
    assert!(out.skipped.iter().any(|s| s.path == real(&r.file("a.tmp"))
        && s.reason == SkipReason::ChangedSinceScan("another file is in its place")));
}

#[test]
fn recycle_warns_when_the_shell_reports_nothing_in_the_bin() {
    let r = Root::new("hid-bin-race");
    let seen = identity_of(&r.file("a.tmp"));
    let aside = r.file("aside.tmp");
    // The path is gone but the "shell" reports no item in the bin (as when Windows deletes
    // for good): a warning that says so (re-review N1), never a quiet success.
    let shell = |p: &WinPath| {
        fs::rename(format!("\\\\?\\{p}"), &aside).unwrap();
        Ok(None)
    };
    let out = recycle_with(&r.policy, &[r.target("a.tmp", seen)], &shell);
    assert!(aside.exists());
    assert_eq!(out.warnings.len(), 1, "{out:?}");
    assert!(
        out.warnings[0]
            .reason
            .to_string()
            .contains("may have deleted this permanently"),
        "{:?}",
        out.warnings[0]
    );
}

/// Review S2: the attacker moves the checked file aside, puts another file at the path, and
/// the shell recycles that one. Here the "shell" reports a file other than the checked one as
/// the item it created: that must be a warning, never a quiet success.
#[test]
fn recycle_warns_when_the_shell_reports_another_file_as_recycled() {
    let r = Root::new("hid-bin-other");
    let seen = identity_of(&r.file("a.tmp"));
    let aside = r.file("aside.tmp");
    let other = real(&r.file("b.tmp"));
    let shell = |p: &WinPath| {
        fs::rename(format!("\\\\?\\{p}"), &aside).unwrap();
        Ok(Some(other.clone()))
    };
    let out = recycle_with(&r.policy, &[r.target("a.tmp", seen)], &shell);
    assert_eq!(out.warnings.len(), 1, "{out:?}");
    assert!(
        out.warnings[0]
            .reason
            .to_string()
            .contains("another file took its place"),
        "{:?}",
        out.warnings[0]
    );
}

/// Review S2: the comparison behind "the shell recycled the file we checked", on temp files.
#[test]
fn the_reported_item_must_be_the_watched_file_itself() {
    let r = Root::new("hid-same");
    let a = real(&r.file("a.tmp"));
    let watch = open_no_follow(&a, Access::Inspect).unwrap();
    assert!(is_same_open_file(&watch, &a));
    assert!(!is_same_open_file(&watch, &real(&r.file("b.tmp"))));
    // Moved (as the shell moves it into the bin): still the same file, at its new place.
    let moved = r.file("moved.tmp");
    fs::rename(r.file("a.tmp"), &moved).unwrap();
    assert!(is_same_open_file(&watch, &real(&moved)));
    // A copy with the same contents, size and date is another file.
    let copy = r.file("copy.tmp");
    fs::copy(&moved, &copy).unwrap();
    assert!(!is_same_open_file(&watch, &real(&copy)));
    // A junction at the reported place is never taken for the file.
    let link = r.file("link");
    make_junction(&link, &r.root);
    assert!(!is_same_open_file(&watch, &wp(&link)));
    fs::remove_dir(&link).unwrap();
}

#[test]
fn only_paths_inside_a_drives_recycle_bin_count_as_recycled() {
    let p = |s: &str| WinPath::parse(s).unwrap();
    assert!(is_in_recycle_bin(&p(
        "C:\\$Recycle.Bin\\S-1-5-21-1-2-3-1001\\$RAB12CD.tmp"
    )));
    assert!(is_in_recycle_bin(&p("D:\\$RECYCLE.BIN\\S-1-5-18\\$R1.txt")));
    for not in [
        "C:\\$Recycle.Bin",
        "C:\\Temp\\$Recycle.Bin\\x",
        "C:\\Users\\Ann\\a.tmp",
        "C:\\$Recycle.Bin2\\x",
    ] {
        assert!(!is_in_recycle_bin(&p(not)), "{not}");
    }
}

// ---- note 7: the journal's folder and file ----

#[test]
fn the_app_folder_is_made_once_and_reopened_without_following_links() {
    let dir = CleanDir::new("jr-make");
    let base = real(&dir.0);
    let first = app_folder(&base).unwrap();
    assert_eq!(first.path, base.join("ByteBroom").unwrap());
    drop(first);
    let again = app_folder(&base).unwrap();
    let journal = Journal::open(&again, "moves.journal").unwrap();
    let entry = JournalEntry {
        time: 1,
        sha256: "A".repeat(64),
        size: 3,
        source: WinPath::parse("D:\\From\\x.bin").unwrap(),
        dest: WinPath::parse("E:\\To\\x.bin").unwrap(),
    };
    journal.append(&entry).unwrap();
    journal.append(&entry).unwrap();
    assert_eq!(journal.entries().unwrap(), vec![entry.clone(), entry]);
}

#[test]
fn a_junction_in_place_of_the_app_folder_is_refused_and_not_followed() {
    let dir = CleanDir::new("jr-junction");
    let sentinel = dir.0.join("sentinel");
    write_file(&sentinel.join("keep.txt"), b"keep");
    let base = dir.0.join("Local");
    fs::create_dir_all(&base).unwrap();
    make_junction(&base.join("ByteBroom"), &sentinel);
    let err = app_folder(&real(&base)).unwrap_err();
    assert!(err.contains("link"), "{err}");
    let names: Vec<_> = fs::read_dir(&sentinel).unwrap().collect();
    assert_eq!(names.len(), 1, "nothing was written through the junction");
    fs::remove_dir(base.join("ByteBroom")).unwrap(); // the junction itself, before cleanup
}

#[test]
fn a_base_folder_reached_through_a_junction_is_refused() {
    let dir = CleanDir::new("jr-base");
    let target = dir.0.join("elsewhere");
    fs::create_dir_all(&target).unwrap();
    let link = dir.0.join("Local");
    make_junction(&link, &target);
    // The path as asked, through the junction (what a planted link would look like).
    let asked = wp(&link);
    assert!(app_folder(&asked).is_err());
    assert!(
        !target.join("ByteBroom").exists(),
        "nothing made through the junction"
    );
    fs::remove_dir(&link).unwrap();
}

#[test]
fn a_hard_linked_or_linked_journal_is_refused() {
    let dir = CleanDir::new("jr-hardlink");
    let sentinel = dir.0.join("sentinel");
    write_file(&sentinel.join("precious.txt"), b"precious");
    let app = dir.0.join("app");
    fs::create_dir_all(&app).unwrap();
    fs::hard_link(sentinel.join("precious.txt"), app.join("moves.journal")).unwrap();
    make_junction(&app.join("other.journal"), &sentinel);
    let held = lock_dir(&real(&app)).unwrap();
    let err = Journal::open(&held, "moves.journal").unwrap_err();
    assert!(err.contains("hard links"), "{err}");
    assert!(Journal::open(&held, "other.journal").is_err());
    assert_eq!(
        fs::read(sentinel.join("precious.txt")).unwrap(),
        b"precious"
    );
    drop(held);
    fs::remove_dir(app.join("other.journal")).unwrap();
}

/// The log starts again above its size limit by renaming it inside the held folder: a plain
/// file is renamed (replacing the old copy); a hard-linked one is refused and left alone.
#[test]
fn the_log_is_renamed_only_inside_the_held_folder_and_only_if_plain() {
    let dir = CleanDir::new("jr-rotate");
    let app = dir.0.join("app");
    write_file(&app.join("bytebroom.log"), b"new");
    write_file(&app.join("bytebroom.log.old"), b"old");
    let held = lock_dir(&real(&app)).unwrap();
    held.replace_name("bytebroom.log", "bytebroom.log.old")
        .unwrap();
    assert!(!app.join("bytebroom.log").exists());
    assert_eq!(fs::read(app.join("bytebroom.log.old")).unwrap(), b"new");

    let sentinel = dir.0.join("sentinel");
    write_file(&sentinel.join("precious.txt"), b"precious");
    fs::hard_link(sentinel.join("precious.txt"), app.join("bytebroom.log")).unwrap();
    assert!(
        held.replace_name("bytebroom.log", "bytebroom.log.old")
            .is_err()
    );
    assert!(app.join("bytebroom.log").exists());
    assert_eq!(
        fs::read(sentinel.join("precious.txt")).unwrap(),
        b"precious"
    );
    assert!(held.replace_name("bytebroom.log", "..\\escape").is_err());
}

/// Re-review R1: the shell parses paths through its namespace, where a folder with a planted
/// `desktop.ini` can be a "folder shortcut" to somewhere else. The item the shell would recycle
/// must be exactly the checked path; a plain file is, a path through a folder shortcut is not.
/// Nothing is recycled here: this only parses names.
#[test]
fn the_shell_item_must_be_exactly_the_checked_path() {
    use bytebroom_core::win::fileop::shell_sees_exactly;
    let r = Root::new("hid-shortcut");
    assert!(shell_sees_exactly(&real(&r.file("a.tmp"))));

    let sentinel = r.dir.0.join("sentinel");
    write_file(&sentinel.join("keep.txt"), b"keep");
    let shortcut = r.root.join("fs");
    fs::create_dir_all(&shortcut).unwrap();
    fs::write(
        shortcut.join("desktop.ini"),
        "[.ShellClassInfo]\r\nCLSID2={0AFACED1-E828-11D1-9187-B532F1E9575D}\r\nFlags=2\r\n",
    )
    .unwrap();
    let script = format!(
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath='{}'; $s.Save()",
        shortcut.join("target.lnk").display(),
        sentinel.display()
    );
    let made = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .status()
        .unwrap();
    assert!(made.success());
    for args in [
        vec![
            "+s".to_string(),
            "+h".into(),
            shortcut.join("desktop.ini").display().to_string(),
        ],
        vec!["+r".to_string(), shortcut.display().to_string()],
    ] {
        assert!(
            std::process::Command::new("attrib")
                .args(&args)
                .status()
                .unwrap()
                .success()
        );
    }
    let through = WinPath::parse(&format!("{}\\keep.txt", real(&shortcut))).unwrap();
    assert!(
        !shell_sees_exactly(&through),
        "a folder shortcut must not pass"
    );
    assert_eq!(fs::read(sentinel.join("keep.txt")).unwrap(), b"keep");
    // Let the temp cleanup remove it.
    std::process::Command::new("attrib")
        .args(["-r", &shortcut.display().to_string()])
        .status()
        .unwrap();
}
