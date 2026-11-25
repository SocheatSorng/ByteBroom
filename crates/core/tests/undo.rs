//! Phase 5, tasks 1-3: putting moves back from the journal, and the history files, on fake trees
//! in a fresh temp folder only. Never the owner's real files, journal or Recycle Bin.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::history::{
    ALREADY_PUT_BACK, ELEVATED_REFUSAL, HISTORY_FILES, RecycledJournal, RecycledRecord, UndoResult,
    clear_history, move_history, refuse_if_elevated, undo_entries, undo_policy,
};
use bytebroom_core::locations::Locations;
use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::Policy;
use bytebroom_core::relocate::{COPY_KEPT, JournalEntry, JournalLine, move_to, undo_move};
use bytebroom_core::win::dir::lock_dir;
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::*;
use std::fs;
use std::path::{Path, PathBuf};

fn wp(path: &Path) -> WinPath {
    WinPath::parse(path.to_str().unwrap()).unwrap()
}

fn policy_for(dir: &Path) -> Policy {
    let root = open_no_follow(&wp(dir), Access::Inspect).unwrap();
    Policy::new(vec![root.resolved], system_layout()).unwrap()
}

struct Setup {
    tree: FakeTree,
    pol: Policy,
    dest: PathBuf,
    app: PathBuf,
}

fn setup() -> Setup {
    let tree = FakeTree::new();
    let pol = policy_for(&tree.root);
    let dest = tree.base.join("dest");
    fs::create_dir(&dest).unwrap();
    let app = tree.base.join("app");
    fs::create_dir(&app).unwrap();
    Setup {
        tree,
        pol,
        dest,
        app,
    }
}

impl Setup {
    fn journal(&self) -> bytebroom_core::relocate::Journal {
        journal_at(&self.app.join("moves.journal"))
    }

    fn move_it(&self, item: &Path) -> Vec<JournalEntry> {
        let journal = self.journal();
        let out = move_to(&self.pol, &[wp(item)], &wp(&self.dest), &journal);
        assert!(out.skipped.is_empty(), "{:?}", out.skipped);
        journal.entries().unwrap()
    }

    fn undo(&self, wanted: &[JournalEntry]) -> Vec<UndoResult> {
        let pol = self.pol.clone();
        undo_entries(
            false,
            &self.journal(),
            wanted,
            &|_| Ok(pol.clone()),
            &undo_move,
        )
    }
}

#[test]
fn putting_back_records_it_and_a_second_try_says_already_put_back() {
    let s = setup();
    let source = s.tree.root.join("junk").join("a.tmp");
    let entries = s.move_it(&source);
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].clean.is_some(),
        "phase 5 moves carry their clean"
    );

    assert_eq!(s.undo(&entries), vec![UndoResult::PutBack]);
    assert_eq!(fs::read(&source).unwrap(), vec![1u8; 1000]);
    assert!(!s.dest.join("a.tmp").exists());
    let history = move_history(&s.journal().lines().unwrap());
    assert!(history[0].undone.is_some());

    assert_eq!(
        s.undo(&entries),
        vec![UndoResult::Refused(ALREADY_PUT_BACK.into())]
    );
    assert_eq!(fs::read(&source).unwrap(), vec![1u8; 1000], "still there");
}

#[test]
fn a_move_that_is_not_in_the_journal_is_refused_and_nothing_changes() {
    let s = setup();
    let source = s.tree.root.join("junk").join("a.tmp");
    let mut forged = s.move_it(&source).remove(0);
    forged.size += 1;
    let before = fs::read(s.app.join("moves.journal")).unwrap();
    assert_eq!(
        s.undo(&[forged]),
        vec![UndoResult::Refused("it is no longer in the history".into())]
    );
    assert!(!source.exists());
    assert!(s.dest.join("a.tmp").exists());
    assert_eq!(fs::read(s.app.join("moves.journal")).unwrap(), before);
}

#[test]
fn a_failed_undo_writes_no_put_back_line() {
    let s = setup();
    let entries = s.move_it(&s.tree.root.join("junk").join("a.tmp"));
    let pol = s.pol.clone();
    let got = undo_entries(
        false,
        &s.journal(),
        &entries,
        &|_| Ok(pol.clone()),
        &|_, _| Err("broke".into()),
    );
    assert_eq!(got, vec![UndoResult::Refused("broke".into())]);
    let lines = s.journal().lines().unwrap();
    assert!(lines.iter().all(|l| matches!(l, JournalLine::Move(_))));
    // And a refused policy stops it before anything is tried.
    let got = undo_entries(
        false,
        &s.journal(),
        &entries,
        &|_| Err("not here".into()),
        &|_, _| panic!("must not run"),
    );
    assert_eq!(got, vec![UndoResult::Refused("not here".into())]);
}

#[test]
fn a_moved_folders_files_go_back_into_the_folder_made_again() {
    let s = setup();
    let deep = s.tree.root.join("junk").join("deep");
    let entries = s.move_it(&deep);
    assert!(!deep.exists());
    assert_eq!(entries.len(), 1);

    assert_eq!(s.undo(&entries), vec![UndoResult::PutBack]);
    assert_eq!(fs::read(deep.join("c.tmp")).unwrap(), vec![3u8; 3000]);
    assert_eq!(powershell_sha256(&deep.join("c.tmp")), entries[0].sha256);
}

#[test]
fn a_failed_undo_removes_the_folders_it_made() {
    let s = setup();
    let deep = s.tree.root.join("junk").join("deep");
    let entries = s.move_it(&deep);
    fs::write(s.dest.join("deep").join("c.tmp"), b"edited after the move").unwrap();

    let got = s.undo(&entries);
    assert!(matches!(&got[0], UndoResult::Refused(_)), "{got:?}");
    assert!(!deep.exists(), "the folder it made again is removed");
    assert!(
        s.dest.join("deep").join("c.tmp").exists(),
        "the moved file stays"
    );
}

#[test]
fn folders_are_never_made_again_outside_the_allowed_roots() {
    let s = setup();
    let entries = s.move_it(&s.tree.root.join("junk").join("a.tmp"));
    let forged = JournalEntry {
        source: wp(&s.tree.sentinel.join("new").join("a.tmp")),
        ..entries[0].clone()
    };
    let before = snapshot(&s.tree.sentinel, "before", &s.tree.base);
    assert!(undo_move(&s.pol, &forged).is_err());
    assert!(!s.tree.sentinel.join("new").exists());
    assert!(s.dest.join("a.tmp").exists());
    let after = snapshot(&s.tree.sentinel, "after", &s.tree.base);
    assert_unchanged(&before, &after);
}

#[test]
fn the_undo_policy_is_the_nearest_real_folder_inside_a_scanned_place() {
    let s = setup();
    let at = Locations {
        downloads: Some(wp(&s.tree.root)),
        ..Locations::default()
    };
    let layout = system_layout();
    let entry = |source: &Path| JournalEntry {
        clean: Some(1),
        time: 1,
        sha256: "0F".repeat(32),
        size: 1,
        source: wp(source),
        dest: wp(&s.dest.join("x")),
    };
    let roots = |p: &Path| {
        undo_policy(&at, &layout, &entry(p)).map(|pol| {
            pol.roots()
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
        })
    };
    let junk = s.tree.root.join("junk");
    assert_eq!(
        roots(&junk.join("a.tmp")).unwrap(),
        vec![wp(&junk).to_string()]
    );
    // A missing folder: the nearest one above that exists.
    assert_eq!(
        roots(&junk.join("gone").join("deeper").join("a.tmp")).unwrap(),
        vec![wp(&junk).to_string()]
    );
    // Outside every scanned place, or through a link: refused.
    assert!(roots(&s.tree.sentinel.join("a.tmp")).is_err());
    assert!(roots(&s.tree.root.join("link").join("keep.txt")).is_err());
    assert!(roots(&s.tree.root.join("link").join("gone").join("x")).is_err());
}

#[test]
fn clearing_the_history_removes_both_journals_and_nothing_else() {
    let s = setup();
    let source = s.tree.root.join("junk").join("a.tmp");
    s.move_it(&source);
    let held = lock_dir(&wp(&s.app)).unwrap();
    RecycledJournal::open(&held)
        .unwrap()
        .append(&[RecycledRecord {
            clean: 1,
            time: 1,
            size: 1,
            original: wp(&source),
            in_bin: WinPath::parse("C:\\$Recycle.Bin\\S-1\\$R1.tmp").unwrap(),
        }])
        .unwrap();
    write_file(&s.app.join("bytebroom.log"), b"counts only");

    clear_history(false, &held).unwrap();
    for name in HISTORY_FILES {
        assert!(!s.app.join(name).exists(), "{name}");
    }
    assert!(s.app.join("bytebroom.log").exists());
    assert!(
        s.dest.join("a.tmp").exists(),
        "clearing never touches the files"
    );
    // Clearing again, with nothing there, is fine.
    clear_history(false, &held).unwrap();
}

#[test]
fn clearing_refuses_a_journal_that_is_a_hard_link_and_keeps_its_target() {
    let s = setup();
    fs::hard_link(
        s.tree.sentinel.join("keep.txt"),
        s.app.join("moves.journal"),
    )
    .unwrap();
    let held = lock_dir(&wp(&s.app)).unwrap();
    assert!(clear_history(false, &held).is_err());
    assert_eq!(
        fs::read(s.tree.sentinel.join("keep.txt")).unwrap(),
        b"the sentinel must survive"
    );
}

#[test]
fn the_recycled_journal_reads_back_what_was_written() {
    let s = setup();
    let held = lock_dir(&wp(&s.app)).unwrap();
    let j = RecycledJournal::open(&held).unwrap();
    let r = RecycledRecord {
        clean: 3,
        time: 9,
        size: 1000,
        original: wp(&s.tree.root.join("junk").join("a.tmp")),
        in_bin: WinPath::parse("C:\\$Recycle.Bin\\S-1\\$R1.tmp").unwrap(),
    };
    j.append(std::slice::from_ref(&r)).unwrap();
    j.append(&[]).unwrap();
    assert_eq!(j.records().unwrap(), vec![r]);
}

/// Security review, phase 5, S1: run as administrator, nothing is put back or cleared, and the
/// journals are left exactly as they were.
#[test]
fn nothing_is_put_back_or_cleared_when_elevated() {
    let s = setup();
    let source = s.tree.root.join("junk").join("a.tmp");
    let entries = s.move_it(&source);
    let before = fs::read(s.app.join("moves.journal")).unwrap();
    let got = undo_entries(
        true,
        &s.journal(),
        &entries,
        &|_| panic!("no policy when elevated"),
        &|_, _| panic!("no undo when elevated"),
    );
    assert_eq!(got, vec![UndoResult::Refused(ELEVATED_REFUSAL.into())]);
    assert!(!source.exists());
    let held = lock_dir(&wp(&s.app)).unwrap();
    assert_eq!(clear_history(true, &held), Err(ELEVATED_REFUSAL.into()));
    assert_eq!(fs::read(s.app.join("moves.journal")).unwrap(), before);
    assert_eq!(refuse_if_elevated(false), Ok(()));
}

/// Security review, phase 5, S3: the file is back and checked but the moved copy stayed; that is
/// recorded as put back, never reported as "nothing changed".
#[test]
fn a_kept_moved_copy_is_reported_and_recorded() {
    let s = setup();
    let entries = s.move_it(&s.tree.root.join("junk").join("a.tmp"));
    let pol = s.pol.clone();
    let got = undo_entries(
        false,
        &s.journal(),
        &entries,
        &|_| Ok(pol.clone()),
        &|_, _| Err(format!("{COPY_KEPT} (in use)")),
    );
    assert!(
        matches!(&got[0], UndoResult::PutBackCopyKept(w) if w.contains("in use")),
        "{got:?}"
    );
    let history = move_history(&s.journal().lines().unwrap());
    assert!(history[0].undone.is_some());
}

/// Security review, phase 5, S4: a junction planted on the way to the original folder is never
/// followed: nothing is restored or made in the folder it points to.
#[test]
fn a_junction_on_the_way_to_the_original_folder_is_refused() {
    let s = setup();
    let entries = s.move_it(&s.tree.root.join("junk").join("a.tmp"));
    let b = s.tree.root.join("b");
    fs::create_dir(&b).unwrap();
    make_junction(&s.tree.root.join("a"), &b);
    for source in [
        s.tree.root.join("a").join("a.tmp"),
        s.tree.root.join("a").join("missing").join("a.tmp"),
    ] {
        let forged = JournalEntry {
            source: wp(&source),
            ..entries[0].clone()
        };
        assert!(undo_move(&s.pol, &forged).is_err(), "{source:?}");
        assert_eq!(
            fs::read_dir(&b).unwrap().count(),
            0,
            "nothing lands in the target"
        );
    }
    assert!(s.dest.join("a.tmp").exists());
    fs::remove_dir(s.tree.root.join("a")).unwrap();
}

/// Security review, phase 5, note 5: even inside the profile, a forged line can't put a file into
/// the startup folder, the WindowsApps folder on the PATH, or ByteBroom's own folder.
#[test]
fn the_undo_policy_refuses_startup_path_and_bytebroom_folders() {
    let s = setup();
    let profile = s.tree.root.clone();
    let at = Locations {
        profile: Some(wp(&profile)),
        local_app_data: Some(wp(&profile.join("AppData").join("Local"))),
        ..Locations::default()
    };
    for source in [
        r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe",
        r"AppData\Local\Microsoft\WindowsApps\x.exe",
        r"AppData\Local\ByteBroom\moves.journal",
    ] {
        let entry = JournalEntry {
            clean: Some(1),
            time: 1,
            sha256: "0F".repeat(32),
            size: 1,
            source: wp(&profile.join(source)),
            dest: wp(&s.dest.join("x")),
        };
        let err = undo_policy(&at, &system_layout(), &entry).unwrap_err();
        assert!(err.contains("never puts files back"), "{source}: {err}");
    }
}

/// Security review, phase 5, note 7: a junction named like a journal is refused by clear, and
/// what it points to survives.
#[test]
fn clearing_refuses_a_journal_that_is_a_junction() {
    let s = setup();
    make_junction(&s.app.join("moves.journal"), &s.tree.sentinel);
    let held = lock_dir(&wp(&s.app)).unwrap();
    assert!(clear_history(false, &held).is_err());
    assert_eq!(
        fs::read(s.tree.sentinel.join("keep.txt")).unwrap(),
        b"the sentinel must survive"
    );
    drop(held);
    fs::remove_dir(s.app.join("moves.journal")).unwrap();
}
