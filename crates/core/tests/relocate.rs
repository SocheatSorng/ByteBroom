//! Task 7: moving with verify and journal, on fake trees. The destination is another temp
//! folder; a second drive is used only on CI (RUNNER_TEMP), never on the owner's real drives.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::engine::SkipReason;
use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::{Policy, Refusal};
use bytebroom_core::relocate::{move_to, read_journal, undo_move};
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::*;
use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

fn wp(path: &Path) -> WinPath {
    WinPath::parse(path.to_str().unwrap()).unwrap()
}

fn policy_for(tree: &FakeTree) -> Policy {
    let root = open_no_follow(&wp(&tree.root), Access::Inspect).unwrap();
    Policy::new(vec![root.resolved], system_layout()).unwrap()
}

struct Setup {
    tree: FakeTree,
    pol: Policy,
    dest: PathBuf,
    journal: PathBuf,
}

fn setup() -> Setup {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let dest = tree.base.join("dest");
    fs::create_dir(&dest).unwrap();
    let journal = tree.base.join("journal").join("moves.log");
    Setup {
        tree,
        pol,
        dest,
        journal,
    }
}

#[test]
fn moves_a_file_and_the_journal_hash_matches_powershell() {
    let s = setup();
    let source = s.tree.root.join("junk").join("a.tmp");
    let before = snapshot(&s.tree.sentinel, "before", &s.tree.base);

    let out = move_to(
        &s.pol,
        &[wp(&source)],
        &wp(&s.dest),
        &journal_at(&s.journal),
    );

    assert!(out.skipped.is_empty(), "{:?}", out.skipped);
    assert!(!source.exists());
    assert_eq!(fs::read(s.dest.join("a.tmp")).unwrap(), vec![1u8; 1000]);
    assert_eq!(out.bytes_moved, 1000);
    assert_eq!(out.bytes_freed, 0, "same drive: moving frees nothing");
    let entries = read_journal(&s.journal).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].size, 1000);
    assert_eq!(entries[0].sha256, powershell_sha256(&s.dest.join("a.tmp")));
    assert!(entries[0].source.to_string().ends_with("junk\\a.tmp"));
    let after = snapshot(&s.tree.sentinel, "after", &s.tree.base);
    assert_unchanged(&before, &after);
}

#[test]
fn never_overwrites_a_file_already_in_the_destination() {
    let s = setup();
    write_file(&s.dest.join("a.tmp"), b"already here");
    let out = move_to(
        &s.pol,
        &[wp(&s.tree.root.join("junk").join("a.tmp"))],
        &wp(&s.dest),
        &journal_at(&s.journal),
    );
    assert!(out.skipped.is_empty(), "{:?}", out.skipped);
    assert_eq!(fs::read(s.dest.join("a.tmp")).unwrap(), b"already here");
    assert_eq!(fs::read(s.dest.join("a (2).tmp")).unwrap(), vec![1u8; 1000]);
}

#[test]
fn moves_a_folder_with_its_structure() {
    let s = setup();
    let out = move_to(
        &s.pol,
        &[wp(&s.tree.root.join("junk"))],
        &wp(&s.dest),
        &journal_at(&s.journal),
    );
    assert!(out.skipped.is_empty(), "{:?}", out.skipped);
    assert!(!s.tree.root.join("junk").exists());
    assert_eq!(
        fs::read(s.dest.join("junk").join("b.tmp")).unwrap(),
        vec![2u8; 2000]
    );
    assert_eq!(
        fs::read(s.dest.join("junk").join("deep").join("c.tmp")).unwrap(),
        vec![3u8; 3000]
    );
    assert_eq!(out.bytes_moved, 6000);
    assert_eq!(read_journal(&s.journal).unwrap().len(), 3);
}

#[test]
fn a_locked_file_stays_and_the_rest_moves() {
    let s = setup();
    let mixed = s.tree.root.join("mixed");
    write_file(&mixed.join("x.tmp"), &[9u8; 100]);
    write_file(&mixed.join("held.tmp"), b"busy");
    let held = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(mixed.join("held.tmp"))
        .unwrap();
    let out = move_to(&s.pol, &[wp(&mixed)], &wp(&s.dest), &journal_at(&s.journal));
    drop(held);
    assert!(!mixed.join("x.tmp").exists());
    assert!(mixed.join("held.tmp").exists());
    assert_eq!(
        fs::read(s.dest.join("mixed").join("x.tmp")).unwrap(),
        vec![9u8; 100]
    );
    let reasons: Vec<_> = out.skipped.iter().map(|s| s.reason.clone()).collect();
    assert_eq!(reasons, vec![SkipReason::InUse, SkipReason::NotEmpty]);
}

#[test]
fn links_and_outside_paths_are_refused_and_the_sentinel_is_untouched() {
    let s = setup();
    let before = snapshot(&s.tree.sentinel, "before", &s.tree.base);
    let out = move_to(
        &s.pol,
        &[
            wp(&s.tree.root.join("link")),
            wp(&s.tree.root.join("link").join("keep.txt")),
        ],
        &wp(&s.dest),
        &journal_at(&s.journal),
    );
    assert!(out.removed.is_empty());
    let reasons: Vec<_> = out.skipped.iter().map(|s| s.reason.clone()).collect();
    assert_eq!(
        reasons,
        vec![
            SkipReason::Refused(Refusal::ReparsePoint),
            SkipReason::Refused(Refusal::OutsideAllowedRoots),
        ]
    );
    assert!(
        fs::read_dir(&s.dest).unwrap().next().is_none(),
        "nothing was copied"
    );
    let after = snapshot(&s.tree.sentinel, "after", &s.tree.base);
    assert_unchanged(&before, &after);
}

#[test]
fn bad_destinations_are_refused_before_anything_happens() {
    let s = setup();
    let target = wp(&s.tree.root.join("junk"));
    let windows = WinPath::parse(&std::env::var("SystemRoot").unwrap()).unwrap();
    make_junction(&s.tree.base.join("dest-link"), &s.dest);
    for dest in [
        windows,
        wp(&s.tree.base.join("dest-link")),
        wp(&s.tree.root.join("junk").join("deep")),
        wp(&s.tree.base.join("missing")),
    ] {
        let out = move_to(
            &s.pol,
            std::slice::from_ref(&target),
            &dest,
            &journal_at(&s.journal),
        );
        assert!(out.removed.is_empty(), "moved into {dest}");
        assert!(
            matches!(out.skipped[0].reason, SkipReason::Unsupported(_)),
            "{dest}: {:?}",
            out.skipped
        );
    }
    let _ = fs::remove_dir(s.tree.base.join("dest-link"));
    assert!(s.tree.root.join("junk").join("a.tmp").exists());
}

#[test]
fn undo_puts_the_file_back_and_removes_the_moved_copy() {
    let s = setup();
    let source = s.tree.root.join("junk").join("b.tmp");
    move_to(
        &s.pol,
        &[wp(&source)],
        &wp(&s.dest),
        &journal_at(&s.journal),
    );
    let entry = read_journal(&s.journal).unwrap().remove(0);

    undo_move(&s.pol, &entry).unwrap();

    assert_eq!(fs::read(&source).unwrap(), vec![2u8; 2000]);
    assert!(!s.dest.join("b.tmp").exists());
    assert_eq!(powershell_sha256(&source), entry.sha256);
}

#[test]
fn undo_refuses_when_the_moved_file_changed_or_the_place_is_taken() {
    let s = setup();
    let source = s.tree.root.join("junk").join("b.tmp");
    move_to(
        &s.pol,
        &[wp(&source)],
        &wp(&s.dest),
        &journal_at(&s.journal),
    );
    let entry = read_journal(&s.journal).unwrap().remove(0);

    write_file(&source, b"new file in the old place");
    assert!(undo_move(&s.pol, &entry).is_err());
    fs::remove_file(&source).unwrap();

    fs::write(s.dest.join("b.tmp"), b"edited after the move").unwrap();
    assert!(undo_move(&s.pol, &entry).is_err());
    assert!(!source.exists(), "a changed file must not be restored");
    assert!(s.dest.join("b.tmp").exists(), "the moved file must be kept");
}

#[test]
fn moving_to_another_drive_frees_the_space() {
    // CI only: RUNNER_TEMP is on another drive there. Never the owner's real drives.
    let Ok(other) = std::env::var("RUNNER_TEMP") else {
        return;
    };
    let s = setup();
    let other_dir = PathBuf::from(other).join(format!(
        "bytebroom-move-{}",
        s.tree.base.file_name().unwrap().to_string_lossy()
    ));
    fs::create_dir_all(&other_dir).unwrap();
    let dest = wp(&other_dir);
    if dest.drive() == wp(&s.tree.root).drive() {
        let _ = fs::remove_dir_all(&other_dir);
        return;
    }
    let out = move_to(
        &s.pol,
        &[wp(&s.tree.root.join("junk").join("a.tmp"))],
        &dest,
        &journal_at(&s.journal),
    );
    assert!(out.skipped.is_empty(), "{:?}", out.skipped);
    assert_eq!(out.bytes_freed, 1000);
    assert_eq!(
        powershell_sha256(&other_dir.join("a.tmp")),
        read_journal(&s.journal).unwrap()[0].sha256
    );
    let _ = fs::remove_dir_all(&other_dir);
}

#[test]
fn a_file_open_for_writing_is_not_moved() {
    // Security review should-fix 5: bytes written after the copy would be lost.
    let s = setup();
    let source = s.tree.root.join("junk").join("a.tmp");
    let writer = OpenOptions::new()
        .write(true)
        .share_mode(7) // read | write | delete: only the write access matters here
        .open(&source)
        .unwrap();
    let out = move_to(
        &s.pol,
        &[wp(&source)],
        &wp(&s.dest),
        &journal_at(&s.journal),
    );
    drop(writer);
    assert_eq!(out.skipped[0].reason, SkipReason::InUse);
    assert!(source.exists());
    assert!(
        fs::read_dir(&s.dest).unwrap().next().is_none(),
        "nothing may be copied"
    );
}
