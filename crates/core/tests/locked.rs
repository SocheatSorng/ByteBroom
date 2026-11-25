//! Security review must-fix 1 and 2: nothing is created, written or removed by path after a
//! check. Held folders can't be swapped, new files are created inside held handles (never
//! following or overwriting anything), and undo only restores into the allowed roots.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::Policy;
use bytebroom_core::relocate::{JournalEntry, move_to, read_journal, undo_move};
use bytebroom_core::win::dir::{CreateError, lock_dir};
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::*;
use std::fs::{self, OpenOptions};
use std::path::Path;

fn wp(path: &Path) -> WinPath {
    WinPath::parse(path.to_str().unwrap()).unwrap()
}

fn policy_for(tree: &FakeTree) -> Policy {
    let root = open_no_follow(&wp(&tree.root), Access::Inspect).unwrap();
    Policy::new(vec![root.resolved], system_layout()).unwrap()
}

#[test]
fn a_held_folder_cannot_be_renamed_until_released() {
    let tree = FakeTree::new();
    let dest = tree.base.join("dest");
    fs::create_dir(&dest).unwrap();
    let held = lock_dir(&wp(&dest)).unwrap();
    assert!(
        fs::rename(&dest, tree.base.join("dest-moved")).is_err(),
        "a held folder was renamed away"
    );
    drop(held);
    fs::rename(&dest, tree.base.join("dest-moved")).unwrap();
}

#[test]
fn a_junction_cannot_be_held_as_a_folder() {
    let tree = FakeTree::new();
    assert!(lock_dir(&wp(&tree.root.join("link"))).is_err());
}

#[test]
fn a_link_planted_under_the_target_name_is_never_followed() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let dest = tree.base.join("dest");
    fs::create_dir(&dest).unwrap();
    // The attacker pre-plants "a.tmp" in the destination as a junction to the sentinel.
    make_junction(&dest.join("a.tmp"), &tree.sentinel);
    let before = snapshot(&tree.sentinel, "before", &tree.base);

    let out = move_to(
        &pol,
        &[wp(&tree.root.join("junk").join("a.tmp"))],
        &wp(&dest),
        &journal_at(&tree.base.join("journal.log")),
    );

    assert!(out.skipped.is_empty(), "{:?}", out.skipped);
    assert_eq!(fs::read(dest.join("a (2).tmp")).unwrap(), vec![1u8; 1000]);
    assert!(
        fs::read_link(dest.join("a.tmp")).is_ok(),
        "the planted link was replaced"
    );
    let after = snapshot(&tree.sentinel, "after", &tree.base);
    assert_unchanged(&before, &after);
    let _ = fs::remove_dir(dest.join("a.tmp"));
}

#[test]
fn create_file_never_overwrites_and_nobody_else_can_write_the_new_file() {
    let tree = FakeTree::new();
    let held = lock_dir(&wp(&tree.root.join("junk"))).unwrap();
    assert!(matches!(
        held.create_file("a.tmp"),
        Err(CreateError::Exists)
    ));
    assert_eq!(
        fs::read(tree.root.join("junk").join("a.tmp")).unwrap(),
        vec![1u8; 1000]
    );
    assert!(matches!(
        held.create_file(".."),
        Err(CreateError::BadName(_))
    ));
    assert!(matches!(
        held.create_file("x\\y"),
        Err(CreateError::BadName(_))
    ));
    assert!(matches!(
        held.create_file("x:stream"),
        Err(CreateError::BadName(_))
    ));

    let created = held.create_file("new.tmp").unwrap();
    assert!(
        OpenOptions::new()
            .write(true)
            .open(tree.root.join("junk").join("new.tmp"))
            .is_err(),
        "another writer could open ByteBroom's new file"
    );
    created.delete().unwrap();
    drop(held);
    assert!(!tree.root.join("junk").join("new.tmp").exists());
}

#[test]
fn undo_refuses_a_forged_journal_line_pointing_outside_the_roots() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let dest = tree.base.join("dest");
    fs::create_dir(&dest).unwrap();
    let journal = tree.base.join("journal.log");
    move_to(
        &pol,
        &[wp(&tree.root.join("junk").join("a.tmp"))],
        &wp(&dest),
        &journal_at(&journal),
    );
    let honest = read_journal(&journal).unwrap().remove(0);
    // A forged line: same moved file, but "restore" it into the sentinel (outside the roots).
    let forged = JournalEntry {
        source: wp(&tree.sentinel.join("planted.dll")),
        ..honest.clone()
    };
    let before = snapshot(&tree.sentinel, "before", &tree.base);
    let err = undo_move(&pol, &forged).unwrap_err();
    assert!(err.contains("outside"), "{err}");
    let after = snapshot(&tree.sentinel, "after", &tree.base);
    assert_unchanged(&before, &after);
    assert!(dest.join("a.tmp").exists(), "the moved file must stay");
}

#[test]
fn undo_refuses_an_original_folder_that_is_a_junction() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let dest = tree.base.join("dest");
    fs::create_dir(&dest).unwrap();
    let journal = tree.base.join("journal.log");
    move_to(
        &pol,
        &[wp(&tree.root.join("junk").join("a.tmp"))],
        &wp(&dest),
        &journal_at(&journal),
    );
    let honest = read_journal(&journal).unwrap().remove(0);
    // The original's folder path now goes through the junction to the sentinel.
    let swapped = JournalEntry {
        source: wp(&tree.root.join("link").join("a.tmp")),
        ..honest
    };
    let before = snapshot(&tree.sentinel, "before", &tree.base);
    assert!(undo_move(&pol, &swapped).is_err());
    let after = snapshot(&tree.sentinel, "after", &tree.base);
    assert_unchanged(&before, &after);
}
