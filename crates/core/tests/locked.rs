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

/// Security review S3: a forged line whose "moved file" is a protected file with the same
/// contents. Undo must not copy it into the cleaned folder nor delete it.
#[test]
fn undo_refuses_a_forged_moved_file_in_a_protected_area() {
    let tree = FakeTree::new();
    let dest = tree.base.join("dest");
    fs::create_dir(&dest).unwrap();
    let journal = tree.base.join("journal.log");
    let pol = policy_for(&tree);
    move_to(
        &pol,
        &[wp(&tree.root.join("junk").join("a.tmp"))],
        &wp(&dest),
        &journal_at(&journal),
    );
    let honest = read_journal(&journal).unwrap().remove(0);
    // A "protected" file with exactly the moved file's contents, in the sentinel, which this
    // layout marks as a protected area.
    let protected = tree.sentinel.join("system.dll");
    fs::copy(dest.join("a.tmp"), &protected).unwrap();
    let real_root = open_no_follow(&wp(&tree.root), Access::Inspect)
        .unwrap()
        .resolved;
    let real_sentinel = open_no_follow(&wp(&tree.sentinel), Access::Inspect)
        .unwrap()
        .resolved
        .final_path;
    let mut layout = system_layout();
    layout.extra_denied.push(real_sentinel.clone());
    let guarded = Policy::new(vec![real_root], layout).unwrap();
    let forged = JournalEntry {
        dest: real_sentinel.join("system.dll").unwrap(),
        ..honest
    };
    let err = undo_move(&guarded, &forged).unwrap_err();
    assert!(err.contains("protected"), "{err}");
    assert!(protected.exists(), "the protected file must stay");
    assert!(
        !tree.root.join("junk").join("a.tmp").exists(),
        "nothing copied back"
    );
}

/// Security review S3: a line whose "moved file" path differs from where the file really is
/// (here: reached through a junction) is refused.
#[test]
fn undo_refuses_a_moved_file_reached_through_a_link() {
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
    let via = tree.base.join("via");
    make_junction(&via, &dest);
    let forged = JournalEntry {
        dest: wp(&via.join("a.tmp")),
        ..honest
    };
    let err = undo_move(&pol, &forged).unwrap_err();
    assert!(err.contains("not where the journal says"), "{err}");
    assert!(dest.join("a.tmp").exists());
    fs::remove_dir(&via).unwrap();
}

/// Security review S3, the rule: the journal is user-writable, so only the unelevated undo in
/// `relocate.rs` (which re-checks both ends) may read it. Elevated code (the phase 4 helper)
/// never does. This sweep fails if any other source file starts reading it.
#[test]
fn only_the_move_module_reads_the_journal() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let mut readers = Vec::new();
    let mut stack = vec![repo.join("crates"), repo.join("src-tauri").join("src")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                if !p.ends_with("tests") && !p.ends_with("target") {
                    stack.push(p);
                }
            } else if p.extension().is_some_and(|e| e == "rs") {
                let text = fs::read_to_string(&p).unwrap();
                // Any mention counts (an import alias still names the item), and undo too:
                // it restores bytes into the cleaned folders, so it must stay unelevated and
                // in the move module (re-review R2). A tripwire, not a proof.
                if [
                    "read_journal",
                    ".entries()",
                    "undo_move",
                    "JournalEntry::parse",
                ]
                .iter()
                .any(|name| text.contains(name))
                {
                    readers.push(p.file_name().unwrap().to_string_lossy().into_owned());
                }
            }
        }
    }
    readers.sort();
    assert_eq!(readers, vec!["relocate.rs".to_string()], "{readers:?}");
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
