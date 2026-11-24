//! Tests of the test fixture and the independent PowerShell checker themselves: a checker that
//! can't see a change would make every safety test pass for the wrong reason.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use std::fs;

#[test]
fn fixture_lives_only_in_temp_and_has_every_hazard() {
    let tree = FakeTree::new();
    assert!(tree.base.starts_with(tests_base()));
    let link_meta = fs::symlink_metadata(tree.root.join("link")).unwrap();
    assert!(link_meta.file_type().is_symlink() || link_meta.is_dir());
    assert!(
        fs::read_link(tree.root.join("link")).is_ok(),
        "junction missing"
    );
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(tree.root.join("locked.tmp"))
            .is_err(),
        "locked.tmp is not held open"
    );
    assert_eq!(
        fs::read(tree.root.join("shared.bin")).unwrap(),
        vec![7u8; 4096]
    );
}

#[test]
fn checker_reports_identical_trees_as_identical() {
    let tree = FakeTree::new();
    let a = snapshot(&tree.sentinel, "a", &tree.base);
    let b = snapshot(&tree.sentinel, "b", &tree.base);
    assert_unchanged(&a, &b);
}

#[test]
fn checker_sees_one_changed_byte_an_added_file_and_a_removed_file() {
    let tree = FakeTree::new();
    let before = snapshot(&tree.root, "before", &tree.base);

    let mut bytes = fs::read(tree.root.join("junk").join("a.tmp")).unwrap();
    bytes[500] ^= 1;
    fs::write(tree.root.join("junk").join("a.tmp"), bytes).unwrap();
    fs::write(tree.root.join("junk").join("new.tmp"), b"x").unwrap();
    fs::remove_file(tree.root.join("junk").join("deep").join("c.tmp")).unwrap();

    let after = snapshot(&tree.root, "after", &tree.base);
    let (code, text) = verify_tree(&[
        "-Compare",
        "-Before",
        before.to_str().unwrap(),
        "-After",
        after.to_str().unwrap(),
    ]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("changed: junk\\a.tmp"), "{text}");
    assert!(text.contains("added: junk\\new.tmp"), "{text}");
    assert!(text.contains("removed: junk\\deep\\c.tmp"), "{text}");
}

#[test]
fn checker_does_not_walk_into_the_junction() {
    let tree = FakeTree::new();
    let snap = snapshot(&tree.root, "root", &tree.base);
    let json = fs::read_to_string(snap).unwrap();
    assert!(json.contains("\"link\""), "{json}");
    assert!(
        !json.contains("keep.txt"),
        "the checker followed the junction: {json}"
    );
}
