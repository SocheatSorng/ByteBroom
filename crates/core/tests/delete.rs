//! Task 5: permanent delete through the checked handle, on the fake tree. After every test the
//! sentinel folder outside the root must be unchanged according to the PowerShell checker.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::engine::{SkipReason, delete_permanently};
use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::{Policy, Refusal};
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::*;
use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

fn wp(path: &Path) -> WinPath {
    WinPath::parse(path.to_str().unwrap()).unwrap()
}

fn policy_for(tree: &FakeTree) -> Policy {
    let root = open_no_follow(&wp(&tree.root), Access::Inspect).unwrap();
    Policy::new(vec![root.resolved], system_layout()).unwrap()
}

/// Run `f`, then prove with verify-tree.ps1 that the sentinel did not change.
fn with_sentinel_guard(tree: &FakeTree, f: impl FnOnce()) {
    let before = snapshot(&tree.sentinel, "sentinel-before", &tree.base);
    f();
    let after = snapshot(&tree.sentinel, "sentinel-after", &tree.base);
    assert_unchanged(&before, &after);
}

#[test]
fn deletes_a_folder_bottom_up_and_counts_the_bytes() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    with_sentinel_guard(&tree, || {
        let out = delete_permanently(&pol, &[wp(&tree.root.join("junk"))]);
        assert!(out.skipped.is_empty(), "{:?}", out.skipped);
        assert_eq!(out.bytes_freed, 1000 + 2000 + 3000);
        assert_eq!(
            out.removed.len(),
            5,
            "3 files + deep + junk: {:?}",
            out.removed
        );
        assert!(!tree.root.join("junk").exists());
    });
}

#[test]
fn never_deletes_or_enters_the_junction() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    with_sentinel_guard(&tree, || {
        let out = delete_permanently(&pol, &[wp(&tree.root.join("link"))]);
        assert!(out.removed.is_empty());
        assert_eq!(
            out.skipped[0].reason,
            SkipReason::Refused(Refusal::ReparsePoint)
        );
        assert!(
            fs::read_link(tree.root.join("link")).is_ok(),
            "the junction was removed"
        );
    });
}

#[test]
fn a_path_through_the_junction_is_refused() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    with_sentinel_guard(&tree, || {
        let out = delete_permanently(&pol, &[wp(&tree.root.join("link").join("keep.txt"))]);
        assert!(out.removed.is_empty());
        assert_eq!(
            out.skipped[0].reason,
            SkipReason::Refused(Refusal::OutsideAllowedRoots)
        );
    });
}

#[test]
fn refuses_the_root_itself_and_anything_outside_it() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    with_sentinel_guard(&tree, || {
        let out = delete_permanently(
            &pol,
            &[
                wp(&tree.root),
                wp(&tree.sentinel),
                wp(&tree.sentinel.join("keep.txt")),
            ],
        );
        assert!(out.removed.is_empty());
        assert_eq!(out.skipped.len(), 3);
        assert!(
            out.skipped
                .iter()
                .all(|s| s.reason == SkipReason::Refused(Refusal::OutsideAllowedRoots))
        );
        assert!(tree.root.join("junk").join("a.tmp").exists());
    });
}

#[test]
fn cleaning_the_whole_root_keeps_the_locked_file_the_link_and_frees_no_hard_link_bytes() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    with_sentinel_guard(&tree, || {
        let targets: Vec<WinPath> = fs::read_dir(&tree.root)
            .unwrap()
            .map(|e| wp(&e.unwrap().path()))
            .collect();
        let out = delete_permanently(&pol, &targets);
        // shared.bin has a second name in the sentinel, so deleting this one frees nothing.
        assert_eq!(out.bytes_freed, 6000);
        assert!(!tree.root.join("shared.bin").exists());
        assert!(tree.root.join("locked.tmp").exists());
        assert!(tree.root.join("link").exists());
        let reasons: Vec<_> = out.skipped.iter().map(|s| s.reason.clone()).collect();
        assert!(reasons.contains(&SkipReason::InUse), "{reasons:?}");
        assert!(reasons.contains(&SkipReason::Refused(Refusal::ReparsePoint)));
    });
}

#[test]
fn a_locked_file_keeps_its_folder_but_everything_else_goes() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let mixed = tree.root.join("mixed");
    write_file(&mixed.join("x.tmp"), &[9u8; 100]);
    write_file(&mixed.join("sub").join("y.tmp"), &[9u8; 50]);
    write_file(&mixed.join("held.tmp"), b"busy");
    let held = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(mixed.join("held.tmp"))
        .unwrap();
    with_sentinel_guard(&tree, || {
        let out = delete_permanently(&pol, &[wp(&mixed)]);
        assert_eq!(out.bytes_freed, 150);
        assert!(!mixed.join("x.tmp").exists());
        assert!(!mixed.join("sub").exists());
        assert!(mixed.join("held.tmp").exists());
        let reasons: Vec<_> = out.skipped.iter().map(|s| s.reason.clone()).collect();
        assert_eq!(reasons, vec![SkipReason::InUse, SkipReason::NotEmpty]);
    });
    drop(held);
}

#[test]
fn deletes_a_read_only_file() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let file = tree.root.join("readonly.tmp");
    write_file(&file, &[5u8; 10]);
    let mut perms = fs::metadata(&file).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&file, perms).unwrap();
    let out = delete_permanently(&pol, &[wp(&file)]);
    assert!(out.skipped.is_empty(), "{:?}", out.skipped);
    assert!(!file.exists());
}

#[test]
fn a_missing_target_is_reported_already_gone() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let out = delete_permanently(&pol, &[wp(&tree.root.join("never-there.tmp"))]);
    assert_eq!(out.skipped[0].reason, SkipReason::NotFound);
}

#[test]
fn a_folder_holding_a_name_that_is_not_valid_unicode_is_kept_whole() {
    // Security review note: a lossy copy of such a name could point at a different file.
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let odd = tree.root.join("odd");
    write_file(&odd.join("fine.tmp"), b"ok");
    let bad_name = OsString::from_wide(&[0x0062, 0xD800, 0x0063]); // b, lone surrogate, c
    fs::write(odd.join(&bad_name), b"x").unwrap();
    let out = delete_permanently(&pol, &[wp(&odd)]);
    assert!(odd.join(&bad_name).exists());
    assert!(odd.exists());
    assert!(
        out.skipped
            .iter()
            .any(|s| s.reason.to_string().contains("not valid Unicode")),
        "{:?}",
        out.skipped
    );
}
