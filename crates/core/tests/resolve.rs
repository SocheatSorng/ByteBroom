//! Task 4: the Windows adapter resolves targets from an open handle without following them,
//! and the policy refuses anything that leads outside the root.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::{Policy, Refusal};
use bytebroom_core::win::{Access, OpenError, open_no_follow, system_layout};
use common::FakeTree;
use std::path::Path;

fn wp(path: &Path) -> WinPath {
    WinPath::parse(path.to_str().unwrap()).unwrap()
}

fn policy_for(tree: &FakeTree) -> Policy {
    let root = open_no_follow(&wp(&tree.root), Access::Inspect).unwrap();
    Policy::new(vec![root.resolved], system_layout()).unwrap()
}

#[test]
fn a_plain_file_resolves_inside_the_root_with_its_size() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let opened =
        open_no_follow(&wp(&tree.root.join("junk").join("b.tmp")), Access::Inspect).unwrap();
    assert!(!opened.resolved.is_reparse_point);
    assert!(!opened.is_directory);
    assert_eq!(opened.size, 2000);
    assert_eq!(opened.link_count, 1);
    assert_eq!(pol.check_target(&opened.resolved), Ok(()));
}

#[test]
fn the_junction_itself_is_seen_as_a_reparse_point_and_refused() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let opened = open_no_follow(&wp(&tree.root.join("link")), Access::Inspect).unwrap();
    assert!(opened.resolved.is_reparse_point);
    assert_eq!(
        pol.check_target(&opened.resolved),
        Err(Refusal::ReparsePoint)
    );
}

#[test]
fn a_path_through_the_junction_resolves_outside_and_is_refused() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let opened = open_no_follow(
        &wp(&tree.root.join("link").join("keep.txt")),
        Access::Delete,
    )
    .unwrap();
    // Windows followed the junction in the middle of the path; the real path shows it.
    assert!(
        opened
            .resolved
            .final_path
            .to_string()
            .ends_with("sentinel\\keep.txt")
    );
    assert_eq!(
        pol.check_target(&opened.resolved),
        Err(Refusal::OutsideAllowedRoots)
    );
}

#[test]
fn a_hard_link_reports_two_names() {
    let tree = FakeTree::new();
    let opened = open_no_follow(&wp(&tree.root.join("shared.bin")), Access::Inspect).unwrap();
    assert_eq!(opened.link_count, 2);
}

#[test]
fn a_file_held_open_without_sharing_is_reported_in_use() {
    let tree = FakeTree::new();
    let err = open_no_follow(&wp(&tree.root.join("locked.tmp")), Access::Delete).unwrap_err();
    assert!(matches!(err, OpenError::InUse), "{err:?}");
}

#[test]
fn a_missing_file_is_reported_not_found() {
    let tree = FakeTree::new();
    let err = open_no_follow(&wp(&tree.root.join("nope.tmp")), Access::Inspect).unwrap_err();
    assert!(matches!(err, OpenError::NotFound), "{err:?}");
}

#[test]
fn a_root_that_is_itself_a_junction_is_refused() {
    let tree = FakeTree::new();
    let link = open_no_follow(&wp(&tree.root.join("link")), Access::Inspect).unwrap();
    assert!(matches!(
        Policy::new(vec![link.resolved], system_layout()),
        Err(Refusal::ReparsePoint)
    ));
}

#[test]
fn the_real_system_layout_protects_this_pc() {
    let layout = system_layout();
    let windows = WinPath::parse(&std::env::var("SystemRoot").unwrap()).unwrap();
    assert!(layout.system_root.eq_ignore_case(&windows));
    assert!(!layout.program_files.is_empty());
    let profile = WinPath::parse(&std::env::var("USERPROFILE").unwrap()).unwrap();
    assert!(
        layout
            .profile_roots
            .iter()
            .any(|p| p.eq_ignore_case(&profile))
    );
    for root in [windows, profile, WinPath::drive_root('C')] {
        let opened = open_no_follow(&root, Access::Inspect).unwrap();
        assert!(
            Policy::new(vec![opened.resolved], layout.clone()).is_err(),
            "{root} was accepted as a root"
        );
    }
}
