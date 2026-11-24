//! Task 8: one table-driven sweep, every action × every refusal case. Nothing in these cases may
//! be removed, copied or recycled, and the PowerShell checker must see the sentinel and the
//! root's other contents unchanged. Refusals happen before the shell is called, so this never
//! touches a real Recycle Bin.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::engine::{Outcome, SkipReason, delete_permanently};
use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::{DENIED_AT_DRIVE_ROOT, Policy, Refusal, denied_reason};
use bytebroom_core::recycle::recycle;
use bytebroom_core::relocate::move_to;
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::*;
use std::fs;
use std::path::Path;

fn wp(path: &Path) -> WinPath {
    WinPath::parse(path.to_str().unwrap()).unwrap()
}

type Action = fn(&Policy, &[WinPath], &FakeTree) -> Outcome;

fn act_delete(p: &Policy, t: &[WinPath], _: &FakeTree) -> Outcome {
    delete_permanently(p, t)
}
fn act_recycle(p: &Policy, t: &[WinPath], _: &FakeTree) -> Outcome {
    recycle(p, t)
}
fn act_move(p: &Policy, t: &[WinPath], tree: &FakeTree) -> Outcome {
    let dest = tree.base.join("dest");
    fs::create_dir_all(&dest).unwrap();
    move_to(p, t, &wp(&dest), &tree.base.join("journal.log"))
}

#[test]
fn every_action_refuses_every_unsafe_target() {
    let actions: [(&str, Action); 3] = [
        ("delete", act_delete),
        ("recycle", act_recycle),
        ("move", act_move),
    ];
    for (name, action) in actions {
        let tree = FakeTree::new();
        let root = open_no_follow(&wp(&tree.root), Access::Inspect).unwrap();
        let pol = Policy::new(vec![root.resolved], system_layout()).unwrap();
        let cases: Vec<(WinPath, SkipReason)> = vec![
            (
                wp(&tree.root),
                SkipReason::Refused(Refusal::OutsideAllowedRoots),
            ),
            (
                wp(&tree.root.join("link")),
                SkipReason::Refused(Refusal::ReparsePoint),
            ),
            (
                wp(&tree.root.join("link").join("keep.txt")),
                SkipReason::Refused(Refusal::OutsideAllowedRoots),
            ),
            (
                wp(&tree.sentinel.join("keep.txt")),
                SkipReason::Refused(Refusal::OutsideAllowedRoots),
            ),
            (
                wp(&tree.sentinel),
                SkipReason::Refused(Refusal::OutsideAllowedRoots),
            ),
            (wp(&tree.root.join("missing.tmp")), SkipReason::NotFound),
        ];
        let sentinel_before = snapshot(&tree.sentinel, "s-before", &tree.base);
        let root_before = snapshot(&tree.root, "r-before", &tree.base);

        for (target, want) in &cases {
            let out = action(&pol, std::slice::from_ref(target), &tree);
            assert!(
                out.removed.is_empty(),
                "{name} removed {target}: {:?}",
                out.removed
            );
            assert_eq!(out.skipped.len(), 1, "{name} {target}: {:?}", out.skipped);
            assert_eq!(&out.skipped[0].reason, want, "{name} {target}");
            assert_eq!(out.bytes_freed + out.bytes_recycled + out.bytes_moved, 0);
        }

        let sentinel_after = snapshot(&tree.sentinel, "s-after", &tree.base);
        let root_after = snapshot(&tree.root, "r-after", &tree.base);
        assert_unchanged(&sentinel_before, &sentinel_after);
        assert_unchanged(&root_before, &root_after);
        if name == "move" {
            let dest = tree.base.join("dest");
            assert!(
                fs::read_dir(&dest).unwrap().next().is_none(),
                "move copied something"
            );
        }
    }
}

#[test]
fn the_hard_floor_holds_on_every_drive_letter() {
    let layout = system_layout();
    for letter in 'A'..='Z' {
        let drive = WinPath::drive_root(letter);
        assert!(
            denied_reason(&drive, &layout).is_some(),
            "{letter}:\\ itself"
        );
        for name in DENIED_AT_DRIVE_ROOT {
            for spelled in [name.to_string(), name.to_uppercase(), name.to_lowercase()] {
                let Ok(area) = drive.join(&spelled) else {
                    continue;
                };
                assert!(denied_reason(&area, &layout).is_some(), "{area}");
                let inside = area.join("x").unwrap();
                assert!(denied_reason(&inside, &layout).is_some(), "{inside}");
            }
        }
    }
    for area in [
        layout.system_root.clone(),
        layout.program_data.clone(),
        layout.profiles_dir.clone(),
    ]
    .into_iter()
    .chain(layout.program_files.iter().cloned())
    .chain(layout.profile_roots.iter().cloned())
    {
        assert!(denied_reason(&area, &layout).is_some(), "{area}");
    }
}

#[test]
fn no_root_can_reach_a_protected_area() {
    // The real environment: none of these may become an allowed root.
    let layout = system_layout();
    let mut candidates = vec![
        layout.system_root.clone(),
        layout.system_root.join("System32").unwrap(),
        layout.program_data.clone(),
        layout.profiles_dir.clone(),
        WinPath::drive_root('C'),
    ];
    candidates.extend(layout.program_files.iter().cloned());
    candidates.extend(layout.profile_roots.iter().cloned());
    for path in candidates {
        let Ok(opened) = open_no_follow(&path, Access::Inspect) else {
            continue; // e.g. Program Files (x86) missing on some systems
        };
        assert!(
            Policy::new(vec![opened.resolved], layout.clone()).is_err(),
            "{path} was accepted as a root"
        );
    }
}
