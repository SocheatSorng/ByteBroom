//! Task 6: the Recycle Bin.
//!
//! Ordinary tests never put anything in a Recycle Bin: they check refusals (which happen before
//! the shell is called) and read-only drive facts. Tests that use the REAL Recycle Bin are
//! `#[ignore]` and also need `BYTEBROOM_REAL_RECYCLE_BIN_TESTS=1` (the owner's decision 1):
//! CI's throwaway runners set it; on the owner's PC, the opt-in run recycles exactly one file
//! named `bytebroom-test-<random>.txt`. The folder test runs only on CI.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::engine::SkipReason;
use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::{Policy, Refusal};
use bytebroom_core::recycle::{RecycleRefusal, preflight, recycle};
use bytebroom_core::win::recycle::bin_facts;
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::*;
use std::fs::OpenOptions;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;

fn wp(path: &Path) -> WinPath {
    WinPath::parse(path.to_str().unwrap()).unwrap()
}

fn policy_for(tree: &FakeTree) -> Policy {
    let root = open_no_follow(&wp(&tree.root), Access::Inspect).unwrap();
    Policy::new(vec![root.resolved], system_layout()).unwrap()
}

fn require_real_bin_opt_in() {
    assert_eq!(
        std::env::var("BYTEBROOM_REAL_RECYCLE_BIN_TESTS").as_deref(),
        Ok("1"),
        "this test uses the real Recycle Bin: set BYTEBROOM_REAL_RECYCLE_BIN_TESTS=1 to run it"
    );
}

#[test]
fn links_and_outside_paths_are_refused_before_the_shell_is_called() {
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let before = snapshot(&tree.sentinel, "before", &tree.base);
    let out = recycle(
        &pol,
        &[
            wp(&tree.root.join("link")),
            wp(&tree.root.join("link").join("keep.txt")),
            wp(&tree.sentinel.join("keep.txt")),
        ],
    );
    assert!(out.removed.is_empty());
    let reasons: Vec<_> = out.skipped.iter().map(|s| s.reason.clone()).collect();
    assert_eq!(
        reasons,
        vec![
            SkipReason::Refused(Refusal::ReparsePoint),
            SkipReason::Refused(Refusal::OutsideAllowedRoots),
            SkipReason::Refused(Refusal::OutsideAllowedRoots),
        ]
    );
    let after = snapshot(&tree.sentinel, "after", &tree.base);
    assert_unchanged(&before, &after);
}

#[test]
fn the_temp_drive_is_a_fixed_drive_with_a_bin() {
    let temp = wp(&std::env::temp_dir());
    let facts = bin_facts(temp.drive());
    assert!(facts.fixed_local, "{facts:?}");
    assert!(!facts.subst, "{facts:?}");
    assert!(facts.bin_present, "{facts:?}");
    assert!(facts.max_bytes > 0, "{facts:?}");
}

/// Removes a `subst` drive letter when dropped.
struct Subst(char);
impl Drop for Subst {
    fn drop(&mut self) {
        let _ = Command::new("subst")
            .arg(format!("{}:", self.0))
            .arg("/D")
            .output();
    }
}

#[test]
fn a_subst_drive_is_treated_as_having_no_bin() {
    let dir = unique_dir("subst");
    let Some(letter) = ('M'..='Y')
        .rev()
        .find(|l| !Path::new(&format!("{l}:\\")).exists())
    else {
        return; // no free drive letter on this PC; nothing to test
    };
    let made = Command::new("subst")
        .arg(format!("{letter}:"))
        .arg(&dir)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let _guard = Subst(letter);
    let facts = bin_facts(letter);
    assert!(facts.subst, "{facts:?}");
    assert_eq!(preflight(&facts, 1), Err(RecycleRefusal::NoBin));

    // A file opened through the subst letter resolves to its real drive, so the engine
    // never recycles through the alias.
    write_file(&dir.join("f.tmp"), b"x");
    let opened = open_no_follow(
        &WinPath::parse(&format!("{letter}:\\f.tmp")).unwrap(),
        Access::Inspect,
    )
    .unwrap();
    assert_ne!(opened.resolved.final_path.drive(), letter);
}

#[test]
#[ignore = "uses the real Recycle Bin; opt in with BYTEBROOM_REAL_RECYCLE_BIN_TESTS=1"]
fn real_bin_recycles_one_dummy_file() {
    require_real_bin_opt_in();
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let name = format!(
        "bytebroom-test-{}.txt",
        tree.base.file_name().unwrap().to_string_lossy()
    );
    let file = tree.root.join(&name);
    write_file(&file, &[b'b'; 4096]);
    let before = snapshot(&tree.sentinel, "before", &tree.base);

    let out = recycle(&pol, &[wp(&file)]);

    assert!(out.skipped.is_empty(), "{:?}", out.skipped);
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    assert!(!file.exists());
    assert_eq!(out.bytes_recycled, 4096);
    assert_eq!(
        out.bytes_freed, 0,
        "recycling on the same drive frees nothing yet"
    );
    let after = snapshot(&tree.sentinel, "after", &tree.base);
    assert_unchanged(&before, &after);
    eprintln!("Recycled {name}: find it in the Recycle Bin.");
}

#[test]
#[ignore = "uses the real Recycle Bin; CI only"]
fn real_bin_recycles_the_rest_of_a_folder_with_a_locked_file() {
    require_real_bin_opt_in();
    if std::env::var("CI").is_err() {
        return; // more than one dummy item: CI's throwaway runners only
    }
    let tree = FakeTree::new();
    let pol = policy_for(&tree);
    let mixed = tree.root.join("mixed");
    write_file(&mixed.join("x.tmp"), &[1u8; 100]);
    write_file(&mixed.join("held.tmp"), b"busy");
    let held = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(mixed.join("held.tmp"))
        .unwrap();

    let out = recycle(&pol, &[wp(&mixed)]);

    assert!(!mixed.join("x.tmp").exists());
    assert!(mixed.join("held.tmp").exists());
    let reasons: Vec<_> = out.skipped.iter().map(|s| s.reason.clone()).collect();
    assert!(reasons.contains(&SkipReason::InUse), "{reasons:?}");
    assert!(reasons.contains(&SkipReason::NotEmpty), "{reasons:?}");
    drop(held);
}
