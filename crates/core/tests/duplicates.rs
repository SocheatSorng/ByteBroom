//! Phase 2 task 5: large files and duplicates, on fake profiles in a temp folder. Only reads; the
//! PowerShell snapshot proves hashing changed nothing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::locations::Locations;
use bytebroom_core::paths::WinPath;
use bytebroom_core::rules::{DUPLICATE_MIN_BYTES, LARGE_FILE_BYTES};
use bytebroom_core::scan::{Finding, ScanOptions, scan};
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::{CleanDir, assert_unchanged, snapshot, write_file};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

const DAY: Duration = Duration::from_secs(24 * 3600);

fn real(path: &Path) -> WinPath {
    let parsed = WinPath::parse(path.to_str().unwrap()).unwrap();
    open_no_follow(&parsed, Access::Inspect)
        .unwrap()
        .resolved
        .final_path
}

/// Write `bytes` and date the file `age` ago.
fn put(path: &Path, bytes: &[u8], age: Duration) {
    write_file(path, bytes);
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() - age)
        .unwrap();
}

/// Content just over the duplicate minimum, from a seed, so different seeds differ everywhere.
fn content(seed: u8, extra: usize) -> Vec<u8> {
    let n = DUPLICATE_MIN_BYTES as usize + extra;
    (0..n).map(|i| (i as u8).wrapping_mul(31) ^ seed).collect()
}

struct Home {
    dir: CleanDir,
    home: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Self {
        let dir = CleanDir::new(tag);
        let home = dir.0.join("Users").join("Ann");
        fs::create_dir_all(home.join("AppData").join("Local")).unwrap();
        fs::create_dir_all(home.join("Downloads")).unwrap();
        Self { dir, home }
    }

    fn locations(&self) -> Locations {
        Locations {
            profile: Some(real(&self.home)),
            local_app_data: Some(real(&self.home.join("AppData").join("Local"))),
            downloads: Some(real(&self.home.join("Downloads"))),
            other_drives: Vec::new(),
            skipped: Vec::new(),
        }
    }

    fn rel(&self, p: &WinPath) -> String {
        p.to_string()[real(&self.home).to_string().len() + 1..].to_string()
    }

    fn findings(&self, rule: &str) -> Vec<Finding> {
        let opts = ScanOptions {
            now: SystemTime::now(),
            cancel: None,
        };
        scan(&self.locations(), &system_layout(), &opts)
            .findings
            .into_iter()
            .filter(|f| f.rule.id == rule)
            .collect()
    }
}

/// Planted duplicates, near-duplicates, hard links and decoys.
fn duplicates_home() -> Home {
    let h = Home::new("dupes");
    let x = content(1, 10);
    put(&h.home.join("Pictures").join("a-copy.bin"), &x, 100 * DAY); // oldest: kept
    put(&h.home.join("Documents").join("a.bin"), &x, 50 * DAY);
    put(&h.home.join("Desktop").join("a-copy2.bin"), &x, 10 * DAY);
    put(&h.home.join("Downloads").join("a (1).bin"), &x, 5 * DAY);
    // Same content in places duplicates are not searched, or never listed.
    put(
        &h.home.join("AppData").join("Local").join("x.bin"),
        &x,
        200 * DAY,
    );
    put(
        &h.home.join("code").join("node_modules").join("x.bin"),
        &x,
        200 * DAY,
    );
    put(
        &h.home.join("repo").join(".git").join("x.bin"),
        &x,
        200 * DAY,
    );
    put(&h.home.join("Documents").join("backup.kdbx"), &x, 200 * DAY);

    // Near-duplicates: same size; the first two share their first 64 KB.
    let near = content(2, 30);
    let mut tail = near.clone();
    *tail.last_mut().unwrap() ^= 0xFF;
    let mut head = near.clone();
    head[0] ^= 0xFF;
    put(&h.home.join("Documents").join("near1.bin"), &near, 30 * DAY);
    put(&h.home.join("Documents").join("near2.bin"), &tail, 20 * DAY);
    put(&h.home.join("Documents").join("near3.bin"), &head, 10 * DAY);

    // Hard links: one file, two names. Not duplicates.
    put(
        &h.home.join("Documents").join("h.bin"),
        &content(3, 20),
        30 * DAY,
    );
    fs::create_dir_all(h.home.join("Music")).unwrap();
    fs::hard_link(
        h.home.join("Documents").join("h.bin"),
        h.home.join("Music").join("h-link.bin"),
    )
    .unwrap();

    // Small duplicates (under the minimum).
    put(
        &h.home.join("Documents").join("s1.txt"),
        &[7u8; 1000],
        30 * DAY,
    );
    put(
        &h.home.join("Documents").join("s2.txt"),
        &[7u8; 1000],
        20 * DAY,
    );
    h
}

#[test]
fn all_but_the_oldest_copy_are_offered_unticked() {
    let h = duplicates_home();
    let mut got: Vec<(String, String)> = h
        .findings("duplicates")
        .iter()
        .map(|f| {
            assert!(!f.pre_ticked);
            assert!(f.path.is_strictly_inside(&f.root));
            assert_eq!(f.bytes, DUPLICATE_MIN_BYTES + 10);
            (
                h.rel(&f.path),
                h.rel(f.duplicate_of.as_ref().expect("names the kept copy")),
            )
        })
        .collect();
    got.sort();
    let kept = "Pictures\\a-copy.bin".to_string();
    assert_eq!(
        got,
        vec![
            ("Desktop\\a-copy2.bin".to_string(), kept.clone()),
            ("Documents\\a.bin".to_string(), kept.clone()),
            ("Downloads\\a (1).bin".to_string(), kept),
        ]
    );
}

#[test]
fn near_duplicates_hard_links_small_files_and_secrets_are_not_offered() {
    let h = duplicates_home();
    for f in h.findings("duplicates") {
        // Neither the offered copy nor the kept one may come from a decoy.
        let rel = format!(
            "{} {}",
            h.rel(&f.path),
            h.rel(f.duplicate_of.as_ref().unwrap())
        );
        for bad in [
            "near",
            "h.bin",
            "h-link",
            "s1",
            "s2",
            "kdbx",
            "AppData",
            "node_modules",
            ".git",
        ] {
            assert!(!rel.contains(bad), "{rel} offered");
        }
    }
}

#[test]
fn a_tie_on_dates_keeps_the_shortest_path() {
    let h = Home::new("dupes-tie");
    let x = content(4, 0);
    // Exactly the same date on both (put() would date each a few microseconds apart).
    let when = SystemTime::now() - 9 * DAY;
    for path in [
        h.home.join("Docs").join("deeper").join("x.bin"),
        h.home.join("Docs").join("x.bin"),
    ] {
        write_file(&path, &x);
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(when)
            .unwrap();
    }
    let f = h.findings("duplicates");
    assert_eq!(f.len(), 1);
    assert_eq!(h.rel(&f[0].path), "Docs\\deeper\\x.bin");
    assert_eq!(h.rel(f[0].duplicate_of.as_ref().unwrap()), "Docs\\x.bin");
}

#[test]
fn hashing_for_duplicates_changes_nothing() {
    let h = duplicates_home();
    let before = snapshot(&h.home, "before", &h.dir.0);
    h.findings("duplicates");
    assert_unchanged(&before, &snapshot(&h.home, "after", &h.dir.0));
}

/// A file of `len` bytes that takes no disk space (sparse), when the file system allows it.
fn sparse(path: &Path, len: u64) {
    write_file(path, b"");
    let _ = Command::new("fsutil")
        .args(["sparse", "setflag"])
        .arg(path)
        .output();
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(len)
        .unwrap();
}

#[test]
fn large_files_start_at_the_owners_threshold_and_are_listed_once() {
    let h = Home::new("large");
    // Downloads sits inside the profile: the file must still be listed only once.
    sparse(&h.home.join("Downloads").join("big.iso"), LARGE_FILE_BYTES);
    sparse(
        &h.home.join("Videos").join("almost.mp4"),
        LARGE_FILE_BYTES - 1,
    );
    sparse(&h.home.join("Videos").join("id.pem"), LARGE_FILE_BYTES); // never listed
    let found = h.findings("large-files");
    let names: Vec<String> = found.iter().map(|f| h.rel(&f.path)).collect();
    assert_eq!(names, vec!["Downloads\\big.iso".to_string()]);
    assert_eq!(found[0].bytes, LARGE_FILE_BYTES);
    assert!(!found[0].pre_ticked);
    assert_eq!(found[0].duplicate_of, None);
    assert_eq!(LARGE_FILE_BYTES, 500 * 1024 * 1024);
}
