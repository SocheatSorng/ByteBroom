//! Phase 2 task 8: a full scan of a generated fake profile with 200,000 files in 20,000 folders
//! must take under 30 seconds in a release build. Ignored by default (it writes 200,000 small
//! files to a temp folder); run it with:
//!
//! `cargo test --release -p bytebroom-core --test speed -- --ignored --nocapture`
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

mod common;

use bytebroom_core::locations::Locations;
use bytebroom_core::paths::WinPath;
use bytebroom_core::scan::{ScanOptions, scan};
use bytebroom_core::walk::{Step, WalkOptions};
use bytebroom_core::win::walk::walk;
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::CleanDir;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

const TOP: usize = 200;
const SUB: usize = 100;
const FILES: usize = 10;
const LIMIT: Duration = Duration::from_secs(30);

fn real(path: &Path) -> WinPath {
    let parsed = WinPath::parse(path.to_str().unwrap()).unwrap();
    open_no_follow(&parsed, Access::Inspect)
        .unwrap()
        .resolved
        .final_path
}

#[test]
#[ignore = "writes 200,000 files; run on demand with --release -- --ignored"]
fn a_full_scan_of_200_000_files_takes_under_30_seconds() {
    let dir = CleanDir::new("speed");
    let home = dir.0.join("Users").join("Ann");
    let local = home.join("AppData").join("Local");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(home.join("Downloads")).unwrap();

    let started = Instant::now();
    let docs = home.join("Documents");
    for t in 0..TOP {
        for s in 0..SUB {
            let folder = docs.join(format!("t{t:03}")).join(format!("s{s:03}"));
            fs::create_dir_all(&folder).unwrap();
            for f in 0..FILES {
                // Small and all different, so nothing is a duplicate or large: the cost measured
                // is the walk, not hashing.
                fs::write(folder.join(format!("f{f}.dat")), format!("{t}-{s}-{f}")).unwrap();
            }
        }
    }
    println!(
        "generated {} files in {:?}",
        TOP * SUB * FILES,
        started.elapsed()
    );

    let layout = {
        let mut l = system_layout();
        l.profile_roots.push(real(&home));
        l
    };

    // The walker alone, once over the profile.
    let t0 = Instant::now();
    let summary = walk(&real(&home), &layout, &WalkOptions::default(), |_| {
        Step::Enter
    })
    .unwrap();
    let walk_time = t0.elapsed();
    assert_eq!(summary.files, (TOP * SUB * FILES) as u64);
    assert!(summary.folders >= (TOP * SUB) as u64);
    println!(
        "walk: {} files, {} folders in {walk_time:?}",
        summary.files, summary.folders
    );

    // The whole scan, every rule (it walks the profile more than once).
    let at = Locations {
        profile: Some(real(&home)),
        local_app_data: Some(real(&local)),
        downloads: Some(real(&home.join("Downloads"))),
        other_drives: Vec::new(),
        skipped: Vec::new(),
    };
    let opts = ScanOptions {
        now: SystemTime::now(),
        cancel: None,
    };
    let t1 = Instant::now();
    let report = scan(&at, &layout, &opts);
    let scan_time = t1.elapsed();
    println!(
        "full scan: {} findings, {} files walked in {scan_time:?}",
        report.findings.len(),
        report.walked.files
    );
    assert!(report.findings.is_empty(), "{:?}", report.findings.first());
    assert!(
        scan_time < LIMIT,
        "the scan took {scan_time:?}, over the {LIMIT:?} target"
    );

    let cleanup = Instant::now();
    drop(dir);
    println!("cleaned up in {:?}", cleanup.elapsed());
}
