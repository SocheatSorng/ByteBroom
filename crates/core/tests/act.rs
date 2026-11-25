//! Phase 3 task 4: fake profile → scan → preview → carry out, with the check right before acting
//! (security review F1). Deletes and moves only inside a temp folder; the independent PowerShell
//! snapshot (`tools/verify-tree.ps1`) checks what changed. The real Recycle Bin is never used: a
//! stand-in records what it was given.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::act::{ActionResult, Context, carry_out};
use bytebroom_core::engine::{Outcome, SkipReason, Target};
use bytebroom_core::locations::Locations;
use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::{Policy, SystemLayout};
use bytebroom_core::preview::{Action, Choice, Preview, preview};
use bytebroom_core::rules::DUPLICATE_MIN_BYTES;
use bytebroom_core::scan::{Finding, ScanOptions, scan};
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::{CleanDir, journal_at, powershell_sha256, snapshot, verify_tree, write_file};
use std::cell::RefCell;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const DAY: Duration = Duration::from_secs(24 * 3600);

fn real(path: &Path) -> WinPath {
    let parsed = WinPath::parse(path.to_str().unwrap()).unwrap();
    open_no_follow(&parsed, Access::Inspect)
        .unwrap()
        .resolved
        .final_path
}

fn dated(path: &Path, bytes: &[u8], when: SystemTime) {
    write_file(path, bytes);
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

fn old(path: &Path, bytes: &[u8]) {
    dated(path, bytes, SystemTime::now() - 40 * DAY);
}

struct Home {
    dir: CleanDir,
    home: PathBuf,
    local: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Self {
        let dir = CleanDir::new(tag);
        let home = dir.0.join("Users").join("Ann");
        let local = home.join("AppData").join("Local");
        old(&local.join("Temp").join("a.tmp"), &[1; 100]);
        old(&local.join("Temp").join("olddir").join("b.tmp"), &[2; 200]);
        old(&local.join("CrashDumps").join("app.dmp"), &[3; 300]);
        old(&home.join("Downloads").join("setup.exe"), &[6; 600]);
        old(&home.join("Downloads").join("keep.exe"), &[7; 700]);
        let dup: Vec<u8> = (0..DUPLICATE_MIN_BYTES as usize + 1)
            .map(|i| i as u8)
            .collect();
        dated(
            &home.join("Pictures").join("orig.bin"),
            &dup,
            SystemTime::now() - 90 * DAY,
        );
        old(&home.join("Documents").join("copy.bin"), &dup);
        write_file(&dir.0.join("outside").join("sentinel.txt"), b"must survive");
        fs::create_dir_all(dir.0.join("Elsewhere")).unwrap();
        Self { dir, home, local }
    }

    fn locations(&self) -> Locations {
        Locations {
            profile: Some(real(&self.home)),
            local_app_data: Some(real(&self.local)),
            downloads: Some(real(&self.home.join("Downloads"))),
            other_drives: Vec::new(),
            skipped: Vec::new(),
        }
    }

    fn layout(&self) -> SystemLayout {
        let mut layout = system_layout();
        layout.profile_roots.push(real(&self.home));
        layout
    }

    fn rel(&self, p: &WinPath) -> String {
        p.to_string()[real(&self.home).to_string().len() + 1..].to_string()
    }

    /// Two days from now, as the other scan tests: the fake files were created just now.
    fn later(&self) -> SystemTime {
        SystemTime::now() + 2 * DAY
    }

    fn findings(&self) -> Vec<Finding> {
        let opts = ScanOptions {
            now: self.later(),
            cancel: None,
        };
        scan(&self.locations(), &self.layout(), &opts).findings
    }

    fn index(&self, findings: &[Finding], rel: &str) -> usize {
        findings
            .iter()
            .position(|f| self.rel(&f.path) == rel)
            .unwrap_or_else(|| panic!("{rel} not found"))
    }

    fn journal(&self) -> PathBuf {
        self.dir.0.join("moves.journal")
    }
}

/// Carry out with a stand-in Recycle Bin that only records what it was given.
fn run(h: &Home, findings: &[Finding], pv: &Preview) -> (Vec<ActionResult>, Vec<Target>) {
    let recycled = RefCell::new(Vec::new());
    let recycle = |_: &Policy, targets: &[Target]| {
        recycled.borrow_mut().extend(targets.iter().cloned());
        Outcome::default()
    };
    let journal = journal_at(&h.journal());
    let ctx = Context {
        layout: &h.layout(),
        now: h.later(),
        journal: &journal,
        recycle: &recycle,
    };
    let results = carry_out(findings, pv, &ctx);
    (results, recycled.into_inner())
}

fn changes(before: &Path, after: &Path) -> Vec<String> {
    let (_, text) = verify_tree(&[
        "-Compare",
        "-Before",
        before.to_str().unwrap(),
        "-After",
        after.to_str().unwrap(),
    ]);
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != "identical")
        .map(String::from)
        .collect()
}

fn skipped_reasons(results: &[ActionResult]) -> Vec<(WinPath, SkipReason)> {
    results
        .iter()
        .flat_map(|r| r.outcome.skipped.iter())
        .map(|s| (s.path.clone(), s.reason.clone()))
        .collect()
}

#[test]
fn permanent_delete_removes_exactly_the_confirmed_items() {
    let h = Home::new("act-delete");
    let findings = h.findings();
    let chosen = [
        "AppData\\Local\\Temp\\a.tmp",
        "AppData\\Local\\Temp\\olddir",
        "Downloads\\setup.exe",
        "Documents\\copy.bin",
    ];
    let choices: Vec<Choice> = chosen
        .iter()
        .map(|r| Choice {
            index: h.index(&findings, r),
            action: Action::Delete,
        })
        .collect();
    let pv = preview(&findings, &choices, None, &h.layout()).unwrap();
    let before = snapshot(&h.dir.0, "before", &h.dir.0);
    let (results, recycled) = run(&h, &findings, &pv);
    let after = snapshot(&h.dir.0, "after", &h.dir.0);
    assert!(recycled.is_empty());
    assert!(skipped_reasons(&results).is_empty(), "{results:?}");
    let freed: u64 = results.iter().map(|r| r.outcome.bytes_freed).sum();
    assert_eq!(freed, 100 + 200 + 600 + DUPLICATE_MIN_BYTES + 1);

    let mut removed = changes(&before, &after);
    removed.sort();
    let mut expected: Vec<String> = [
        "Users\\Ann\\AppData\\Local\\Temp\\a.tmp",
        "Users\\Ann\\AppData\\Local\\Temp\\olddir",
        "Users\\Ann\\AppData\\Local\\Temp\\olddir\\b.tmp",
        "Users\\Ann\\Downloads\\setup.exe",
        "Users\\Ann\\Documents\\copy.bin",
    ]
    .iter()
    .map(|p| format!("removed: {p}"))
    .collect();
    expected.sort();
    // The snapshots themselves are written into the folder too; ignore those lines.
    // The journal is opened (created empty) before any clean, as the app does.
    removed
        .retain(|l| !l.contains("before") && !l.contains("after") && l != "added: moves.journal");
    assert_eq!(removed, expected);
}

#[test]
fn a_move_keeps_the_file_whole_and_journals_it() {
    let h = Home::new("act-move");
    let findings = h.findings();
    let i = h.index(&findings, "Downloads\\setup.exe");
    let src = h.home.join("Downloads").join("setup.exe");
    let hash_before = powershell_sha256(&src);
    // The preview refuses a move to the same drive (it frees nothing), and these tests have only
    // one drive, so the preview is made for a delete and turned into a move here. The move path
    // itself is what this test checks; `preview` has its own tests for the drive rule.
    let mut pv = preview(
        &findings,
        &[Choice {
            index: i,
            action: Action::Delete,
        }],
        None,
        &h.layout(),
    )
    .unwrap();
    pv.actions[0].action = Action::Move;
    pv.move_to = Some(real(&h.dir.0.join("Elsewhere")));
    let (results, _) = run(&h, &findings, &pv);
    assert!(skipped_reasons(&results).is_empty(), "{results:?}");
    assert!(!src.exists());
    let moved = h.dir.0.join("Elsewhere").join("setup.exe");
    assert_eq!(powershell_sha256(&moved), hash_before);
    assert_eq!(results[0].outcome.bytes_moved, 600);
    let journal = fs::read_to_string(h.journal()).unwrap();
    assert!(journal.contains("setup.exe"), "{journal}");
    assert!(journal.to_lowercase().contains(&hash_before.to_lowercase()));
}

#[test]
fn a_file_swapped_after_the_scan_is_refused() {
    let h = Home::new("act-swap");
    let findings = h.findings();
    let i = h.index(&findings, "Downloads\\setup.exe");
    let path = h.home.join("Downloads").join("setup.exe");
    let seen = findings[i].identity.unwrap();
    // Another file, same name, same size and same date: only Windows' file number differs.
    fs::remove_file(&path).unwrap();
    dated(&path, &[9; 600], seen.modified);
    let pv = preview(
        &findings,
        &[Choice {
            index: i,
            action: Action::Delete,
        }],
        None,
        &h.layout(),
    )
    .unwrap();
    let (results, _) = run(&h, &findings, &pv);
    assert!(path.exists(), "the swapped-in file must stay");
    assert_eq!(
        skipped_reasons(&results),
        vec![(
            findings[i].path.clone(),
            SkipReason::ChangedSinceScan("another file is in its place")
        )]
    );
    assert_eq!(results[0].outcome.bytes_freed, 0);
}

#[test]
fn a_file_rewritten_after_the_scan_is_refused() {
    let h = Home::new("act-rewrite");
    let findings = h.findings();
    let i = h.index(&findings, "Downloads\\setup.exe");
    let path = h.home.join("Downloads").join("setup.exe");
    old(&path, &[6; 650]);
    let pv = preview(
        &findings,
        &[Choice {
            index: i,
            action: Action::Delete,
        }],
        None,
        &h.layout(),
    )
    .unwrap();
    let (results, _) = run(&h, &findings, &pv);
    assert!(path.exists());
    assert_eq!(
        skipped_reasons(&results)[0].1,
        SkipReason::ChangedSinceScan("its contents changed")
    );
}

#[test]
fn a_duplicate_edited_after_the_scan_is_refused() {
    // Edit each copy in turn, keeping its length and date, so only a fresh hash can tell.
    for (edited, what) in [
        ("Documents\\copy.bin", "it no longer matches the kept copy"),
        ("Pictures\\orig.bin", "it no longer matches the kept copy"),
    ] {
        let h = Home::new("act-dup");
        let findings = h.findings();
        let i = h.index(&findings, "Documents\\copy.bin");
        assert!(findings[i].duplicate_of.is_some());
        let path = h.home.join(edited);
        let opened = open_no_follow(&real(&path), Access::Inspect).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        bytes[5] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(opened.modified)
            .unwrap();
        let pv = preview(
            &findings,
            &[Choice {
                index: i,
                action: Action::Delete,
            }],
            None,
            &h.layout(),
        )
        .unwrap();
        let (results, _) = run(&h, &findings, &pv);
        assert!(
            h.home.join("Documents").join("copy.bin").exists(),
            "{edited}"
        );
        assert_eq!(
            skipped_reasons(&results)[0].1,
            SkipReason::ChangedSinceScan(what),
            "{edited}"
        );
    }
}

#[test]
fn a_duplicate_whose_kept_copy_is_gone_is_refused() {
    let h = Home::new("act-kept-gone");
    let findings = h.findings();
    let i = h.index(&findings, "Documents\\copy.bin");
    fs::remove_file(h.home.join("Pictures").join("orig.bin")).unwrap();
    let pv = preview(
        &findings,
        &[Choice {
            index: i,
            action: Action::Delete,
        }],
        None,
        &h.layout(),
    )
    .unwrap();
    let (results, _) = run(&h, &findings, &pv);
    assert!(h.home.join("Documents").join("copy.bin").exists());
    assert_eq!(
        skipped_reasons(&results)[0].1,
        SkipReason::ChangedSinceScan("the kept copy is gone or changed")
    );
}

#[test]
fn a_temp_item_used_after_the_scan_is_refused_by_the_24_hour_rule() {
    let h = Home::new("act-fresh");
    let findings = h.findings();
    let olddir = h.index(&findings, "AppData\\Local\\Temp\\olddir");
    let atmp = h.index(&findings, "AppData\\Local\\Temp\\a.tmp");
    // The scan and the clean both run "two days from now" (`h.later()`), so everything the
    // fixture made just now counts as two days old. After the scan, a file in olddir is written
    // with a change date of that same "now": used within the last day. a.tmp is untouched.
    let new_file = h.local.join("Temp").join("olddir").join("new.tmp");
    dated(&new_file, b"in use", h.later());
    let pv = preview(
        &findings,
        &[
            Choice {
                index: olddir,
                action: Action::Delete,
            },
            Choice {
                index: atmp,
                action: Action::Delete,
            },
        ],
        None,
        &h.layout(),
    )
    .unwrap();
    let (results, _) = run(&h, &findings, &pv);
    assert!(new_file.exists());
    assert!(h.local.join("Temp").join("olddir").join("b.tmp").exists());
    assert_eq!(
        skipped_reasons(&results),
        vec![(
            findings[olddir].path.clone(),
            SkipReason::ChangedSinceScan("it was used in the last day, or can't all be read")
        )]
    );
    // The untouched item still went.
    assert!(!h.local.join("Temp").join("a.tmp").exists());
}

/// Security review note 4: the 24-hour rule judges the item directly inside the rule's folder.
/// A finding nested deeper (the scanner never makes one) can't be judged, so it stays.
#[test]
fn a_temp_finding_nested_below_its_root_fails_safe() {
    let h = Home::new("act-nested");
    let mut findings = h.findings();
    let olddir = h.index(&findings, "AppData\\Local\\Temp\\olddir");
    let b = real(&h.local.join("Temp").join("olddir").join("b.tmp"));
    findings[olddir].path = b.clone();
    findings[olddir].is_folder = false;
    let pv = preview(
        &findings,
        &[Choice {
            index: olddir,
            action: Action::Delete,
        }],
        None,
        &h.layout(),
    )
    .unwrap();
    let (results, _) = run(&h, &findings, &pv);
    assert!(h.local.join("Temp").join("olddir").join("b.tmp").exists());
    assert_eq!(
        skipped_reasons(&results)
            .iter()
            .filter(|(p, _)| *p == b)
            .map(|(_, r)| r.clone())
            .collect::<Vec<_>>(),
        vec![SkipReason::ChangedSinceScan(
            "its folder can no longer be checked"
        )]
    );
}

#[test]
fn recycling_goes_only_through_the_given_bin_and_only_checked_items() {
    let h = Home::new("act-recycle");
    let findings = h.findings();
    let a = h.index(&findings, "AppData\\Local\\Temp\\a.tmp");
    let s = h.index(&findings, "Downloads\\setup.exe");
    // setup.exe is rewritten after the scan, so only a.tmp reaches the bin.
    old(&h.home.join("Downloads").join("setup.exe"), &[1; 10]);
    let pv = preview(
        &findings,
        &[
            Choice {
                index: a,
                action: Action::Recycle,
            },
            Choice {
                index: s,
                action: Action::Recycle,
            },
        ],
        None,
        &h.layout(),
    )
    .unwrap();
    let before = snapshot(&h.dir.0, "before", &h.dir.0);
    let (results, recycled) = run(&h, &findings, &pv);
    let after = snapshot(&h.dir.0, "after", &h.dir.0);
    // The file's scan identity goes with it, for the bin to check on its own handle.
    assert_eq!(
        recycled,
        vec![Target {
            path: findings[a].path.clone(),
            expect: findings[a].identity,
        }]
    );
    assert!(findings[a].identity.is_some());
    assert_eq!(skipped_reasons(&results).len(), 1);
    // The stand-in removed nothing; neither did anything else.
    let mut diff = changes(&before, &after);
    diff.retain(|l| !l.contains("before") && !l.contains("after") && l != "added: moves.journal");
    assert!(diff.is_empty(), "{diff:?}");
}
