//! Phase 2 task 7: fake profile → scan → select → delete, checked by the independent PowerShell
//! snapshot: only the selected items are gone. Deletes only inside a temp folder, permanently
//! (the real Recycle Bin is never used by these tests).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::clean::{plan_clean, prepare};
use bytebroom_core::engine::delete_permanently;
use bytebroom_core::locations::Locations;
use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::SystemLayout;
use bytebroom_core::rules::{DUPLICATE_MIN_BYTES, RULES};
use bytebroom_core::scan::{Finding, ScanOptions, scan};
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::{CleanDir, make_junction, snapshot, verify_tree, write_file};
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

fn old(path: &Path, bytes: &[u8]) {
    write_file(path, bytes);
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() - 40 * DAY)
        .unwrap();
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
        let cache = local
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default");
        old(
            &cache.join("Cache").join("Cache_Data").join("f_1"),
            &[4; 400],
        );
        old(&cache.join("Cookies"), &[5; 50]); // must survive
        old(&home.join("Downloads").join("setup.exe"), &[6; 600]);
        old(&home.join("Downloads").join("keep.exe"), &[7; 700]);
        let dup: Vec<u8> = (0..DUPLICATE_MIN_BYTES as usize + 1)
            .map(|i| i as u8)
            .collect();
        old(&home.join("Pictures").join("orig.bin"), &dup);
        old(&home.join("Documents").join("copy.bin"), &dup);
        // Make the picture the older copy.
        File::options()
            .write(true)
            .open(home.join("Pictures").join("orig.bin"))
            .unwrap()
            .set_modified(SystemTime::now() - 90 * DAY)
            .unwrap();
        write_file(&dir.0.join("outside").join("sentinel.txt"), b"must survive");
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

    /// The real layout, with the fake profile listed as a profile (as Windows lists real ones).
    fn layout(&self) -> SystemLayout {
        let mut layout = system_layout();
        layout.profile_roots.push(real(&self.home));
        layout
    }

    fn rel(&self, p: &WinPath) -> String {
        p.to_string()[real(&self.home).to_string().len() + 1..].to_string()
    }

    /// Scanned as if two days from now: the fake files were created just now, and creation dates
    /// count toward the 24-hour temp rule.
    fn findings(&self) -> Vec<Finding> {
        let opts = ScanOptions {
            now: SystemTime::now() + 2 * DAY,
            cancel: None,
        };
        scan(&self.locations(), &self.layout(), &opts).findings
    }
}

/// The `removed:` lines of a verify-tree comparison; panics on any other kind of difference.
fn removed(before: &Path, after: &Path) -> Vec<String> {
    let (_, text) = verify_tree(&[
        "-Compare",
        "-Before",
        before.to_str().unwrap(),
        "-After",
        after.to_str().unwrap(),
    ]);
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line == "identical" {
            continue;
        }
        let rel = line
            .strip_prefix("removed: ")
            .unwrap_or_else(|| panic!("unexpected difference: {line}"));
        out.push(rel.to_string());
    }
    out
}

#[test]
fn scan_select_delete_removes_exactly_the_selection() {
    let h = Home::new("clean-e2e");
    let findings = h.findings();
    let wanted = [
        "AppData\\Local\\Temp\\a.tmp",
        "AppData\\Local\\Temp\\olddir",
        "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\Cache_Data",
        "Downloads\\setup.exe",
        "Documents\\copy.bin",
    ];
    let chosen: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| wanted.contains(&h.rel(&f.path).as_str()))
        .map(|(i, _)| i)
        .collect();
    // Documents\copy.bin is both a duplicate and (here) nothing else; every wanted item is found.
    let chosen_paths: Vec<String> = chosen.iter().map(|&i| h.rel(&findings[i].path)).collect();
    for w in wanted {
        assert!(
            chosen_paths.iter().any(|c| c == w),
            "{w} not found: {chosen_paths:?}"
        );
    }

    let plan = plan_clean(&findings, &chosen).unwrap();
    let ready = prepare(&plan, &h.layout());
    assert!(ready.refused.is_empty(), "{:?}", ready.refused);
    let policy = ready.policy.expect("every root passes");
    // The roots are the rules' own folders, never the profile or a drive.
    for root in policy.roots() {
        assert!(root.is_strictly_inside(&real(&h.home)), "{root}");
    }

    // Snapshots live in their own temp folder, outside the tree they describe.
    let snaps = CleanDir::new("clean-e2e-snaps");
    let before = snapshot(&h.dir.0, "before", &snaps.0);
    let outcome = delete_permanently(&policy, &ready.targets);
    assert!(outcome.skipped.is_empty(), "{:?}", outcome.skipped);
    let after = snapshot(&h.dir.0, "after", &snaps.0);

    // Everything removed is a chosen item or inside one, and every chosen item is removed.
    let home_rel = h
        .home
        .strip_prefix(&h.dir.0)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let gone = removed(&before, &after);
    for g in &gone {
        let in_home = g
            .strip_prefix(&format!("{home_rel}\\"))
            .unwrap_or_else(|| panic!("{g} was removed outside the profile"));
        assert!(
            wanted
                .iter()
                .any(|w| in_home == *w || in_home.starts_with(&format!("{w}\\"))),
            "{g} was removed but not selected"
        );
    }
    for w in wanted {
        assert!(
            gone.iter().any(|g| g.ends_with(w)),
            "{w} was selected but is still there"
        );
    }
}

/// A finding the scanner would never produce, to test that `prepare` refuses its root.
fn crafted(root: &Path, item: &Path) -> Finding {
    let rule = RULES.iter().find(|r| r.id == "user-temp").unwrap();
    Finding {
        rule,
        tier: rule.tier,
        root: real(root),
        path: real(item),
        is_folder: false,
        bytes: 1,
        files: 1,
        newest: SystemTime::now() - 40 * DAY,
        cloud: false,
        pre_ticked: true,
        duplicate_of: None,
    }
}

#[test]
fn a_startup_or_key_folder_is_refused_before_the_engine_sees_it() {
    let h = Home::new("clean-startup");
    let roaming = h.home.join("AppData").join("Roaming").join("Microsoft");
    let startup = roaming
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup");
    let protect = roaming.join("Protect");
    write_file(&startup.join("run-me.lnk"), b"x");
    write_file(&protect.join("key"), b"x");
    let findings = vec![
        crafted(&startup, &startup.join("run-me.lnk")),
        crafted(&protect, &protect.join("key")),
        crafted(&h.local.join("Temp"), &h.local.join("Temp").join("a.tmp")),
    ];
    let plan = plan_clean(&findings, &[0, 1, 2]).unwrap();
    let ready = prepare(&plan, &h.layout());
    assert_eq!(ready.refused.len(), 2, "{:?}", ready.refused);
    assert!(
        ready
            .refused
            .iter()
            .all(|r| r.why.contains("key, credential or startup"))
    );
    // Only the temp file goes ahead.
    assert_eq!(
        ready.targets,
        vec![real(&h.local.join("Temp").join("a.tmp"))]
    );
    let outcome = delete_permanently(&ready.policy.unwrap(), &ready.targets);
    assert!(outcome.skipped.is_empty());
    assert!(startup.join("run-me.lnk").exists());
    assert!(protect.join("key").exists());
    assert!(!h.local.join("Temp").join("a.tmp").exists());
}

#[test]
fn a_root_swapped_for_a_junction_after_the_scan_is_refused() {
    let h = Home::new("clean-swap");
    let findings = h.findings();
    let chosen: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| f.rule.id == "crash-dumps")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(chosen.len(), 1);
    let plan = plan_clean(&findings, &chosen).unwrap();

    // After the scan, CrashDumps is replaced by a junction to a folder with the same names.
    let dumps = h.local.join("CrashDumps");
    let decoy = h.dir.0.join("outside").join("CrashDumps");
    write_file(&decoy.join("app.dmp"), b"not yours to delete");
    fs::rename(&dumps, h.local.join("CrashDumps-moved")).unwrap();
    make_junction(&dumps, &decoy);

    let ready = prepare(&plan, &h.layout());
    fs::remove_dir(&dumps).unwrap();
    assert!(ready.policy.is_none());
    assert!(ready.targets.is_empty());
    assert_eq!(ready.refused.len(), 1);
    assert!(decoy.join("app.dmp").exists());
}

/// Security review must-fix M1: a folder the scan offers (pre-ticked) may hold a vault, a key or
/// a browser login file. Emptying the folder must take everything else and leave those.
#[test]
fn emptying_an_offered_folder_never_takes_keys_vaults_or_logins() {
    let h = Home::new("clean-never-listed");
    let extract = h.local.join("Temp").join("extract1");
    old(&extract.join("a.tmp"), &[1; 10]);
    old(&extract.join("vault.kdbx"), &[2; 10]);
    old(&extract.join("Login Data"), &[3; 10]);
    old(&extract.join(".ssh").join("id_ed25519"), &[4; 10]);
    old(&extract.join("deep").join("server.pem"), &[5; 10]);
    old(&extract.join("deep").join("b.tmp"), &[6; 10]);

    let findings = h.findings();
    let i = findings
        .iter()
        .position(|f| h.rel(&f.path) == "AppData\\Local\\Temp\\extract1")
        .expect("the folder is offered");
    assert!(findings[i].pre_ticked);
    let plan = plan_clean(&findings, &[i]).unwrap();
    let ready = prepare(&plan, &h.layout());
    let outcome = delete_permanently(&ready.policy.unwrap(), &ready.targets);

    assert!(!extract.join("a.tmp").exists());
    assert!(!extract.join("deep").join("b.tmp").exists());
    for kept in [
        extract.join("vault.kdbx"),
        extract.join("Login Data"),
        extract.join(".ssh").join("id_ed25519"),
        extract.join("deep").join("server.pem"),
    ] {
        assert!(kept.exists(), "{} was deleted", kept.display());
    }
    let refused = outcome
        .skipped
        .iter()
        .filter(|s| {
            s.reason
                == bytebroom_core::engine::SkipReason::Refused(
                    bytebroom_core::policy::Refusal::NeverListed,
                )
        })
        .count();
    assert_eq!(refused, 4, "{:?}", outcome.skipped);
    // The folders that still hold them are kept, and say why.
    assert!(extract.exists());
    assert!(
        outcome
            .skipped
            .iter()
            .any(|s| s.reason == bytebroom_core::engine::SkipReason::NotEmpty)
    );
}
