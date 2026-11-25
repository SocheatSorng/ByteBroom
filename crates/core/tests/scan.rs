//! Phase 2 task 4: green and amber findings from a fake profile with every category, plus decoys
//! that must not match. Only reads; the PowerShell snapshot proves nothing changed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::locations::Locations;
use bytebroom_core::paths::WinPath;
use bytebroom_core::rules::Tier;
use bytebroom_core::scan::{Finding, ScanOptions, scan};
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::{CleanDir, assert_unchanged, make_junction, snapshot, write_file};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

const DAY: Duration = Duration::from_secs(24 * 3600);

fn real(path: &Path) -> WinPath {
    let parsed = WinPath::parse(path.to_str().unwrap()).unwrap();
    open_no_follow(&parsed, Access::Inspect)
        .unwrap()
        .resolved
        .final_path
}

/// Write a file and set its change date `age` ago.
fn aged(path: &Path, bytes: usize, age: Duration) {
    write_file(path, &vec![b'x'; bytes]);
    let f = File::options().write(true).open(path).unwrap();
    f.set_modified(SystemTime::now() - age).unwrap();
}

fn old(path: &Path, bytes: usize) {
    aged(path, bytes, 40 * DAY);
}

struct Profile {
    dir: CleanDir,
    home: PathBuf,
}

impl Profile {
    fn new() -> Self {
        let dir = CleanDir::new("scan");
        let home = dir.0.join("Users").join("Ann");
        let local = home.join("AppData").join("Local");
        let outside = dir.0.join("outside");
        old(&outside.join("Cache").join("secret.bin"), 999);

        // Green.
        old(&local.join("Temp").join("old.tmp"), 100);
        aged(
            &local.join("Temp").join("fresh.tmp"),
            100,
            Duration::from_secs(3600),
        );
        old(&local.join("Temp").join("mixed").join("x.tmp"), 100);
        aged(
            &local.join("Temp").join("mixed").join("new.tmp"),
            100,
            Duration::ZERO,
        );
        old(&local.join("Temp").join("olddir").join("a.tmp"), 100);
        old(
            &local.join("Temp").join("olddir").join("deep").join("b.tmp"),
            200,
        );
        old(&local.join("CrashDumps").join("app.dmp"), 300);
        let wer = local.join("Microsoft").join("Windows").join("WER");
        old(&wer.join("ReportArchive").join("r1").join("Report.wer"), 10);
        old(&wer.join("ReportQueue").join("q1").join("a"), 10);
        let explorer = local.join("Microsoft").join("Windows").join("Explorer");
        old(&explorer.join("thumbcache_256.db"), 400);
        old(&explorer.join("iconcache_32.db"), 50);
        old(&explorer.join("thumbcache_256.db.bak"), 1); // decoy
        old(&explorer.join("ExplorerStartupLog.etl"), 1); // decoy
        old(
            &local
                .join("Microsoft")
                .join("Windows")
                .join("INetCache")
                .join("IE")
                .join("x.dat"),
            20,
        );
        old(&local.join("D3DSCache").join("abc").join("x"), 30);

        // A junction partway along a rule's path: Brave-Browser leads outside the profile, so
        // "User Data\*\Cache" below it must not be scanned even though Cache itself is real.
        let brave_out = outside.join("brave");
        old(
            &brave_out
                .join("User Data")
                .join("Default")
                .join("Cache")
                .join("secret.bin"),
            999,
        );
        fs::create_dir_all(local.join("BraveSoftware")).unwrap();
        make_junction(
            &local.join("BraveSoftware").join("Brave-Browser"),
            &brave_out,
        );

        let chrome = local.join("Google").join("Chrome").join("User Data");
        old(
            &chrome
                .join("Default")
                .join("Cache")
                .join("Cache_Data")
                .join("f_1"),
            500,
        );
        old(
            &chrome
                .join("Default")
                .join("Code Cache")
                .join("js")
                .join("x"),
            60,
        );
        old(&chrome.join("Default").join("GPUCache").join("data_0"), 70);
        old(
            &chrome
                .join("Profile 1")
                .join("Cache")
                .join("Cache_Data")
                .join("f"),
            80,
        );
        for decoy in ["Cookies", "History", "Login Data", "Bookmarks", "Web Data"] {
            old(&chrome.join("Default").join(decoy), 5);
        }
        old(&chrome.join("Local State"), 5);
        old(&chrome.join("Default").join("Network").join("Cookies"), 5);
        make_junction(&chrome.join("Linked"), &outside); // a "profile" that is a junction
        let edge = local
            .join("Microsoft")
            .join("Edge")
            .join("User Data")
            .join("Default");
        fs::create_dir_all(&edge).unwrap();
        make_junction(&edge.join("Cache"), &outside.join("Cache")); // a Cache that is a junction
        old(
            &local
                .join("Mozilla")
                .join("Firefox")
                .join("Profiles")
                .join("abc.default")
                .join("cache2")
                .join("entries")
                .join("E1"),
            90,
        );

        // Amber.
        old(&local.join("npm-cache").join("_cacache").join("x"), 11);
        old(&local.join("uv").join("cache").join("wheel.bin"), 12);
        old(
            &home
                .join(".cargo")
                .join("registry")
                .join("cache")
                .join("c.crate"),
            13,
        );
        let downloads = home.join("Downloads");
        old(&downloads.join("old-setup.exe"), 1000);
        aged(&downloads.join("new-setup.exe"), 1000, 2 * DAY);
        old(&downloads.join("photo.jpg"), 1000); // decoy: not an installer
        old(&downloads.join("sub").join("old.MSI"), 2000);
        old(&downloads.join("vault.kdbx"), 10); // never listed
        let code = home.join("code");
        old(&code.join("proj").join(".git").join("HEAD"), 1);
        old(
            &code
                .join("proj")
                .join("node_modules")
                .join("left-pad")
                .join("index.js"),
            3000,
        );
        old(
            &code
                .join("proj")
                .join("target")
                .join("debug")
                .join("app.exe"),
            4000,
        );
        old(
            &code.join("proj").join("src").join("bin").join("main.rs"),
            1,
        ); // decoy: no .git beside
        old(&code.join("notproj").join("node_modules").join("x.js"), 1); // decoy: no .git
        old(&home.join(".ssh").join("id_rsa"), 1); // never listed

        Self { dir, home }
    }

    /// The real layout with the fake profile listed, as Windows lists the real one (so the
    /// profile root is on the floor as a delete target, exactly as on the owner's PC).
    fn layout(&self) -> bytebroom_core::policy::SystemLayout {
        let mut layout = system_layout();
        layout.profile_roots.push(real(&self.home));
        layout
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

    fn rel(&self, f: &Finding) -> String {
        let home = real(&self.home).to_string();
        f.path.to_string()[home.len() + 1..].to_string()
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        let local = self.home.join("AppData").join("Local");
        let _ = fs::remove_dir(local.join("BraveSoftware").join("Brave-Browser"));
        let _ = fs::remove_dir(
            local
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Linked"),
        );
        let _ = fs::remove_dir(
            local
                .join("Microsoft")
                .join("Edge")
                .join("User Data")
                .join("Default")
                .join("Cache"),
        );
    }
}

fn run(p: &Profile) -> Vec<Finding> {
    let opts = ScanOptions {
        now: SystemTime::now(),
        cancel: None,
    };
    let report = scan(&p.locations(), &p.layout(), &opts);
    assert!(!report.cancelled);
    report.findings
}

const L: &str = "AppData\\Local\\";

#[test]
fn every_category_is_found_and_no_decoy_is() {
    let p = Profile::new();
    let found: BTreeSet<(String, String)> = run(&p)
        .iter()
        .map(|f| (f.rule.id.to_string(), p.rel(f)))
        .collect();
    let chrome = format!("{L}Google\\Chrome\\User Data\\");
    let expected: BTreeSet<(String, String)> = [
        ("user-temp", format!("{L}Temp\\old.tmp")),
        ("user-temp", format!("{L}Temp\\olddir")),
        ("crash-dumps", format!("{L}CrashDumps\\app.dmp")),
        (
            "error-reports",
            format!("{L}Microsoft\\Windows\\WER\\ReportArchive\\r1"),
        ),
        (
            "error-reports",
            format!("{L}Microsoft\\Windows\\WER\\ReportQueue\\q1"),
        ),
        (
            "thumbnail-cache",
            format!("{L}Microsoft\\Windows\\Explorer\\thumbcache_256.db"),
        ),
        (
            "thumbnail-cache",
            format!("{L}Microsoft\\Windows\\Explorer\\iconcache_32.db"),
        ),
        (
            "internet-cache",
            format!("{L}Microsoft\\Windows\\INetCache\\IE"),
        ),
        ("shader-cache", format!("{L}D3DSCache\\abc")),
        (
            "browser-caches",
            format!("{chrome}Default\\Cache\\Cache_Data"),
        ),
        ("browser-caches", format!("{chrome}Default\\Code Cache\\js")),
        (
            "browser-caches",
            format!("{chrome}Default\\GPUCache\\data_0"),
        ),
        (
            "browser-caches",
            format!("{chrome}Profile 1\\Cache\\Cache_Data"),
        ),
        (
            "browser-caches",
            format!("{L}Mozilla\\Firefox\\Profiles\\abc.default\\cache2\\entries"),
        ),
        ("developer-caches", format!("{L}npm-cache\\_cacache")),
        ("developer-caches", format!("{L}uv\\cache\\wheel.bin")),
        ("developer-caches", ".cargo\\registry\\cache".to_string()),
        ("old-installers", "Downloads\\old-setup.exe".to_string()),
        ("old-installers", "Downloads\\sub\\old.MSI".to_string()),
        ("build-folders", "code\\proj\\node_modules".to_string()),
        ("build-folders", "code\\proj\\target".to_string()),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_string(), b))
    .collect();
    let missing: Vec<_> = expected.difference(&found).collect();
    let extra: Vec<_> = found.difference(&expected).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "missing {missing:#?}\nextra {extra:#?}"
    );
}

#[test]
fn findings_carry_tier_ticks_sizes_counts_and_dates() {
    let p = Profile::new();
    let findings = run(&p);
    for f in &findings {
        assert_eq!(f.tier, f.rule.tier);
        assert_eq!(f.pre_ticked, f.tier == Tier::Green, "{}", p.rel(f));
        assert!(f.path.is_strictly_inside(&f.root), "{}", p.rel(f));
        assert!(f.files >= 1);
        assert!(f.newest <= SystemTime::now());
    }
    let get = |rel: &str| {
        findings
            .iter()
            .find(|f| p.rel(f) == rel)
            .unwrap_or_else(|| panic!("{rel} not found"))
    };
    let olddir = get(&format!("{L}Temp\\olddir"));
    assert_eq!(
        (olddir.bytes, olddir.files, olddir.is_folder),
        (300, 2, true)
    );
    assert!(olddir.newest < SystemTime::now() - 39 * DAY);
    assert!(olddir.root.to_string().ends_with("AppData\\Local\\Temp"));
    let exe = get("Downloads\\old-setup.exe");
    assert_eq!((exe.bytes, exe.files, exe.is_folder), (1000, 1, false));
    assert!(!exe.pre_ticked);
    let nm = get("code\\proj\\node_modules");
    assert_eq!((nm.bytes, nm.files), (3000, 1));
    assert!(nm.root.to_string().ends_with("code\\proj"));
}

#[test]
fn nothing_secret_or_linked_ever_appears() {
    let p = Profile::new();
    for f in run(&p) {
        let rel = p.rel(&f).to_lowercase();
        for bad in [
            ".ssh",
            "kdbx",
            "cookies",
            "history",
            "login data",
            "bookmarks",
            "web data",
            "local state",
            "linked",
            "edge",
            "secret",
        ] {
            assert!(!rel.contains(bad), "{rel} matched {bad}");
        }
    }
}

#[test]
fn fresh_temp_items_wait_and_the_cut_off_is_24_hours() {
    let p = Profile::new();
    // Seen from 2 days in the future, the 1-hour-old temp file and folder are old enough.
    let opts = ScanOptions {
        now: SystemTime::now() + 2 * DAY,
        cancel: None,
    };
    let report = scan(&p.locations(), &p.layout(), &opts);
    let temp: BTreeSet<String> = report
        .findings
        .iter()
        .filter(|f| f.rule.id == "user-temp")
        .map(|f| p.rel(f))
        .collect();
    for name in ["old.tmp", "fresh.tmp", "mixed", "olddir"] {
        assert!(
            temp.contains(&format!("{L}Temp\\{name}")),
            "{name}: {temp:?}"
        );
    }
    // And the 2-day-old installer is still too young until 30 days have passed.
    assert!(
        !report
            .findings
            .iter()
            .any(|f| p.rel(f) == "Downloads\\new-setup.exe")
    );
}

#[test]
fn missing_locations_give_no_findings_and_cancel_stops() {
    let p = Profile::new();
    let none = Locations::default();
    let opts = ScanOptions {
        now: SystemTime::now(),
        cancel: None,
    };
    assert!(scan(&none, &system_layout(), &opts).findings.is_empty());

    let flag = AtomicBool::new(true);
    let opts = ScanOptions {
        now: SystemTime::now(),
        cancel: Some(&flag),
    };
    let report = scan(&p.locations(), &p.layout(), &opts);
    assert!(report.cancelled);
    assert!(report.findings.is_empty());
}

#[test]
fn the_scan_changes_nothing() {
    let p = Profile::new();
    let before = snapshot(&p.home, "before", &p.dir.0);
    let outside = p.dir.0.join("outside");
    let out_before = snapshot(&outside, "out-before", &p.dir.0);
    run(&p);
    assert_unchanged(&before, &snapshot(&p.home, "after", &p.dir.0));
    assert_unchanged(&out_before, &snapshot(&outside, "out-after", &p.dir.0));
}
