//! Phase 2 task 3: the walker, on fake trees in a temp folder. It only reads; an independent
//! PowerShell snapshot proves nothing changed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::paths::WinPath;
use bytebroom_core::walk::{Item, Step, WalkOptions, WalkSummary};
use bytebroom_core::win::walk::walk;
use bytebroom_core::win::{Access, OpenError, open_no_follow, system_layout};
use common::{CleanDir, assert_unchanged, make_junction, snapshot, write_file};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

fn real(path: &Path) -> WinPath {
    let parsed = WinPath::parse(path.to_str().unwrap()).unwrap();
    open_no_follow(&parsed, Access::Inspect)
        .unwrap()
        .resolved
        .final_path
}

/// ```text
/// base\
///   root\
///     a.bin (1000)
///     sub\b.bin (2000)
///     sub\deep\d1\d2\c.bin (3000)
///     hard1.bin (4096)  ═ hard link ═  sub\hard2.bin
///     link\ ──junction──▶ ..\outside
///     .ssh\id_rsa, Login Data, vault.kdbx, sub\Cookies-journal   (never listed)
///     odd.  (a name ending in a dot, made through \\?\)
///     locked\x.bin  (listing denied to this user, when ACLs allow it)
///   outside\big.bin (50000)   must never be reported
/// ```
struct Tree {
    dir: CleanDir,
    root: PathBuf,
    locked: PathBuf,
    locked_ok: bool,
}

impl Tree {
    fn new() -> Self {
        let dir = CleanDir::new("walk");
        let root = dir.0.join("root");
        let outside = dir.0.join("outside");
        write_file(&outside.join("big.bin"), &[9u8; 50_000]);
        write_file(&root.join("a.bin"), &[1u8; 1000]);
        write_file(&root.join("sub").join("b.bin"), &[2u8; 2000]);
        let deep = root.join("sub").join("deep").join("d1").join("d2");
        write_file(&deep.join("c.bin"), &[3u8; 3000]);
        write_file(&root.join("hard1.bin"), &[4u8; 4096]);
        fs::hard_link(root.join("hard1.bin"), root.join("sub").join("hard2.bin")).unwrap();
        make_junction(&root.join("link"), &outside);
        write_file(&root.join(".ssh").join("id_rsa"), &[5u8; 700]);
        write_file(&root.join("Login Data"), &[6u8; 800]);
        write_file(&root.join("vault.kdbx"), &[7u8; 900]);
        write_file(&root.join("sub").join("Cookies-journal"), &[8u8; 100]);
        for name in never_listed_files() {
            write_file(&root.join("more").join(name), &[8u8; 10]);
        }
        fs::write(
            format!("\\\\?\\{}\\odd.", root.display()),
            [0u8; 10].as_slice(),
        )
        .unwrap();
        let locked = root.join("locked");
        write_file(&locked.join("x.bin"), &[1u8; 10]);
        let user = std::env::var("USERNAME").unwrap();
        let locked_ok = Command::new("icacls")
            .arg(&locked)
            .args(["/deny", &format!("{user}:(RD)")])
            .output()
            .is_ok_and(|o| o.status.success());
        Self {
            dir,
            root,
            locked,
            locked_ok,
        }
    }

    /// Remove the two decoys PowerShell's snapshot can't read (the denied folder and the name
    /// ending in a dot), so the independent snapshot covers everything else.
    fn make_snapshot_friendly(&mut self) {
        self.unlock();
        fs::remove_dir_all(&self.locked).unwrap();
        fs::remove_file(format!("\\\\?\\{}\\odd.", self.root.display())).unwrap();
    }

    fn unlock(&self) {
        if let Ok(user) = std::env::var("USERNAME") {
            let _ = Command::new("icacls")
                .arg(&self.locked)
                .args(["/remove:d", &user])
                .output();
        }
    }

    fn root(&self) -> WinPath {
        real(&self.root)
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        self.unlock();
        let _ = fs::remove_dir(self.root.join("link"));
        let _ = fs::remove_file(format!("\\\\?\\{}\\odd.", self.root.display()));
    }
}

/// Walk and collect every reported file and folder, relative to the root.
fn collect(
    root: &WinPath,
    opts: &WalkOptions,
) -> (BTreeMap<String, u64>, Vec<String>, WalkSummary) {
    let prefix = root.to_string().len() + 1;
    let mut files = BTreeMap::new();
    let mut folders = Vec::new();
    let summary = walk(root, &system_layout(), opts, |item| {
        match item {
            Item::File(f) => {
                let rel = f.path.to_string()[prefix..].to_string();
                assert!(f.path.is_strictly_inside(root), "{rel} escaped the root");
                files.insert(rel, f.len);
            }
            Item::Folder { path, .. } => {
                assert!(path.is_strictly_inside(root));
                folders.push(path.to_string()[prefix..].to_string());
            }
            Item::Incomplete { .. } => {}
        }
        Step::Enter
    })
    .unwrap();
    (files, folders, summary)
}

/// The folders the walk reports as not fully seen, relative to the root.
fn incomplete_folders(root: &WinPath, opts: &WalkOptions) -> Vec<String> {
    let prefix = root.to_string().len() + 1;
    let mut out = Vec::new();
    walk(root, &system_layout(), opts, |item| {
        if let Item::Incomplete { path, .. } = item {
            out.push(path.to_string()[prefix..].to_string());
        }
        Step::Enter
    })
    .unwrap();
    out
}

#[test]
fn reports_every_real_file_with_its_length() {
    let tree = Tree::new();
    let (files, folders, s) = collect(&tree.root(), &WalkOptions::default());
    let expected: BTreeMap<String, u64> = [
        ("a.bin", 1000),
        ("hard1.bin", 4096),
        ("sub\\b.bin", 2000),
        ("sub\\hard2.bin", 4096),
        ("sub\\deep\\d1\\d2\\c.bin", 3000),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    assert_eq!(files, expected);
    for f in [
        "sub",
        "sub\\deep",
        "sub\\deep\\d1",
        "sub\\deep\\d1\\d2",
        "locked",
    ] {
        assert!(folders.contains(&f.to_string()), "{f} missing: {folders:?}");
    }
    assert_eq!(s.files, 5);
    assert!(!s.cancelled);
}

#[test]
fn a_hard_linked_file_is_counted_once() {
    let tree = Tree::new();
    let mut repeats = 0;
    let s = walk(
        &tree.root(),
        &system_layout(),
        &WalkOptions::default(),
        |item| {
            if let Item::File(f) = item
                && f.repeat
            {
                repeats += 1;
                assert_eq!(f.len, 4096);
            }
            Step::Enter
        },
    )
    .unwrap();
    assert_eq!(repeats, 1);
    assert_eq!(s.hard_link_repeats, 1);
    assert_eq!(s.bytes, 1000 + 2000 + 3000 + 4096);
}

#[test]
fn never_enters_or_reports_the_junction() {
    let tree = Tree::new();
    let (files, folders, s) = collect(&tree.root(), &WalkOptions::default());
    assert!(
        !files
            .keys()
            .any(|k| k.contains("big") || k.starts_with("link"))
    );
    assert!(!folders.contains(&"link".to_string()));
    assert_eq!(s.links_skipped, 1);
}

#[test]
fn never_lists_keys_vaults_or_browser_logins() {
    let tree = Tree::new();
    let (files, folders, s) = collect(&tree.root(), &WalkOptions::default());
    for k in files.keys().chain(folders.iter()) {
        let lower = k.to_lowercase();
        for bad in [".ssh", "id_rsa", "login data", "kdbx", "cookies"] {
            assert!(!lower.contains(bad), "{k} was listed");
        }
        assert!(!k.starts_with("more\\"), "{k} was listed");
    }
    // .ssh (not entered, so id_rsa is never seen), Login Data, vault.kdbx, Cookies-journal,
    // and one file per entry of the never-listed lists in `more\`.
    assert_eq!(s.protected_skipped, 4 + never_listed_files().len() as u64);
}

/// One file name for every entry of the never-listed name and extension lists.
fn never_listed_files() -> Vec<String> {
    use bytebroom_core::rules::{NEVER_LISTED_EXTENSIONS, NEVER_LISTED_NAMES};
    NEVER_LISTED_NAMES
        .iter()
        .map(|n| n.to_string())
        .chain(NEVER_LISTED_EXTENSIONS.iter().map(|e| format!("x.{e}")))
        .collect()
}

#[test]
fn odd_names_are_counted_not_fatal() {
    let tree = Tree::new();
    let (files, _, s) = collect(&tree.root(), &WalkOptions::default());
    assert!(!files.keys().any(|k| k.starts_with("odd")));
    assert_eq!(s.odd_names, 1);
}

#[test]
fn an_unreadable_folder_is_counted_and_the_walk_goes_on() {
    let tree = Tree::new();
    if !tree.locked_ok {
        eprintln!("icacls could not deny listing here; skipping the access-denied check");
        return;
    }
    let (files, _, s) = collect(&tree.root(), &WalkOptions::default());
    assert!(!files.contains_key("locked\\x.bin"));
    assert_eq!(s.unreadable, 1);
    assert_eq!(s.files, 5);
    // The visitor is told which folder was not seen, so its item's sizes and dates are known
    // to be incomplete.
    assert_eq!(
        incomplete_folders(&tree.root(), &WalkOptions::default()),
        vec!["locked".to_string()]
    );
}

#[test]
fn stops_at_the_depth_limit() {
    let tree = Tree::new();
    let opts = WalkOptions {
        max_depth: 2,
        ..WalkOptions::default()
    };
    let (files, folders, s) = collect(&tree.root(), &opts);
    assert!(folders.contains(&"sub\\deep".to_string()));
    assert!(!folders.contains(&"sub\\deep\\d1".to_string()));
    assert!(!files.keys().any(|k| k.contains("c.bin")));
    assert!(files.contains_key("sub\\b.bin"));
    assert_eq!(s.depth_limited, 1);
    let mut gaps = incomplete_folders(&tree.root(), &opts);
    gaps.retain(|g| g != "locked"); // denied to this user when icacls allowed it
    assert_eq!(gaps, vec!["sub\\deep".to_string()]);
}

#[test]
fn the_visitor_can_skip_a_folder() {
    let tree = Tree::new();
    let mut seen = Vec::new();
    walk(
        &tree.root(),
        &system_layout(),
        &WalkOptions::default(),
        |item| {
            match item {
                Item::Folder { path, .. } if path.parts().last().is_some_and(|n| n == "sub") => {
                    return Step::Skip;
                }
                Item::File(f) => seen.push(f.path.parts().last().cloned().unwrap()),
                Item::Folder { .. } | Item::Incomplete { .. } => {}
            }
            Step::Enter
        },
    )
    .unwrap();
    seen.sort();
    assert_eq!(seen, vec!["a.bin", "hard1.bin"]);
}

#[test]
fn cancelling_stops_the_walk() {
    let tree = Tree::new();
    let flag = AtomicBool::new(true);
    let opts = WalkOptions {
        cancel: Some(&flag),
        ..WalkOptions::default()
    };
    let (files, _, s) = collect(&tree.root(), &opts);
    assert!(s.cancelled);
    assert!(files.is_empty());

    // Cancelled from inside, after the first folder: nothing below it is listed.
    let flag = AtomicBool::new(false);
    let opts = WalkOptions {
        cancel: Some(&flag),
        ..WalkOptions::default()
    };
    let mut files_after = 0;
    let s = walk(&tree.root(), &system_layout(), &opts, |item| {
        if let Item::File(_) = item {
            files_after += 1;
        }
        flag.store(true, Ordering::Relaxed);
        Step::Enter
    })
    .unwrap();
    assert!(s.cancelled);
    assert!(s.files < 5, "{s:?}");
}

#[test]
fn a_link_or_a_file_as_the_root_is_refused() {
    let tree = Tree::new();
    let link = WinPath::parse(tree.root.join("link").to_str().unwrap()).unwrap();
    let got = walk(&link, &system_layout(), &WalkOptions::default(), |_| {
        Step::Enter
    });
    assert!(got.is_err(), "{got:?}");
    let file = tree.root().join("a.bin").unwrap();
    assert!(
        walk(&file, &system_layout(), &WalkOptions::default(), |_| {
            Step::Enter
        })
        .is_err()
    );
    let gone = tree.root().join("nope").unwrap();
    assert!(matches!(
        walk(&gone, &system_layout(), &WalkOptions::default(), |_| {
            Step::Enter
        }),
        Err(OpenError::NotFound)
    ));
}

#[test]
fn the_walk_changes_nothing() {
    let mut tree = Tree::new();
    tree.make_snapshot_friendly();
    let before = snapshot(&tree.root, "before", &tree.dir.0);
    let outside_before = snapshot(&tree.dir.0.join("outside"), "outside-before", &tree.dir.0);
    collect(&tree.root(), &WalkOptions::default());
    let after = snapshot(&tree.root, "after", &tree.dir.0);
    let outside_after = snapshot(&tree.dir.0.join("outside"), "outside-after", &tree.dir.0);
    assert_unchanged(&before, &after);
    assert_unchanged(&outside_before, &outside_after);
}
