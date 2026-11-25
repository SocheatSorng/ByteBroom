//! Shared test fixture: a fake tree in a fresh temp folder, never anywhere else.
//!
//! Layout under `<temp>\bytebroom-tests\<unique>\`:
//!
//! ```text
//! root\                    the allowed root handed to the engine
//!   junk\a.tmp, b.tmp      ordinary files
//!   junk\deep\c.tmp
//!   link\  ──junction──▶   ..\sentinel   (must never be followed)
//!   shared.bin             hard link; its other name is sentinel\shared.bin
//!   locked.tmp             held open without sharing while the fixture lives
//! sentinel\                outside the root; must be unchanged after every test
//!   keep.txt, shared.bin
//! ```
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// The only parent folder tests may create things in.
pub fn tests_base() -> PathBuf {
    std::env::temp_dir().join("bytebroom-tests")
}

/// A new, empty, uniquely named folder under the tests base.
pub fn unique_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = tests_base().join(format!("{tag}-{}-{nanos}-{n}", std::process::id()));
    assert!(
        dir.starts_with(std::env::temp_dir()),
        "test folder escaped temp"
    );
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// The move journal at `path` (inside a test folder), opened the way the app opens it.
pub fn journal_at(path: &Path) -> bytebroom_core::relocate::Journal {
    assert!(
        path.starts_with(tests_base()),
        "journal outside the tests base"
    );
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir).unwrap();
    let dir = bytebroom_core::paths::WinPath::parse(dir.to_str().unwrap()).unwrap();
    let held = bytebroom_core::win::dir::lock_dir(&dir).unwrap();
    let name = path.file_name().unwrap().to_str().unwrap();
    bytebroom_core::relocate::Journal::open(&held, name).unwrap()
}

pub fn write_file(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut f = File::create(path).unwrap();
    f.write_all(bytes).unwrap();
}

/// Create a directory junction (no administrator rights needed).
pub fn make_junction(link: &Path, target: &Path) {
    let status = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap();
    assert!(status.status.success(), "mklink /J failed: {status:?}");
}

pub struct FakeTree {
    pub base: PathBuf,
    pub root: PathBuf,
    pub sentinel: PathBuf,
    locked: Option<File>,
}

impl FakeTree {
    pub fn new() -> Self {
        let base = unique_dir("tree");
        let root = base.join("root");
        let sentinel = base.join("sentinel");
        write_file(&sentinel.join("keep.txt"), b"the sentinel must survive");
        write_file(&sentinel.join("shared.bin"), &[7u8; 4096]);
        write_file(&root.join("junk").join("a.tmp"), &[1u8; 1000]);
        write_file(&root.join("junk").join("b.tmp"), &[2u8; 2000]);
        write_file(&root.join("junk").join("deep").join("c.tmp"), &[3u8; 3000]);
        fs::hard_link(sentinel.join("shared.bin"), root.join("shared.bin")).unwrap();
        make_junction(&root.join("link"), &sentinel);
        write_file(&root.join("locked.tmp"), b"in use");
        let locked = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(root.join("locked.tmp"))
            .unwrap();
        Self {
            base,
            root,
            sentinel,
            locked: Some(locked),
        }
    }

    /// Stop holding `locked.tmp` open.
    pub fn unlock(&mut self) {
        self.locked = None;
    }
}

impl Drop for FakeTree {
    fn drop(&mut self) {
        self.locked = None;
        // Remove the junction itself first, so cleanup can never reach through it.
        let _ = fs::remove_dir(self.root.join("link"));
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// Run `tools/verify-tree.ps1`. Returns (exit code, output).
pub fn verify_tree(args: &[&str]) -> (i32, String) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tools")
        .join("verify-tree.ps1");
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script)
        .args(args)
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    (out.status.code().unwrap_or(-1), text)
}

/// Snapshot `dir` into a JSON file next to the fixture and return its path.
pub fn snapshot(dir: &Path, name: &str, into: &Path) -> PathBuf {
    let out = into.join(format!("{name}.json"));
    let (code, text) = verify_tree(&[
        "-Snapshot",
        "-Path",
        dir.to_str().unwrap(),
        "-Out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "snapshot failed: {text}");
    out
}

/// Assert two snapshots are identical, according to the PowerShell checker.
pub fn assert_unchanged(before: &Path, after: &Path) {
    let (code, text) = verify_tree(&[
        "-Compare",
        "-Before",
        before.to_str().unwrap(),
        "-After",
        after.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "tree changed:\n{text}");
}

/// A unique temp folder that is removed (with everything in it) when dropped.
pub struct CleanDir(pub PathBuf);

impl CleanDir {
    pub fn new(tag: &str) -> Self {
        Self(unique_dir(tag))
    }
}

impl Drop for CleanDir {
    fn drop(&mut self) {
        assert!(
            self.0.starts_with(tests_base()),
            "refusing to clean outside the tests base"
        );
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// SHA-256 of a file according to PowerShell's Get-FileHash (an independent implementation).
pub fn powershell_sha256(file: &Path) -> String {
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!(
            "(Get-FileHash -Algorithm SHA256 -LiteralPath '{}').Hash",
            file.display().to_string().replace('\'', "''")
        ))
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}
