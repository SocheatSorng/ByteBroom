//! Phase 2 task 6: red-tier sizes, read-only. Everything runs against a fake "drive" folder in a
//! temp folder and a stand-in Recycle Bin query, never the owner's real drive or Recycle Bin.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::paths::WinPath;
use bytebroom_core::red::{RedFinding, RedSize};
use bytebroom_core::walk::WalkOptions;
use bytebroom_core::win::red::{Listed, RedPlaces, listed_size, red_sizes_at};
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::{CleanDir, assert_unchanged, make_junction, snapshot, write_file};
use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn real(path: &Path) -> WinPath {
    let parsed = WinPath::parse(path.to_str().unwrap()).unwrap();
    open_no_follow(&parsed, Access::Inspect)
        .unwrap()
        .resolved
        .final_path
}

fn size_of(found: &[RedFinding], id: &str) -> RedSize {
    found
        .iter()
        .find(|f| f.rule.id == id)
        .unwrap_or_else(|| panic!("{id} missing"))
        .size
}

fn full(bytes: u64) -> RedSize {
    RedSize::Bytes {
        bytes,
        complete: true,
    }
}

struct FakeDrives {
    dir: CleanDir,
    c: PathBuf,
    d: PathBuf,
}

impl FakeDrives {
    fn new() -> Self {
        let dir = CleanDir::new("red");
        let c = dir.0.join("C");
        let d = dir.0.join("D");
        write_file(&c.join("pagefile.sys"), &[0u8; 1234]);
        write_file(&c.join("hiberfil.sys"), &[0u8; 5678]);
        write_file(
            &c.join("Windows.old").join("Windows").join("x"),
            &[0u8; 100],
        );
        write_file(&c.join("Windows.old").join("Users").join("a"), &[0u8; 200]);
        write_file(&dir.0.join("outside").join("big"), &[0u8; 9999]);
        make_junction(&c.join("Windows.old").join("link"), &dir.0.join("outside"));
        write_file(&d.join("pagefile.sys"), &[0u8; 1000]);
        Self { dir, c, d }
    }

    fn places(&self) -> RedPlaces {
        RedPlaces {
            system_drive: real(&self.c),
            other_drives: vec![real(&self.d)],
        }
    }
}

impl Drop for FakeDrives {
    fn drop(&mut self) {
        let _ = fs::remove_dir(self.c.join("Windows.old").join("link"));
    }
}

#[test]
fn every_red_item_is_sized_or_says_needs_admin() {
    let fake = FakeDrives::new();
    // Hold hiberfil.sys open without sharing, as Windows does: its size still comes from the
    // folder listing, without opening it.
    let _held = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(fake.c.join("hiberfil.sys"))
        .unwrap();
    let found = red_sizes_at(
        &fake.places(),
        &system_layout(),
        &WalkOptions::default(),
        || Some(42),
    );
    assert_eq!(found.len(), 7);
    assert_eq!(size_of(&found, "recycle-bin"), full(42));
    assert_eq!(size_of(&found, "hiberfil"), full(5678));
    assert_eq!(size_of(&found, "pagefile"), full(1234 + 1000));
    // The junction inside Windows.old is not followed.
    assert_eq!(size_of(&found, "windows-old"), full(300));
    for id in ["update-store", "delivery-optimization", "restore-points"] {
        assert_eq!(size_of(&found, id), RedSize::NeedsAdmin, "{id}");
    }
    assert!(found.iter().all(|f| !f.rule.pre_ticked()));
}

#[test]
fn missing_items_say_not_present_and_a_failed_query_says_needs_admin() {
    let dir = CleanDir::new("red-empty");
    let empty = dir.0.join("C");
    fs::create_dir_all(&empty).unwrap();
    let places = RedPlaces {
        system_drive: real(&empty),
        other_drives: Vec::new(),
    };
    let found = red_sizes_at(&places, &system_layout(), &WalkOptions::default(), || None);
    assert_eq!(size_of(&found, "recycle-bin"), RedSize::NeedsAdmin);
    for id in ["hiberfil", "pagefile", "windows-old"] {
        assert_eq!(size_of(&found, id), RedSize::Absent, "{id}");
    }
}

#[test]
fn an_unreadable_part_of_windows_old_marks_the_size_incomplete() {
    let fake = FakeDrives::new();
    let locked = fake.c.join("Windows.old").join("Users");
    let user = std::env::var("USERNAME").unwrap();
    let denied = Command::new("icacls")
        .arg(&locked)
        .args(["/deny", &format!("{user}:(RD)")])
        .output()
        .is_ok_and(|o| o.status.success());
    let found = red_sizes_at(
        &fake.places(),
        &system_layout(),
        &WalkOptions::default(),
        || Some(0),
    );
    let _ = Command::new("icacls")
        .arg(&locked)
        .args(["/remove:d", &user])
        .output();
    assert!(denied, "icacls could not deny the folder");
    assert_eq!(
        size_of(&found, "windows-old"),
        RedSize::Bytes {
            bytes: 100,
            complete: false
        }
    );
}

#[test]
fn listed_size_reads_files_only() {
    let fake = FakeDrives::new();
    assert_eq!(
        listed_size(&real(&fake.c).join("pagefile.sys").unwrap()),
        Listed::Size(1234)
    );
    assert_eq!(
        listed_size(&real(&fake.c).join("Windows.old").unwrap()),
        Listed::Absent
    );
    assert_eq!(
        listed_size(&real(&fake.c).join("nope.sys").unwrap()),
        Listed::Absent
    );
    assert_eq!(
        listed_size(&real(&fake.c).join("no").unwrap().join("such.sys").unwrap()),
        Listed::Absent
    );
}

#[test]
fn measuring_changes_nothing() {
    let fake = FakeDrives::new();
    let before = snapshot(&fake.c, "before", &fake.dir.0);
    red_sizes_at(
        &fake.places(),
        &system_layout(),
        &WalkOptions::default(),
        || Some(0),
    );
    assert_unchanged(&before, &snapshot(&fake.c, "after", &fake.dir.0));
}

/// The red-tier code must not be able to act. Its code lines (comments aside) may not name
/// anything that deletes, moves, recycles, empties or writes.
#[test]
fn the_red_tier_code_cannot_act() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for file in [src.join("red.rs"), src.join("win").join("red.rs")] {
        let text = fs::read_to_string(&file).unwrap();
        for (n, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            let lower = code.to_lowercase();
            for banned in [
                "delete",
                "dispose",
                "remove",
                "access::move",
                "access::delete",
                "recycle::",
                "relocate",
                "engine",
                "emptyrecyclebin",
                "shfileoperation",
                "setfileinformation",
                "createfile",
                "write",
                "fs::",
            ] {
                assert!(
                    !lower.contains(banned),
                    "{}:{}: `{banned}` in {code}",
                    file.display(),
                    n + 1
                );
            }
        }
    }
}
