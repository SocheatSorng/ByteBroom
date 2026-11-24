//! Phase 2 task 1: the scanner's locations, built from a fake profile in a temp folder and checked
//! on disk without following links. Only reads; nothing is created outside the temp folder.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::locations::{Candidate, Locations, Sources, Which};
use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::SystemLayout;
use bytebroom_core::win::locations::{locations, locations_from};
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::{CleanDir, make_junction};
use std::fs;
use std::path::Path;

/// Windows' own spelling of a folder that exists.
fn real(path: &Path) -> WinPath {
    let parsed = WinPath::parse(path.to_str().unwrap()).unwrap();
    open_no_follow(&parsed, Access::Inspect)
        .unwrap()
        .resolved
        .final_path
}

struct FakeProfile {
    _dir: CleanDir,
    profile: WinPath,
    local: WinPath,
    downloads: WinPath,
    layout: SystemLayout,
}

impl FakeProfile {
    fn new() -> Self {
        let dir = CleanDir::new("locations");
        let base = dir.0.join("Users").join("Ann");
        fs::create_dir_all(base.join("AppData").join("Local")).unwrap();
        fs::create_dir_all(base.join("Downloads")).unwrap();
        let profile = real(&base);
        let local = real(&base.join("AppData").join("Local"));
        let downloads = real(&base.join("Downloads"));
        let mut layout = system_layout();
        layout.profile_roots.push(profile.clone());
        Self {
            _dir: dir,
            profile,
            local,
            downloads,
            layout,
        }
    }

    fn base(&self) -> std::path::PathBuf {
        self._dir.0.join("Users").join("Ann")
    }

    fn sources(&self) -> Sources {
        Sources {
            profile: Candidate {
                api: Some(self.profile.clone()),
                env: Some(self.profile.clone()),
            },
            local_app_data: Candidate {
                api: Some(self.local.clone()),
                env: Some(self.local.clone()),
            },
            downloads: Candidate {
                api: Some(self.downloads.clone()),
                env: None,
            },
            fixed_drives: Vec::new(),
        }
    }
}

#[test]
fn a_fake_profile_gives_every_location() {
    let fake = FakeProfile::new();
    let l = locations_from(&fake.sources(), &fake.layout);
    assert_eq!(l.profile.as_ref(), Some(&fake.profile));
    assert_eq!(l.local_app_data.as_ref(), Some(&fake.local));
    assert_eq!(l.downloads.as_ref(), Some(&fake.downloads));
    assert!(l.skipped.is_empty(), "{:?}", l.skipped);
}

#[test]
fn a_junction_as_a_location_is_not_scanned() {
    let fake = FakeProfile::new();
    let elsewhere = fake._dir.0.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let link = fake.base().join("LinkedDownloads");
    make_junction(&link, &elsewhere);
    let mut s = fake.sources();
    s.downloads.api = Some(WinPath::parse(link.to_str().unwrap()).unwrap());
    let l = locations_from(&s, &fake.layout);
    assert_eq!(l.downloads, None);
    let why = l.skipped.iter().find(|x| x.which == Which::Downloads);
    assert!(why.is_some_and(|w| w.why.contains("link")), "{why:?}");
    fs::remove_dir(&link).unwrap();
}

#[test]
fn a_location_reached_through_a_junction_is_not_scanned() {
    let fake = FakeProfile::new();
    let hop = fake._dir.0.join("hop");
    make_junction(&hop, &fake.base());
    let mut s = fake.sources();
    let via = WinPath::parse(hop.join("Downloads").to_str().unwrap()).unwrap();
    s.downloads.api = Some(via);
    let l = locations_from(&s, &fake.layout);
    assert_eq!(l.downloads, None);
    fs::remove_dir(&hop).unwrap();
}

#[test]
fn a_missing_folder_or_a_file_is_not_scanned() {
    let fake = FakeProfile::new();
    let file = fake.base().join("Downloads").join("not-a-folder.txt");
    fs::write(&file, b"x").unwrap();

    let mut s = fake.sources();
    s.downloads.api = Some(WinPath::parse(file.to_str().unwrap()).unwrap());
    assert_eq!(locations_from(&s, &fake.layout).downloads, None);

    let mut s = fake.sources();
    let gone = fake.base().join("NoSuchFolder");
    s.downloads.api = Some(WinPath::parse(gone.to_str().unwrap()).unwrap());
    assert_eq!(locations_from(&s, &fake.layout).downloads, None);
}

#[test]
fn a_junctioned_profile_drops_local_app_data_with_it() {
    let fake = FakeProfile::new();
    let hop = fake._dir.0.join("AnnLink");
    make_junction(&hop, &fake.base());
    let hop_path = WinPath::parse(hop.to_str().unwrap()).unwrap();
    let mut layout = fake.layout.clone();
    layout.profile_roots.push(hop_path.clone());
    let mut s = fake.sources();
    s.profile = Candidate {
        api: Some(hop_path.clone()),
        env: None,
    };
    let local = WinPath::parse(hop.join("AppData").join("Local").to_str().unwrap()).unwrap();
    s.local_app_data = Candidate {
        api: Some(local),
        env: None,
    };
    let l = locations_from(&s, &layout);
    assert_eq!(l.profile, None);
    assert_eq!(l.local_app_data, None);
    fs::remove_dir(&hop).unwrap();
}

#[test]
fn the_wrong_case_is_respelled_as_windows_reports_it() {
    let fake = FakeProfile::new();
    let mut s = fake.sources();
    let shouted = WinPath::parse(&fake.downloads.to_string().to_uppercase()).unwrap();
    s.downloads.api = Some(shouted);
    let l: Locations = locations_from(&s, &fake.layout);
    assert_eq!(l.downloads.as_ref(), Some(&fake.downloads));
}

/// Read-only look at this PC: the real locations exist and none is a link. It lists folders only
/// through Windows' API and opens them for attributes; it changes nothing.
#[test]
fn the_real_locations_are_folders_inside_a_listed_profile() {
    let layout = system_layout();
    let l = locations(&layout);
    let profile = l.profile.as_ref().expect("the real profile is trusted");
    assert!(
        layout
            .profile_roots
            .iter()
            .any(|r| r.eq_ignore_case(profile))
    );
    let local = l.local_app_data.as_ref().expect("LocalAppData is trusted");
    assert!(local.is_strictly_inside(profile));
    assert!(l.other_drives.iter().all(WinPath::is_drive_root));
    assert!(
        !l.other_drives
            .iter()
            .any(|d| d.drive() == layout.system_root.drive())
    );
}
