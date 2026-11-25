//! Where the scanner looks: the user's profile, LocalAppData, Downloads and the other fixed drives.
//!
//! Pure: the Windows adapter (`win::locations`) gathers the candidate values and checks them on
//! disk; tests pass values for a fake profile in a temp folder. Every rule here can only drop a
//! location, never add one, so a steered value makes ByteBroom scan less, not more.
//!
//! The trust rule matches phase 1's layout: the Windows API is the source, and the environment is
//! only a cross-check. When the two disagree, something changed one of them (any program running
//! as the user can), so the location is not trusted and is not scanned at all.

use crate::paths::WinPath;
use crate::policy::{SystemLayout, denied_reason};

/// One location as Windows' API and the environment report it.
#[derive(Debug, Clone, Default)]
pub struct Candidate {
    /// From `SHGetKnownFolderPath`.
    pub api: Option<WinPath>,
    /// From the matching environment variable, if there is one.
    pub env: Option<WinPath>,
}

/// Everything the scanner's locations are built from.
#[derive(Debug, Clone, Default)]
pub struct Sources {
    /// `FOLDERID_Profile` and `%USERPROFILE%`.
    pub profile: Candidate,
    /// `FOLDERID_LocalAppData` and `%LOCALAPPDATA%`.
    pub local_app_data: Candidate,
    /// `FOLDERID_Downloads` (it has no environment variable).
    pub downloads: Candidate,
    /// Letters of the fixed (non-removable, non-network) drives.
    pub fixed_drives: Vec<char>,
}

/// Which location was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    /// The user's profile folder.
    Profile,
    /// `AppData\Local`.
    LocalAppData,
    /// The Downloads folder.
    Downloads,
}

impl Which {
    /// A plain-English name for messages.
    pub fn label(self) -> &'static str {
        match self {
            Self::Profile => "your profile folder",
            Self::LocalAppData => "AppData\\Local",
            Self::Downloads => "Downloads",
        }
    }
}

/// A location that is not scanned, and why. Shown to the owner, so a scan never quietly covers
/// less than it seems to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The location.
    pub which: Which,
    /// Why it is not scanned.
    pub why: String,
}

/// The folders the scanner's rules look in. A `None` location is not scanned; `skipped` says why.
#[derive(Debug, Clone, Default)]
pub struct Locations {
    /// The user's profile folder, e.g. `C:\Users\Ann`.
    pub profile: Option<WinPath>,
    /// `AppData\Local`, always strictly inside the profile.
    pub local_app_data: Option<WinPath>,
    /// The Downloads folder (it may live on another drive).
    pub downloads: Option<WinPath>,
    /// Roots of the fixed drives other than the Windows drive and the profile's drive, e.g. `D:\`.
    pub other_drives: Vec<WinPath>,
    /// Locations that are not scanned, and why.
    pub skipped: Vec<Skipped>,
}

/// Record that `which` is skipped; returns `None` so callers can write `return skip(...)`.
fn skip(list: &mut Vec<Skipped>, which: Which, why: impl Into<String>) -> Option<WinPath> {
    list.push(Skipped {
        which,
        why: why.into(),
    });
    None
}

/// The API value, if the environment (when it has a value) agrees with it.
fn pick(which: Which, c: &Candidate, skipped: &mut Vec<Skipped>) -> Option<WinPath> {
    let Some(api) = c.api.clone() else {
        return skip(skipped, which, "Windows did not report where it is");
    };
    match &c.env {
        Some(env) if !env.eq_ignore_case(&api) => skip(
            skipped,
            which,
            "Windows and the environment disagree about where it is",
        ),
        _ => Some(api),
    }
}

/// Why `path` may not be a scan location: a whole drive, or anywhere on the hard floor. The
/// profile root itself is on the floor as a delete target, so `is_profile` lets that one through.
fn floor_reason(path: &WinPath, layout: &SystemLayout, is_profile: bool) -> Option<String> {
    let why = denied_reason(path, layout)?;
    let own_profile_root =
        is_profile && layout.profile_roots.iter().any(|r| r.eq_ignore_case(path));
    (!own_profile_root).then_some(why)
}

impl Locations {
    /// Build the locations from `sources`, dropping every value that is not trusted.
    pub fn resolve(sources: &Sources, layout: &SystemLayout) -> Self {
        let mut skipped = Vec::new();

        let profile = pick(Which::Profile, &sources.profile, &mut skipped).and_then(|p| {
            if !layout.profile_roots.iter().any(|r| r.eq_ignore_case(&p)) {
                return skip(
                    &mut skipped,
                    Which::Profile,
                    "it is not one of the profiles Windows lists",
                );
            }
            match floor_reason(&p, layout, true) {
                Some(why) => skip(&mut skipped, Which::Profile, why),
                None => Some(p),
            }
        });

        let local = pick(Which::LocalAppData, &sources.local_app_data, &mut skipped);
        let local_app_data = match (local, &profile) {
            (None, _) => None,
            (Some(_), None) => skip(
                &mut skipped,
                Which::LocalAppData,
                "your profile folder is not scanned",
            ),
            (Some(l), Some(p)) if !l.is_strictly_inside(p) => skip(
                &mut skipped,
                Which::LocalAppData,
                "it is not inside your profile folder",
            ),
            (Some(l), Some(_)) => match floor_reason(&l, layout, false) {
                Some(why) => skip(&mut skipped, Which::LocalAppData, why),
                None => Some(l),
            },
        };

        // Downloads has no environment cross-check, and its HKCU value can be changed by any program
        // running as the user. Accept it only inside the owner's own profile, or on another drive
        // outside every profile, so it can never point at another user's files.
        let downloads = pick(Which::Downloads, &sources.downloads, &mut skipped).and_then(|d| {
            if let Some(why) = floor_reason(&d, layout, false) {
                return skip(&mut skipped, Which::Downloads, why);
            }
            // Ignoring case: the on-disk check respells it as Windows does afterwards.
            let in_own_profile = profile
                .as_ref()
                .is_some_and(|p| d.is_at_or_inside_ignore_case(p) && !d.eq_ignore_case(p));
            let in_any_profile = layout
                .profile_roots
                .iter()
                .any(|r| d.is_at_or_inside_ignore_case(r));
            let own_drive = profile
                .as_ref()
                .map_or(layout.system_root.drive(), WinPath::drive);
            if in_own_profile || (!in_any_profile && d.drive() != own_drive) {
                Some(d)
            } else {
                skip(
                    &mut skipped,
                    Which::Downloads,
                    "it is neither inside your profile folder nor on another drive",
                )
            }
        });

        let system_drive = layout.system_root.drive();
        let home_drive = profile.as_ref().map_or(system_drive, WinPath::drive);
        let mut other_drives: Vec<WinPath> = Vec::new();
        for letter in sources
            .fixed_drives
            .iter()
            .filter(|c| c.is_ascii_alphabetic())
        {
            let root = WinPath::drive_root(*letter);
            if root.drive() != system_drive
                && root.drive() != home_drive
                && !other_drives.contains(&root)
            {
                other_drives.push(root);
            }
        }

        Self {
            profile,
            local_app_data,
            downloads,
            other_drives,
            skipped,
        }
    }

    /// Stop scanning `which`, with a reason (used by the Windows adapter's on-disk check).
    /// Dropping the profile also drops LocalAppData, which is trusted only inside it.
    pub fn drop_location(&mut self, which: Which, why: impl Into<String>) {
        let slot = match which {
            Which::Profile => &mut self.profile,
            Which::LocalAppData => &mut self.local_app_data,
            Which::Downloads => &mut self.downloads,
        };
        if slot.take().is_some() {
            skip(&mut self.skipped, which, why);
        }
        if which == Which::Profile {
            self.drop_location(Which::LocalAppData, "your profile folder is not scanned");
        }
    }

    /// The locations that are scanned, with which one each is.
    pub fn scanned(&self) -> Vec<(Which, &WinPath)> {
        [
            (Which::Profile, &self.profile),
            (Which::LocalAppData, &self.local_app_data),
            (Which::Downloads, &self.downloads),
        ]
        .into_iter()
        .filter_map(|(w, p)| p.as_ref().map(|p| (w, p)))
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> WinPath {
        WinPath::parse(s).unwrap_or_else(|e| unreachable!("{s}: {e}"))
    }

    fn layout() -> SystemLayout {
        SystemLayout {
            system_root: p("C:\\Windows"),
            program_files: vec![p("C:\\Program Files"), p("C:\\Program Files (x86)")],
            program_data: p("C:\\ProgramData"),
            profiles_dir: p("C:\\Users"),
            profile_roots: vec![p("C:\\Users\\Ann"), p("C:\\Users\\Bob")],
            extra_denied: vec![p("D:\\Windows")],
        }
    }

    fn both(s: &str) -> Candidate {
        Candidate {
            api: Some(p(s)),
            env: Some(p(s)),
        }
    }

    fn api_only(s: &str) -> Candidate {
        Candidate {
            api: Some(p(s)),
            env: None,
        }
    }

    fn normal() -> Sources {
        Sources {
            profile: both("C:\\Users\\Ann"),
            local_app_data: both("C:\\Users\\Ann\\AppData\\Local"),
            downloads: api_only("C:\\Users\\Ann\\Downloads"),
            fixed_drives: vec!['C', 'D', 'E'],
        }
    }

    fn skipped_for(l: &Locations, which: Which) -> Option<&str> {
        l.skipped
            .iter()
            .find(|s| s.which == which)
            .map(|s| s.why.as_str())
    }

    #[test]
    fn agreeing_values_are_all_used() {
        let l = Locations::resolve(&normal(), &layout());
        assert_eq!(l.profile, Some(p("C:\\Users\\Ann")));
        assert_eq!(l.local_app_data, Some(p("C:\\Users\\Ann\\AppData\\Local")));
        assert_eq!(l.downloads, Some(p("C:\\Users\\Ann\\Downloads")));
        assert_eq!(l.other_drives, vec![p("D:\\"), p("E:\\")]);
        assert!(l.skipped.is_empty(), "{:?}", l.skipped);
        assert_eq!(l.scanned().len(), 3);
    }

    #[test]
    fn env_differing_only_in_case_still_agrees() {
        let mut s = normal();
        s.local_app_data.env = Some(p("c:\\users\\ann\\appdata\\LOCAL"));
        let l = Locations::resolve(&s, &layout());
        assert!(l.local_app_data.is_some());
    }

    #[test]
    fn env_that_disagrees_with_the_api_drops_the_location() {
        let mut s = normal();
        s.local_app_data.env = Some(p("D:\\Projects"));
        let l = Locations::resolve(&s, &layout());
        assert_eq!(l.local_app_data, None);
        assert!(skipped_for(&l, Which::LocalAppData).is_some_and(|w| w.contains("disagree")));
        // Neither value is used: the environment never becomes a scan location.
        assert!(!l.scanned().iter().any(|(_, x)| x.drive() == 'D'));
    }

    #[test]
    fn a_disagreeing_profile_drops_local_app_data_too() {
        let mut s = normal();
        s.profile.env = Some(p("C:\\Users\\Bob"));
        let l = Locations::resolve(&s, &layout());
        assert_eq!(l.profile, None);
        assert_eq!(l.local_app_data, None);
        assert!(skipped_for(&l, Which::LocalAppData).is_some());
        // Downloads inside a profile that is not trusted is not trusted either (security review
        // S6); on another drive it would stand on its own.
        assert_eq!(l.downloads, None);
        let mut s = normal();
        s.profile.env = Some(p("C:\\Users\\Bob"));
        s.downloads = api_only("D:\\Downloads");
        assert!(Locations::resolve(&s, &layout()).downloads.is_some());
    }

    #[test]
    fn the_environment_alone_is_never_enough() {
        let mut s = normal();
        s.local_app_data.api = None;
        let l = Locations::resolve(&s, &layout());
        assert_eq!(l.local_app_data, None);
        assert!(skipped_for(&l, Which::LocalAppData).is_some());
    }

    #[test]
    fn a_profile_windows_does_not_list_is_refused() {
        let mut s = normal();
        s.profile = both("C:\\Users\\Mallory");
        s.local_app_data = both("C:\\Users\\Mallory\\AppData\\Local");
        let l = Locations::resolve(&s, &layout());
        assert_eq!(l.profile, None);
        assert_eq!(l.local_app_data, None);
    }

    #[test]
    fn local_app_data_outside_the_profile_is_refused() {
        for elsewhere in [
            "D:\\Projects",
            "C:\\Users\\Bob\\AppData\\Local",
            "C:\\Users\\Ann",
        ] {
            let mut s = normal();
            s.local_app_data = both(elsewhere);
            let l = Locations::resolve(&s, &layout());
            assert_eq!(l.local_app_data, None, "{elsewhere}");
            assert!(l.profile.is_some());
        }
    }

    #[test]
    fn no_location_may_sit_on_the_hard_floor() {
        for bad in [
            "C:\\",
            "D:\\",
            "C:\\Windows",
            "C:\\Windows\\System32",
            "C:\\Program Files\\App",
            "C:\\ProgramData",
            "C:\\Users",
            "C:\\Users\\Bob",
            "D:\\Windows\\x",
            "C:\\pagefile.sys",
            "E:\\System Volume Information\\x",
        ] {
            let mut s = normal();
            s.downloads = api_only(bad);
            let l = Locations::resolve(&s, &layout());
            assert_eq!(l.downloads, None, "downloads at {bad}");
            assert!(skipped_for(&l, Which::Downloads).is_some(), "{bad}");

            // Bob is a listed profile, so it is a valid profile (just not a valid Downloads).
            if bad != "C:\\Users\\Bob" {
                let mut s = normal();
                s.profile = both(bad);
                let l = Locations::resolve(&s, &layout());
                assert_eq!(l.profile, None, "profile at {bad}");
            }
        }
    }

    #[test]
    fn downloads_may_live_on_another_drive() {
        let mut s = normal();
        s.downloads = api_only("D:\\Downloads");
        let l = Locations::resolve(&s, &layout());
        assert_eq!(l.downloads, Some(p("D:\\Downloads")));
    }

    #[test]
    fn downloads_never_points_at_another_users_files() {
        // Security review S6: the HKCU value can be steered.
        for bad in [
            "C:\\Users\\Bob\\Downloads",
            "C:\\Users\\Bob\\Documents\\x",
            "C:\\Data\\Downloads",
        ] {
            let mut s = normal();
            s.downloads = api_only(bad);
            let l = Locations::resolve(&s, &layout());
            assert_eq!(l.downloads, None, "{bad}");
            assert!(
                skipped_for(&l, Which::Downloads).is_some_and(|w| w.contains("profile")),
                "{bad}"
            );
        }
        // Redirected inside the owner's own profile (e.g. OneDrive) is fine.
        let mut s = normal();
        s.downloads = api_only("C:\\Users\\Ann\\OneDrive\\Downloads");
        assert!(Locations::resolve(&s, &layout()).downloads.is_some());
    }

    #[test]
    fn other_drives_leave_out_the_windows_and_profile_drives_and_repeats() {
        let mut s = normal();
        s.profile = both("C:\\Users\\Ann");
        s.fixed_drives = vec!['c', 'd', 'D', '1', 'f'];
        let l = Locations::resolve(&s, &layout());
        assert_eq!(l.other_drives, vec![p("D:\\"), p("F:\\")]);
    }

    #[test]
    fn dropping_a_location_records_why_and_takes_local_app_data_with_the_profile() {
        let mut l = Locations::resolve(&normal(), &layout());
        l.drop_location(Which::Downloads, "it is a link");
        assert_eq!(l.downloads, None);
        assert_eq!(skipped_for(&l, Which::Downloads), Some("it is a link"));

        l.drop_location(Which::Profile, "it is a link");
        assert_eq!(l.profile, None);
        assert_eq!(l.local_app_data, None);
        assert!(l.scanned().is_empty());
        // Dropping twice records nothing new.
        let before = l.skipped.len();
        l.drop_location(Which::Profile, "again");
        assert_eq!(l.skipped.len(), before);
    }

    #[test]
    fn every_location_says_which_it_is() {
        for w in [Which::Profile, Which::LocalAppData, Which::Downloads] {
            assert!(!w.label().is_empty());
        }
    }
}
