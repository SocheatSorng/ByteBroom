//! The rule catalogue: what ByteBroom looks for, in which tier, and where.
//!
//! Pure data. Every rule names its tier, a plain-English label (shown to the owner and listed in
//! the README, which a docs-drift test checks) and where it looks, relative to the scanner's
//! [`Locations`]. Tests prove that no rule can point into the hard floor or at a "never listed"
//! name. Nothing here acts: the scanner turns rules into findings, and the phase 1 engine checks
//! every item again at the moment of action.

use crate::locations::Locations;
use crate::paths::WinPath;

/// How safe a category is to clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// Windows or the app rebuilds it; pre-ticked.
    Green,
    /// The owner's own data or slow to rebuild; never pre-ticked.
    Amber,
    /// Windows' own areas: sizes only, freed in phase 4 through Windows' own tools.
    Red,
}

impl Tier {
    /// The tier's name as the README writes it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Green => "Green",
            Self::Amber => "Amber",
            Self::Red => "Red",
        }
    }
}

/// The trusted location a rule's folders are relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    /// The user's profile folder.
    Profile,
    /// `AppData\Local`.
    LocalAppData,
    /// The Downloads folder.
    Downloads,
    /// The roots of the other fixed drives (search areas only).
    OtherDrives,
}

/// A folder a rule cleans in, relative to a base. `path` uses `\` between parts, and a part that is
/// exactly `*` stands for any one folder name (a browser profile, for example).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Place {
    /// What the path is relative to.
    pub base: Base,
    /// The path below the base; never empty, so a rule never cleans a base itself.
    pub path: &'static str,
}

/// What the scanner searches for in a search rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Find {
    /// Files at or above [`LARGE_FILE_BYTES`].
    LargeFiles,
    /// Files with identical content; all but the oldest copy are offered.
    Duplicates,
    /// Files with these extensions older than [`OLD_INSTALLER_DAYS`].
    OldInstallers(&'static [&'static str]),
    /// Folders with these names inside a folder that also holds `.git`.
    BuildFolders(&'static [&'static str]),
}

/// A red-tier item: reported by size, never acted on in phase 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedItem {
    /// What is in the Recycle Bin (`SHQueryRecycleBinW`).
    RecycleBin,
    /// `hiberfil.sys` at the Windows drive's root.
    Hiberfil,
    /// `pagefile.sys` at the Windows drive's root.
    Pagefile,
    /// `Windows.old` at the Windows drive's root.
    WindowsOld,
    /// `Windows\SoftwareDistribution\Download`.
    UpdateStore,
    /// Delivery Optimization's cache.
    DeliveryOptimization,
    /// System restore points.
    RestorePoints,
}

/// How a rule looks for what it offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Look {
    /// Everything inside these folders (never the folders themselves).
    Contents(&'static [Place]),
    /// Files directly inside these folders whose names match one of `names` (`*` = any text).
    Files {
        /// The folders.
        places: &'static [Place],
        /// Name patterns, matched ignoring ASCII case.
        names: &'static [&'static str],
    },
    /// Individual items found anywhere in these areas (the walk skips the hard floor and every
    /// "never listed" name).
    Search {
        /// Where to search.
        areas: &'static [Base],
        /// What to search for.
        find: Find,
    },
    /// Size only; nothing can act on it.
    SizeOnly(RedItem),
}

/// One category of things to clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    /// Stable id, for code and settings.
    pub id: &'static str,
    /// Plain-English name shown to the owner and listed in the README.
    pub label: &'static str,
    /// The tier.
    pub tier: Tier,
    /// Where and how it looks.
    pub look: Look,
    /// Items with a file changed within this many hours are not offered (0: no limit).
    pub fresh_hours: u64,
}

impl Rule {
    /// Green findings start ticked; amber and red never do.
    pub fn pre_ticked(&self) -> bool {
        self.tier == Tier::Green
    }
}

/// Owner decision 1: files of this size or more are "large" (500 MB, as Explorer counts them).
pub const LARGE_FILE_BYTES: u64 = 500 * 1024 * 1024;
/// Owner decision 2: installers in Downloads are offered once they are this many days old.
pub const OLD_INSTALLER_DAYS: u64 = 30;
/// Owner decision 4: temp files changed within this many hours are not offered.
pub const FRESH_TEMP_HOURS: u64 = 24;

/// Folders that are never listed, wherever they are (matched ignoring ASCII case).
pub const NEVER_LISTED_FOLDERS: [&str; 2] = [".ssh", ".gnupg"];
/// File names that are never listed: wallets and the browser files that hold logins, cookies,
/// history and settings. Their SQLite `-journal` companions are covered too.
pub const NEVER_LISTED_NAMES: [&str; 8] = [
    "wallet.dat",
    "Cookies",
    "Login Data",
    "Login Data For Account",
    "Web Data",
    "History",
    "Bookmarks",
    "Local State",
];
/// Extensions that are never listed: password vaults, certificates and keys.
pub const NEVER_LISTED_EXTENSIONS: [&str; 7] =
    ["kdbx", "1pif", "agilekeychain", "pfx", "p12", "pem", "key"];

/// True when an item with this name must never appear in any finding (files and folders alike).
pub fn is_never_listed(name: &str) -> bool {
    let bare = name.strip_suffix("-journal").unwrap_or(name);
    NEVER_LISTED_FOLDERS
        .iter()
        .chain(NEVER_LISTED_NAMES.iter())
        .any(|n| bare.eq_ignore_ascii_case(n))
        || name.rsplit_once('.').is_some_and(|(stem, ext)| {
            !stem.is_empty()
                && NEVER_LISTED_EXTENSIONS
                    .iter()
                    .any(|e| ext.eq_ignore_ascii_case(e))
        })
}

/// `name` matches `pattern`, where `*` stands for any text (including none), ignoring ASCII case.
pub fn name_matches(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().map(|c| c.to_ascii_lowercase()).collect();
    let n: Vec<char> = name.chars().map(|c| c.to_ascii_lowercase()).collect();
    // Classic greedy matcher with one backtrack point.
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && p[pi] != '*' && p[pi] == n[ni] {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

const BROWSER_CACHES: [Place; 10] = [
    Place {
        base: Base::LocalAppData,
        path: "BraveSoftware\\Brave-Browser\\User Data\\*\\Cache",
    },
    Place {
        base: Base::LocalAppData,
        path: "BraveSoftware\\Brave-Browser\\User Data\\*\\Code Cache",
    },
    Place {
        base: Base::LocalAppData,
        path: "BraveSoftware\\Brave-Browser\\User Data\\*\\GPUCache",
    },
    Place {
        base: Base::LocalAppData,
        path: "Google\\Chrome\\User Data\\*\\Cache",
    },
    Place {
        base: Base::LocalAppData,
        path: "Google\\Chrome\\User Data\\*\\Code Cache",
    },
    Place {
        base: Base::LocalAppData,
        path: "Google\\Chrome\\User Data\\*\\GPUCache",
    },
    Place {
        base: Base::LocalAppData,
        path: "Microsoft\\Edge\\User Data\\*\\Cache",
    },
    Place {
        base: Base::LocalAppData,
        path: "Microsoft\\Edge\\User Data\\*\\Code Cache",
    },
    Place {
        base: Base::LocalAppData,
        path: "Microsoft\\Edge\\User Data\\*\\GPUCache",
    },
    Place {
        base: Base::LocalAppData,
        path: "Mozilla\\Firefox\\Profiles\\*\\cache2",
    },
];

const DEV_CACHES: [Place; 6] = [
    Place {
        base: Base::LocalAppData,
        path: "npm-cache",
    },
    Place {
        base: Base::LocalAppData,
        path: "pip\\Cache",
    },
    Place {
        base: Base::LocalAppData,
        path: "uv\\cache",
    },
    Place {
        base: Base::Profile,
        path: ".cargo\\registry",
    },
    Place {
        base: Base::Profile,
        path: ".nuget\\packages",
    },
    Place {
        base: Base::Profile,
        path: ".gradle\\caches",
    },
];

const fn local(path: &'static str) -> Place {
    Place {
        base: Base::LocalAppData,
        path,
    }
}

/// Every rule, in the order the owner sees them.
pub static RULES: [Rule; 19] = [
    // Green: Windows or the app rebuilds them.
    Rule {
        id: "user-temp",
        label: "User temp files",
        tier: Tier::Green,
        look: Look::Contents(&[local("Temp")]),
        fresh_hours: FRESH_TEMP_HOURS,
    },
    Rule {
        id: "crash-dumps",
        label: "Crash dumps",
        tier: Tier::Green,
        look: Look::Contents(&[local("CrashDumps")]),
        fresh_hours: 0,
    },
    Rule {
        id: "error-reports",
        label: "Windows error reports",
        tier: Tier::Green,
        look: Look::Contents(&[
            local("Microsoft\\Windows\\WER\\ReportArchive"),
            local("Microsoft\\Windows\\WER\\ReportQueue"),
        ]),
        fresh_hours: 0,
    },
    Rule {
        id: "thumbnail-cache",
        label: "Thumbnail and icon cache",
        tier: Tier::Green,
        look: Look::Files {
            places: &[local("Microsoft\\Windows\\Explorer")],
            names: &["thumbcache_*.db", "iconcache_*.db"],
        },
        fresh_hours: 0,
    },
    Rule {
        id: "internet-cache",
        label: "Internet cache",
        tier: Tier::Green,
        look: Look::Contents(&[local("Microsoft\\Windows\\INetCache")]),
        fresh_hours: 0,
    },
    Rule {
        id: "shader-cache",
        label: "DirectX shader cache",
        tier: Tier::Green,
        look: Look::Contents(&[local("D3DSCache")]),
        fresh_hours: 0,
    },
    Rule {
        id: "browser-caches",
        label: "Browser caches",
        tier: Tier::Green,
        look: Look::Contents(&BROWSER_CACHES),
        fresh_hours: 0,
    },
    // Amber: the owner picks.
    Rule {
        id: "large-files",
        label: "Large files",
        tier: Tier::Amber,
        look: Look::Search {
            areas: &[Base::Profile, Base::Downloads, Base::OtherDrives],
            find: Find::LargeFiles,
        },
        fresh_hours: 0,
    },
    Rule {
        id: "duplicates",
        label: "Duplicates",
        tier: Tier::Amber,
        look: Look::Search {
            areas: &[Base::Profile, Base::Downloads, Base::OtherDrives],
            find: Find::Duplicates,
        },
        fresh_hours: 0,
    },
    Rule {
        id: "old-installers",
        label: "Old installers",
        tier: Tier::Amber,
        look: Look::Search {
            areas: &[Base::Downloads],
            find: Find::OldInstallers(&["exe", "msi", "msix", "zip", "iso"]),
        },
        fresh_hours: 0,
    },
    Rule {
        id: "developer-caches",
        label: "Developer caches",
        tier: Tier::Amber,
        look: Look::Contents(&DEV_CACHES),
        fresh_hours: 0,
    },
    Rule {
        id: "build-folders",
        label: "Build folders in code projects",
        tier: Tier::Amber,
        look: Look::Search {
            areas: &[Base::Profile, Base::OtherDrives],
            find: Find::BuildFolders(&["node_modules", "target", "bin", "obj", "dist"]),
        },
        fresh_hours: 0,
    },
    // Red: sizes only.
    Rule {
        id: "recycle-bin",
        label: "Recycle Bin",
        tier: Tier::Red,
        look: Look::SizeOnly(RedItem::RecycleBin),
        fresh_hours: 0,
    },
    Rule {
        id: "hiberfil",
        label: "Hibernation file",
        tier: Tier::Red,
        look: Look::SizeOnly(RedItem::Hiberfil),
        fresh_hours: 0,
    },
    Rule {
        id: "pagefile",
        label: "Page file",
        tier: Tier::Red,
        look: Look::SizeOnly(RedItem::Pagefile),
        fresh_hours: 0,
    },
    Rule {
        id: "windows-old",
        label: "Previous Windows installation",
        tier: Tier::Red,
        look: Look::SizeOnly(RedItem::WindowsOld),
        fresh_hours: 0,
    },
    Rule {
        id: "update-store",
        label: "Windows Update store",
        tier: Tier::Red,
        look: Look::SizeOnly(RedItem::UpdateStore),
        fresh_hours: 0,
    },
    Rule {
        id: "delivery-optimization",
        label: "Delivery Optimization files",
        tier: Tier::Red,
        look: Look::SizeOnly(RedItem::DeliveryOptimization),
        fresh_hours: 0,
    },
    Rule {
        id: "restore-points",
        label: "Restore points",
        tier: Tier::Red,
        look: Look::SizeOnly(RedItem::RestorePoints),
        fresh_hours: 0,
    },
];

/// The trusted folder a base stands for, if it is scanned. `OtherDrives` is several roots, so it
/// has no single folder.
pub fn base_folder(base: Base, at: &Locations) -> Option<&WinPath> {
    match base {
        Base::Profile => at.profile.as_ref(),
        Base::LocalAppData => at.local_app_data.as_ref(),
        Base::Downloads => at.downloads.as_ref(),
        Base::OtherDrives => None,
    }
}

impl Place {
    /// The path's parts; a `*` part stands for any one folder name.
    pub fn parts(&self) -> impl Iterator<Item = &'static str> {
        self.path.split('\\')
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{SystemLayout, denied_reason};
    use std::collections::HashSet;

    fn p(s: &str) -> WinPath {
        WinPath::parse(s).unwrap_or_else(|e| unreachable!("{s}: {e}"))
    }

    fn layout() -> SystemLayout {
        SystemLayout {
            system_root: p("C:\\Windows"),
            program_files: vec![p("C:\\Program Files"), p("C:\\Program Files (x86)")],
            program_data: p("C:\\ProgramData"),
            profiles_dir: p("C:\\Users"),
            profile_roots: vec![p("C:\\Users\\Ann")],
            extra_denied: Vec::new(),
        }
    }

    fn locations() -> Locations {
        Locations {
            profile: Some(p("C:\\Users\\Ann")),
            local_app_data: Some(p("C:\\Users\\Ann\\AppData\\Local")),
            downloads: Some(p("C:\\Users\\Ann\\Downloads")),
            other_drives: vec![p("D:\\")],
            skipped: Vec::new(),
        }
    }

    /// Every folder a rule cleans in, with each `*` filled by `fill`.
    fn places(rule: &Rule) -> &'static [Place] {
        match rule.look {
            Look::Contents(places) | Look::Files { places, .. } => places,
            Look::Search { .. } | Look::SizeOnly(_) => &[],
        }
    }

    fn resolve(place: &Place, fill: &str) -> WinPath {
        let at = locations();
        let mut path = base_folder(place.base, &at)
            .unwrap_or_else(|| unreachable!("{place:?} has no single base"))
            .clone();
        for part in place.parts() {
            let part = if part == "*" { fill } else { part };
            path = path
                .join(part)
                .unwrap_or_else(|e| unreachable!("{place:?}: {e}"));
        }
        path
    }

    #[test]
    fn every_rule_has_a_unique_id_and_label_and_a_place_to_look() {
        let mut ids = HashSet::new();
        let mut labels = HashSet::new();
        for rule in RULES {
            assert!(ids.insert(rule.id), "id {} repeats", rule.id);
            assert!(labels.insert(rule.label), "label {} repeats", rule.label);
            assert!(!rule.label.trim().is_empty() && !rule.id.is_empty());
            match rule.look {
                Look::Contents(places) => assert!(!places.is_empty(), "{}", rule.id),
                Look::Files { places, names } => {
                    assert!(!places.is_empty() && !names.is_empty(), "{}", rule.id);
                }
                Look::Search { areas, .. } => assert!(!areas.is_empty(), "{}", rule.id),
                Look::SizeOnly(_) => {}
            }
        }
    }

    #[test]
    fn only_green_is_pre_ticked() {
        for rule in RULES {
            assert_eq!(rule.pre_ticked(), rule.tier == Tier::Green, "{}", rule.id);
        }
    }

    #[test]
    fn red_rules_only_report_and_nothing_else_does() {
        for rule in RULES {
            let size_only = matches!(rule.look, Look::SizeOnly(_));
            assert_eq!(size_only, rule.tier == Tier::Red, "{}", rule.id);
        }
    }

    #[test]
    fn each_tier_has_rules_in_the_plan() {
        let count = |t| RULES.iter().filter(|r| r.tier == t).count();
        assert_eq!(count(Tier::Green), 7);
        assert_eq!(count(Tier::Amber), 5);
        assert_eq!(count(Tier::Red), 7);
    }

    #[test]
    fn no_place_is_empty_or_climbs_out_or_names_other_drives() {
        for rule in RULES {
            for place in places(&rule) {
                assert_ne!(place.base, Base::OtherDrives, "{}", rule.id);
                assert!(!place.path.is_empty(), "{}", rule.id);
                for part in place.parts() {
                    assert!(
                        part == "*" || (WinPath::drive_root('C').join(part).is_ok()),
                        "{}: bad part {part:?}",
                        rule.id
                    );
                    assert!(!part.contains('*') || part == "*", "{}", rule.id);
                }
            }
        }
    }

    #[test]
    fn no_rule_points_into_the_hard_floor() {
        // Whatever fills a `*`, the folder stays strictly inside its base and off the floor.
        for fill in ["Default", "Profile 1", "abcd.default-release", "x"] {
            for rule in RULES {
                for place in places(&rule) {
                    let path = resolve(place, fill);
                    let at = locations();
                    let base = base_folder(place.base, &at).unwrap_or_else(|| unreachable!());
                    assert!(path.is_strictly_inside(base), "{}: {path}", rule.id);
                    assert_eq!(denied_reason(&path, &layout()), None, "{}: {path}", rule.id);
                }
            }
        }
    }

    #[test]
    fn no_rule_points_at_a_never_listed_name() {
        let never: Vec<&str> = NEVER_LISTED_FOLDERS
            .iter()
            .chain(NEVER_LISTED_NAMES.iter())
            .copied()
            .chain(["vault.kdbx", "id.pem", "cert.pfx", "Cookies-journal"])
            .collect();
        for rule in RULES {
            for place in places(&rule) {
                for part in place.parts() {
                    assert!(!is_never_listed(part), "{}: {part}", rule.id);
                }
            }
            if let Look::Files { names, .. } = rule.look {
                for pattern in names {
                    for name in &never {
                        assert!(!name_matches(pattern, name), "{pattern} matches {name}");
                    }
                }
            }
            if let Look::Search {
                find: Find::OldInstallers(exts),
                ..
            } = rule.look
            {
                for ext in exts {
                    assert!(!NEVER_LISTED_EXTENSIONS.contains(ext), "{ext}");
                }
            }
        }
    }

    #[test]
    fn browser_rules_reach_only_cache_folders() {
        let allowed = ["Cache", "Code Cache", "GPUCache", "cache2"];
        for place in BROWSER_CACHES {
            let last = place.parts().last().unwrap_or_default();
            assert!(allowed.contains(&last), "{}", place.path);
        }
    }

    #[test]
    fn never_listed_names_are_caught_in_any_case_and_with_journals() {
        for name in [
            ".ssh",
            ".SSH",
            ".gnupg",
            "Cookies",
            "cookies-journal",
            "Login Data",
            "Login Data-journal",
            "Login Data For Account",
            "Web Data",
            "History",
            "Bookmarks",
            "Local State",
            "wallet.dat",
            "Passwords.KDBX",
            "old.1pif",
            "1Password.agilekeychain",
            "me.pfx",
            "me.p12",
            "server.pem",
            "private.key",
        ] {
            assert!(is_never_listed(name), "{name}");
        }
        for name in [
            "Cache",
            "History.txt",
            "keys.txt",
            "key",
            ".key",
            "Cookies.bak.zip",
            "setup.exe",
            "thumbcache_256.db",
            "data_0",
        ] {
            assert!(!is_never_listed(name), "{name}");
        }
    }

    #[test]
    fn name_patterns_match_like_explorer_ignoring_case() {
        assert!(name_matches("thumbcache_*.db", "thumbcache_256.db"));
        assert!(name_matches("thumbcache_*.db", "THUMBCACHE_idx.DB"));
        assert!(name_matches("thumbcache_*.db", "thumbcache_.db"));
        assert!(name_matches("*", "anything"));
        assert!(name_matches("a*b*c", "aXXbYYc"));
        assert!(!name_matches("thumbcache_*.db", "thumbcache_256.db.bak"));
        assert!(!name_matches("thumbcache_*.db", "xthumbcache_256.db"));
        assert!(!name_matches("iconcache_*.db", "thumbcache_1.db"));
        assert!(!name_matches("a*b*c", "aXXbYY"));
    }

    #[test]
    fn only_user_temp_keeps_fresh_files() {
        for rule in RULES.iter() {
            let expected = if rule.id == "user-temp" {
                FRESH_TEMP_HOURS
            } else {
                0
            };
            assert_eq!(rule.fresh_hours, expected, "{}", rule.id);
        }
    }

    #[test]
    fn owner_decisions_are_the_agreed_numbers() {
        assert_eq!(LARGE_FILE_BYTES, 500 * 1024 * 1024);
        assert_eq!(OLD_INSTALLER_DAYS, 30);
        assert_eq!(FRESH_TEMP_HOURS, 24);
    }

    #[test]
    fn other_drives_have_no_single_base_folder() {
        assert_eq!(base_folder(Base::OtherDrives, &locations()), None);
        assert!(base_folder(Base::Profile, &locations()).is_some());
    }
}
