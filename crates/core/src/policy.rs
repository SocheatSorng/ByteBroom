//! The hard floor: which paths the engine may act on at all.
//!
//! Pure: callers pass facts that the Windows adapter resolved from an open handle. Every check
//! here can only refuse; nothing in this module widens what is allowed.

use crate::paths::{WinPath, eq_ignore_case as part_eq_ignore_case};
use std::fmt;

/// Names directly under any drive root that are never acted on, whatever the UI asks.
/// Red-tier space (pagefile, restore points, the Recycle Bin store) is freed only through
/// Windows' own tools (phase 4).
pub const DENIED_AT_DRIVE_ROOT: [&str; 14] = [
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "System Volume Information",
    "$Recycle.Bin",
    "Boot",
    "EFI",
    "Recovery",
    "bootmgr",
    "BOOTNXT",
    "$WinREAgent",
    "$Windows.~BT",
    "$Windows.~WS",
    "Config.msi",
];

/// Folders at the root of every drive **other than** the running Windows' drive that are never
/// acted on, whole subtrees: another Windows installation's own folders. (`Windows.old` is left
/// out so the red tier can still measure it; nothing ever acts on it as a file.)
pub const SYSTEM_FOLDERS_ON_OTHER_DRIVES: [&str; 4] = [
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
];

/// Folders under **every** profile root that are never acted on, whole subtrees: Windows' key
/// and credential stores (losing DPAPI's `Protect` keys loses every secret they encrypt), the
/// per-user Startup folder (a file placed there runs at sign-in), and SSH/GPG keys. Paths assume
/// the standard `AppData` layout; a redirected AppData is not covered here.
pub const SENSITIVE_IN_PROFILE: [&str; 10] = [
    "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "AppData\\Roaming\\Microsoft\\Protect",
    "AppData\\Roaming\\Microsoft\\Credentials",
    "AppData\\Local\\Microsoft\\Credentials",
    "AppData\\Roaming\\Microsoft\\Crypto",
    "AppData\\Roaming\\Microsoft\\SystemCertificates",
    "AppData\\Roaming\\Microsoft\\Vault",
    "AppData\\Local\\Microsoft\\Vault",
    ".ssh",
    ".gnupg",
];

/// Folders under `ProgramData` that are never acted on, whole subtrees. `Microsoft` holds the
/// machine keys (`Crypto`), the all-users Startup folder and Defender's data.
pub const SENSITIVE_IN_PROGRAM_DATA: [&str; 1] = ["Microsoft"];

/// `path` is `base\rel` or inside it, ignoring case. Compares parts in place (no allocation),
/// because the walker asks this for every entry it lists.
fn inside_relative(path: &WinPath, base: &WinPath, rel: &str) -> bool {
    let rel_count = rel.split('\\').count();
    let (parts, base_parts) = (path.parts(), base.parts());
    path.drive() == base.drive()
        && parts.len() >= base_parts.len() + rel_count
        && path.is_at_or_inside_ignore_case(base)
        && parts[base_parts.len()..]
            .iter()
            .zip(rel.split('\\'))
            .all(|(a, b)| part_eq_ignore_case(a, b))
}

/// Some part of `path` is a "never listed" name (e.g. `.ssh`, `Login Data`, `x.kdbx`). The
/// scanner never enters or reports these; the engine refuses to act on them or anything inside.
fn has_never_listed_part(path: &WinPath) -> bool {
    path.parts()
        .iter()
        .any(|p| crate::rules::is_never_listed(p))
}

/// Where Windows keeps its own folders on this PC. Built from the real environment by the
/// Windows adapter, and from fake values in tests.
#[derive(Debug, Clone)]
pub struct SystemLayout {
    /// `%SystemRoot%`, e.g. `C:\Windows`.
    pub system_root: WinPath,
    /// `Program Files` and `Program Files (x86)`.
    pub program_files: Vec<WinPath>,
    /// `%ProgramData%`.
    pub program_data: WinPath,
    /// The folder that holds the user profiles, e.g. `C:\Users`.
    pub profiles_dir: WinPath,
    /// Every user profile folder, e.g. `C:\Users\Ann`.
    pub profile_roots: Vec<WinPath>,
    /// Further protected areas, whole subtrees (e.g. an environment variable that disagrees with
    /// the Windows API). Only ever adds protection.
    pub extra_denied: Vec<WinPath>,
}

impl SystemLayout {
    /// `%SystemRoot%\Temp`, the one place under Windows that holds deletable files.
    fn system_temp(&self) -> Option<WinPath> {
        self.system_root.join("Temp").ok()
    }
}

/// Why the engine refused to act on a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The target (or an allowed root) is a symlink, junction or other reparse point.
    ReparsePoint,
    /// The target's real path is not strictly inside any allowed root.
    OutsideAllowedRoots,
    /// The target is in an area on the hard floor (see the spec's deny list).
    DeniedArea(String),
    /// An allowed root is too broad or sits in a denied area.
    BadRoot(String),
    /// The target is, or is inside, a "never listed" item: a key, password vault, wallet or
    /// browser login file (see `rules::is_never_listed`).
    NeverListed,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReparsePoint => write!(f, "links and junctions are never followed or deleted"),
            Self::OutsideAllowedRoots => write!(f, "outside the folders chosen for this clean"),
            Self::DeniedArea(why) => write!(f, "protected Windows area: {why}"),
            Self::BadRoot(why) => write!(f, "this folder can't be cleaned as a whole: {why}"),
            Self::NeverListed => write!(
                f,
                "keys, password vaults, wallets and browser logins are never touched"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// What the Windows adapter found out about a target from its open handle.
#[derive(Debug, Clone)]
pub struct ResolvedPath {
    /// The real path Windows reports for the handle (`GetFinalPathNameByHandle`).
    pub final_path: WinPath,
    /// The target itself is a reparse point (opened without following it).
    pub is_reparse_point: bool,
}

/// Why `path` is on the hard floor, or `None` if it is not.
pub fn denied_reason(path: &WinPath, layout: &SystemLayout) -> Option<String> {
    if path.is_drive_root() {
        return Some("a whole drive".into());
    }
    if let Some(first) = path.parts().first()
        && DENIED_AT_DRIVE_ROOT
            .iter()
            .any(|name| first.eq_ignore_ascii_case(name))
    {
        return Some(format!("{first} at the drive root"));
    }
    // Another Windows (dual boot, an old disk) keeps its system folders at its own drive's root,
    // which the running Windows' layout knows nothing about.
    if path.drive() != layout.system_root.drive()
        && let Some(first) = path.parts().first()
        && SYSTEM_FOLDERS_ON_OTHER_DRIVES
            .iter()
            .any(|name| first.eq_ignore_ascii_case(name))
    {
        return Some(format!("{first} on another drive"));
    }
    if path.is_at_or_inside_ignore_case(&layout.system_root) {
        let in_temp = layout.system_temp().is_some_and(|temp| {
            path.is_at_or_inside_ignore_case(&temp) && !path.eq_ignore_case(&temp)
        });
        if !in_temp {
            return Some("Windows system folder".into());
        }
    }
    if layout
        .program_files
        .iter()
        .any(|pf| path.is_at_or_inside_ignore_case(pf))
    {
        return Some("Program Files".into());
    }
    if layout
        .extra_denied
        .iter()
        .any(|area| path.is_at_or_inside_ignore_case(area))
    {
        return Some("a protected Windows folder".into());
    }
    if SENSITIVE_IN_PROGRAM_DATA
        .iter()
        .any(|rel| inside_relative(path, &layout.program_data, rel))
    {
        return Some("a protected Windows folder in ProgramData".into());
    }
    if layout.profile_roots.iter().any(|profile| {
        SENSITIVE_IN_PROFILE
            .iter()
            .any(|rel| inside_relative(path, profile, rel))
    }) {
        return Some("a key, credential or startup folder".into());
    }
    if path.eq_ignore_case(&layout.program_data) {
        return Some("ProgramData itself".into());
    }
    if path.eq_ignore_case(&layout.profiles_dir) {
        return Some("the folder that holds every user profile".into());
    }
    if layout.profile_roots.iter().any(|p| path.eq_ignore_case(p)) {
        return Some("a user profile folder itself".into());
    }
    None
}

/// The folders one clean may act inside, checked against the hard floor.
#[derive(Debug, Clone)]
pub struct Policy {
    roots: Vec<WinPath>,
    layout: SystemLayout,
}

impl Policy {
    /// Build a policy. Every root must be a real path resolved by Windows, not a reparse point,
    /// and not too broad (a drive root, a profile root, ...) or inside a denied area.
    pub fn new(roots: Vec<ResolvedPath>, layout: SystemLayout) -> Result<Self, Refusal> {
        let mut checked = Vec::with_capacity(roots.len());
        for root in roots {
            if root.is_reparse_point {
                return Err(Refusal::ReparsePoint);
            }
            // %SystemRoot%\Temp is the one denied folder whose contents may be cleaned.
            let is_system_temp = layout
                .system_temp()
                .is_some_and(|temp| root.final_path.eq_ignore_case(&temp));
            if !is_system_temp && let Some(why) = denied_reason(&root.final_path, &layout) {
                return Err(Refusal::BadRoot(why));
            }
            checked.push(root.final_path);
        }
        Ok(Self {
            roots: checked,
            layout,
        })
    }

    /// The allowed roots.
    pub fn roots(&self) -> &[WinPath] {
        &self.roots
    }

    /// Where Windows keeps its own folders (the hard floor this policy enforces).
    pub fn layout(&self) -> &SystemLayout {
        &self.layout
    }

    /// May files be created in this folder (to restore a moved file)? It must be a real folder
    /// that is an allowed root or inside one, and not on the hard floor.
    pub fn check_container(&self, folder: &ResolvedPath) -> Result<(), Refusal> {
        if folder.is_reparse_point {
            return Err(Refusal::ReparsePoint);
        }
        if has_never_listed_part(&folder.final_path) {
            return Err(Refusal::NeverListed);
        }
        let is_root = self.roots.contains(&folder.final_path);
        if !is_root
            && !self
                .roots
                .iter()
                .any(|root| folder.final_path.is_strictly_inside(root))
        {
            return Err(Refusal::OutsideAllowedRoots);
        }
        // Roots were checked when the policy was built (including %SystemRoot%\Temp).
        if !is_root && let Some(why) = denied_reason(&folder.final_path, &self.layout) {
            return Err(Refusal::DeniedArea(why));
        }
        Ok(())
    }

    /// May the engine act on this target? Called again right before every action.
    pub fn check_target(&self, target: &ResolvedPath) -> Result<(), Refusal> {
        if target.is_reparse_point {
            return Err(Refusal::ReparsePoint);
        }
        // Checked here, where every delete, recycle and move passes, so emptying a folder the
        // scan offered (say Temp\extract1) can never take a vault or key found inside it.
        if has_never_listed_part(&target.final_path) {
            return Err(Refusal::NeverListed);
        }
        if !self
            .roots
            .iter()
            .any(|root| target.final_path.is_strictly_inside(root))
        {
            return Err(Refusal::OutsideAllowedRoots);
        }
        if let Some(why) = denied_reason(&target.final_path, &self.layout) {
            return Err(Refusal::DeniedArea(why));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> WinPath {
        WinPath::parse(s).unwrap()
    }

    fn resolved(s: &str) -> ResolvedPath {
        ResolvedPath {
            final_path: p(s),
            is_reparse_point: false,
        }
    }

    fn layout() -> SystemLayout {
        SystemLayout {
            system_root: p("C:\\Windows"),
            program_files: vec![p("C:\\Program Files"), p("C:\\Program Files (x86)")],
            program_data: p("C:\\ProgramData"),
            profiles_dir: p("C:\\Users"),
            profile_roots: vec![p("C:\\Users\\Ann"), p("C:\\Users\\Public")],
            extra_denied: vec![p("D:\\WinOld")],
        }
    }

    fn policy(roots: &[&str]) -> Policy {
        Policy::new(roots.iter().map(|r| resolved(r)).collect(), layout()).unwrap()
    }

    #[test]
    fn allows_only_strictly_inside_a_root() {
        let pol = policy(&["C:\\Users\\Ann\\AppData\\Local\\Temp"]);
        assert_eq!(
            pol.check_target(&resolved("C:\\Users\\Ann\\AppData\\Local\\Temp\\a.tmp")),
            Ok(())
        );
        assert_eq!(
            pol.check_target(&resolved("C:\\Users\\Ann\\AppData\\Local\\Temp")),
            Err(Refusal::OutsideAllowedRoots)
        );
        assert_eq!(
            pol.check_target(&resolved("C:\\Users\\Ann\\Documents\\cv.docx")),
            Err(Refusal::OutsideAllowedRoots)
        );
    }

    #[test]
    fn refuses_reparse_points_as_targets_and_roots() {
        let pol = policy(&["D:\\Scratch"]);
        let link = ResolvedPath {
            final_path: p("D:\\Scratch\\link"),
            is_reparse_point: true,
        };
        assert_eq!(pol.check_target(&link), Err(Refusal::ReparsePoint));
        let root_link = ResolvedPath {
            final_path: p("D:\\Scratch"),
            is_reparse_point: true,
        };
        assert!(matches!(
            Policy::new(vec![root_link], layout()),
            Err(Refusal::ReparsePoint)
        ));
    }

    #[test]
    fn refuses_roots_that_are_too_broad() {
        for root in [
            "C:\\",
            "D:\\",
            "C:\\Windows",
            "C:\\windows\\System32",
            "C:\\Windows\\Temp2",
            "C:\\Program Files",
            "c:\\program files (x86)\\App",
            "C:\\ProgramData",
            "C:\\Users",
            "C:\\Users\\Ann",
            "C:\\USERS\\PUBLIC",
            "C:\\System Volume Information",
            "E:\\$Recycle.Bin\\S-1-5-21",
        ] {
            let got = Policy::new(vec![resolved(root)], layout());
            assert!(
                matches!(got, Err(Refusal::BadRoot(_))),
                "{root} was accepted as a root"
            );
        }
    }

    #[test]
    fn system_temp_contents_are_the_only_windows_exception() {
        let pol = policy(&["C:\\Windows\\Temp"]);
        assert_eq!(
            pol.check_target(&resolved("C:\\Windows\\Temp\\setup.log")),
            Ok(())
        );
        assert!(denied_reason(&p("C:\\Windows\\Temp"), &layout()).is_some());
        assert!(denied_reason(&p("C:\\Windows\\Temp2\\x"), &layout()).is_some());
    }

    #[test]
    fn hard_floor_holds_even_inside_an_allowed_root() {
        // A root on another drive can't reach that drive's protected root entries,
        // and a root can't make a profile folder itself deletable.
        let pol = policy(&["C:\\Users\\Ann\\AppData", "C:\\ProgramData\\App"]);
        assert_eq!(
            pol.check_target(&resolved("C:\\Users\\Ann\\AppData\\x")),
            Ok(())
        );
        assert_eq!(
            pol.check_target(&resolved("C:\\ProgramData\\App\\cache\\x")),
            Ok(())
        );
        for name in DENIED_AT_DRIVE_ROOT {
            let path = p(&format!("D:\\{name}"));
            assert!(denied_reason(&path, &layout()).is_some(), "{name}");
            let inside = path.join("x").unwrap();
            assert!(denied_reason(&inside, &layout()).is_some(), "{name}\\x");
        }
    }

    #[test]
    fn refusal_messages_are_plain_english() {
        assert_eq!(
            Refusal::ReparsePoint.to_string(),
            "links and junctions are never followed or deleted"
        );
        assert_eq!(
            Refusal::OutsideAllowedRoots.to_string(),
            "outside the folders chosen for this clean"
        );
    }

    #[test]
    fn never_listed_items_and_everything_inside_them_are_refused() {
        let pol = policy(&["C:\\Users\\Ann\\AppData\\Local\\Temp"]);
        let t = "C:\\Users\\Ann\\AppData\\Local\\Temp\\extract1";
        for bad in [
            "vault.kdbx",
            "Login Data",
            "Cookies-journal",
            "id.PEM",
            ".ssh",
            ".ssh\\id_rsa",
            "wallet.dat",
            "keys.agilekeychain\\data",
        ]
        .into_iter()
        .map(String::from)
        // Every entry of every list (the phase 3 additions included).
        .chain(
            crate::rules::NEVER_LISTED_FOLDERS
                .iter()
                .chain(crate::rules::NEVER_LISTED_NAMES.iter())
                .map(|n| n.to_string()),
        )
        .chain(
            crate::rules::NEVER_LISTED_EXTENSIONS
                .iter()
                .map(|e| format!("x.{e}")),
        ) {
            let path = format!("{t}\\{bad}");
            assert_eq!(
                pol.check_target(&resolved(&path)),
                Err(Refusal::NeverListed),
                "{path}"
            );
            assert_eq!(
                pol.check_container(&resolved(&path)),
                Err(Refusal::NeverListed),
                "{path}"
            );
        }
        // Their neighbours are fine.
        for ok in ["a.tmp", "History.txt", "key", "ssh"] {
            assert_eq!(
                pol.check_target(&resolved(&format!("{t}\\{ok}"))),
                Ok(()),
                "{ok}"
            );
        }
        assert!(Refusal::NeverListed.to_string().contains("never touched"));
    }

    #[test]
    fn key_credential_and_startup_folders_are_on_the_floor_in_every_profile() {
        for profile in ["C:\\Users\\Ann", "C:\\Users\\Public"] {
            for rel in SENSITIVE_IN_PROFILE {
                let area = p(&format!("{profile}\\{rel}"));
                let inside = area.join("x").unwrap();
                let shouted = p(&area.to_string().to_uppercase());
                for path in [&area, &inside, &shouted] {
                    assert!(denied_reason(path, &layout()).is_some(), "{path}");
                    let got = Policy::new(vec![resolved(&path.to_string())], layout());
                    assert!(matches!(got, Err(Refusal::BadRoot(_))), "{path}: {got:?}");
                }
                // A broader root is allowed, but nothing inside the protected folder is. (.ssh
                // and .gnupg sit directly in the profile, which can't be a root at all.)
                if rel.starts_with("AppData\\") {
                    let pol = policy(&[&format!("{profile}\\AppData")]);
                    assert!(matches!(
                        pol.check_target(&resolved(&inside.to_string())),
                        Err(Refusal::DeniedArea(_))
                    ));
                    assert!(matches!(
                        pol.check_container(&resolved(&area.to_string())),
                        Err(Refusal::DeniedArea(_))
                    ));
                }
            }
        }
    }

    #[test]
    fn program_data_microsoft_is_on_the_floor_but_other_apps_are_not() {
        for bad in [
            "C:\\ProgramData\\Microsoft",
            "C:\\ProgramData\\microsoft\\Crypto\\RSA",
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        ] {
            assert!(denied_reason(&p(bad), &layout()).is_some(), "{bad}");
        }
        assert_eq!(
            denied_reason(&p("C:\\ProgramData\\SomeApp\\cache"), &layout()),
            None
        );
        assert_eq!(
            denied_reason(&p("C:\\ProgramData\\MicrosoftEdgeCache"), &layout()),
            None
        );
    }

    #[test]
    fn another_windows_on_another_drive_is_protected() {
        for bad in [
            "D:\\Windows\\System32\\x.dll",
            "D:\\windows",
            "E:\\Program Files\\App\\a.exe",
            "D:\\Program Files (x86)\\x",
            "D:\\ProgramData\\Microsoft\\x",
        ] {
            assert!(denied_reason(&p(bad), &layout()).is_some(), "{bad}");
        }
        // The running Windows' drive keeps its own rules: ProgramData's apps are not floor.
        assert_eq!(
            denied_reason(&p("C:\\ProgramData\\SomeApp\\cache"), &layout()),
            None
        );
        // Ordinary folders on other drives, and Windows.old (measured by the red tier), are not.
        for ok in [
            "D:\\Games\\big.iso",
            "D:\\Windows.old\\x",
            "D:\\Data\\Windows\\x",
        ] {
            assert_eq!(denied_reason(&p(ok), &layout()), None, "{ok}");
        }
    }

    #[test]
    fn neighbours_of_protected_folders_are_not_caught() {
        for ok in [
            "C:\\Users\\Ann\\AppData\\Roaming\\Microsoft\\ProtectX",
            "C:\\Users\\Ann\\AppData\\Local\\Microsoft\\Windows\\INetCache\\x",
            "C:\\Users\\Ann\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\x",
            "C:\\Users\\Bob\\AppData\\Roaming\\Microsoft\\Protect",
            "D:\\Users\\Ann\\.ssh",
        ] {
            assert_eq!(denied_reason(&p(ok), &layout()), None, "{ok}");
        }
    }
}
