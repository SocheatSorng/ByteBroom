//! The elevated helper's rules (phase 4): which actions exist, how the helper answers, and
//! which files and folders count as admin-owned. Pure; the Windows side is `win::admin`.
//!
//! The helper (`bytebroom-admin.exe`) runs as administrator, so everything it accepts from the
//! unelevated side is untrusted:
//!
//! - **Arguments:** exactly one action name from [`AdminAction::ALL`], spelled exactly. No
//!   paths, no free text, no options.
//! - **Answer:** only its exit code ([`Exit`]). It writes no file the app reads, and reads no
//!   file the user can write.
//! - **Location:** it runs only from an admin-owned place ([`problem`]): if an ordinary user
//!   could replace the helper, or rename a folder on its path, elevating it would elevate them.

#![forbid(unsafe_code)]

use std::ffi::OsString;

/// One job the helper can do. Each later task adds its action here, and nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAction {
    /// Does nothing, successfully: proves the UAC round trip and the location check.
    Noop,
    /// Makes a restore point (or confirms one from the last 24 hours) and nothing else. Every
    /// system-changing action also makes its own, in the same run (`restore::guarded`).
    RestorePoint,
    /// Turns hibernation off (`powercfg /hibernate off`; owner's decision 4).
    HibernationOff,
    /// Clears the Delivery Optimization cache (`Delete-DeliveryOptimizationCache -Force`).
    DeliveryOptimizationCache,
}

impl AdminAction {
    /// Every action, in a fixed order.
    pub const ALL: [AdminAction; 4] = [
        AdminAction::Noop,
        AdminAction::RestorePoint,
        AdminAction::HibernationOff,
        AdminAction::DeliveryOptimizationCache,
    ];

    /// The command-line word for this action (fixed text, never built from input).
    pub fn arg(self) -> &'static str {
        match self {
            Self::Noop => "noop",
            Self::RestorePoint => "restore-point",
            Self::HibernationOff => "hibernation-off",
            Self::DeliveryOptimizationCache => "delivery-optimization-cache",
        }
    }

    /// The restore point's description, as Windows lists it (fixed text).
    pub fn restore_description(self) -> &'static str {
        match self {
            Self::Noop => "ByteBroom",
            Self::RestorePoint => "ByteBroom: restore point on request",
            Self::HibernationOff => "ByteBroom: before turning hibernation off",
            Self::DeliveryOptimizationCache => {
                "ByteBroom: before clearing the Delivery Optimization cache"
            }
        }
    }
}

/// A Windows program the helper may run: always by full path under System32, never found by
/// a search the user could steer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Program {
    /// `powercfg.exe`.
    Powercfg,
    /// Windows PowerShell 5.1.
    WindowsPowerShell,
}

impl Program {
    /// Its path below System32.
    pub fn below_system32(self) -> &'static str {
        match self {
            Self::Powercfg => "powercfg.exe",
            Self::WindowsPowerShell => r"WindowsPowerShell\v1.0\powershell.exe",
        }
    }
}

/// What the helper runs for an action: a program and fixed arguments, plus environment
/// variables added to [`fixed_environment`] for that program only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The program.
    pub program: Program,
    /// Its arguments, fixed text (System32's path is the only part filled in, from the API).
    pub args: Vec<String>,
    /// Extra environment for the child.
    pub extra_env: Vec<(&'static str, String)>,
}

/// The plan for an action, with `system32` from the Windows API. `None` for actions that run
/// no program, or if `system32` could break the command's quoting. Pure.
pub fn plan(action: AdminAction, system32: &str) -> Option<Plan> {
    match action {
        AdminAction::Noop | AdminAction::RestorePoint => None,
        AdminAction::HibernationOff => Some(Plan {
            program: Program::Powercfg,
            args: vec!["/hibernate".into(), "off".into()],
            extra_env: Vec::new(),
        }),
        AdminAction::DeliveryOptimizationCache => {
            if system32.contains(['\'', '"', '`', '$', ';']) {
                return None;
            }
            let modules = format!(r"{system32}\WindowsPowerShell\v1.0\Modules");
            // The module by its full System32 path and the cmdlet by its module-qualified
            // name: nothing is looked up in a folder the user can write (Documents), and the
            // user's execution policy (HKCU) and module cache are not used.
            let command = format!(
                r"Import-Module -Name '{modules}\DeliveryOptimization\DeliveryOptimization.psd1' -ErrorAction Stop; DeliveryOptimization\Delete-DeliveryOptimizationCache -Force -ErrorAction Stop"
            );
            Some(Plan {
                program: Program::WindowsPowerShell,
                args: [
                    "-NoProfile",
                    "-NonInteractive",
                    "-NoLogo",
                    "-ExecutionPolicy",
                    "RemoteSigned",
                    "-Command",
                ]
                .into_iter()
                .map(String::from)
                .chain([command])
                .collect(),
                extra_env: vec![
                    ("PSModulePath", modules),
                    // Microsoft: an invalid path turns the module analysis cache off.
                    ("PSModuleAnalysisCachePath", "NUL".into()),
                ],
            })
        }
    }
}

/// The helper's answer for a program's exit code (`None`: it couldn't start, or ran too long
/// and was stopped). Pure.
pub fn exit_for_program(code: Option<u32>) -> Exit {
    match code {
        Some(0) => Exit::Done,
        _ => Exit::Failed,
    }
}

/// How long the helper lets an action's program run before stopping it.
pub const PROGRAM_WAIT: std::time::Duration = std::time::Duration::from_secs(180);

/// Parse the helper's arguments (without the program name): exactly one exact action word.
pub fn parse_args(args: &[OsString]) -> Option<AdminAction> {
    let [only] = args else { return None };
    let word = only.to_str()?;
    AdminAction::ALL.into_iter().find(|a| a.arg() == word)
}

/// The helper's answer, as its process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The action was done.
    Done,
    /// The arguments were not exactly one known action; nothing was done.
    BadArgs,
    /// The helper is in a place an ordinary user could change; nothing was done.
    UntrustedLocation,
    /// The helper is not running as administrator; nothing was done.
    NotElevated,
    /// The action was tried and failed.
    Failed,
    /// No restore point: System Restore is turned off. Nothing was changed.
    RestoreOff,
    /// No restore point: System Restore is paused for low disk space. Nothing was changed.
    RestoreLowDisk,
    /// No restore point could be made. Nothing was changed.
    RestoreFailed,
}

impl Exit {
    /// Every answer, for tests and the window's texts.
    pub const ALL: [Exit; 8] = [
        Exit::Done,
        Exit::BadArgs,
        Exit::UntrustedLocation,
        Exit::NotElevated,
        Exit::Failed,
        Exit::RestoreOff,
        Exit::RestoreLowDisk,
        Exit::RestoreFailed,
    ];

    /// The process exit code.
    pub fn code(self) -> u8 {
        match self {
            Self::Done => 0,
            Self::BadArgs => 2,
            Self::UntrustedLocation => 3,
            Self::NotElevated => 4,
            Self::Failed => 5,
            Self::RestoreOff => 6,
            Self::RestoreLowDisk => 7,
            Self::RestoreFailed => 8,
        }
    }

    /// Read an exit code back. Anything unknown (a crash, another program) is a failure.
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Self::Done,
            2 => Self::BadArgs,
            3 => Self::UntrustedLocation,
            4 => Self::NotElevated,
            6 => Self::RestoreOff,
            7 => Self::RestoreLowDisk,
            8 => Self::RestoreFailed,
            _ => Self::Failed,
        }
    }

    /// What it means, in words for the owner.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::BadArgs => "the helper was asked for something it doesn't do; nothing was done",
            Self::UntrustedLocation => {
                "the helper is in a folder ordinary users can change, so it refused; reinstall it with tools/install-helper.ps1"
            }
            Self::NotElevated => "the helper was not given administrator rights; nothing was done",
            Self::Failed => "the helper could not do it",
            Self::RestoreOff => {
                "System Restore is turned off, so no restore point could be made; nothing was changed"
            }
            Self::RestoreLowDisk => {
                "System Restore is paused because the disk is low on space; nothing was changed"
            }
            Self::RestoreFailed => "Windows could not make a restore point; nothing was changed",
        }
    }
}

/// The whole environment the elevated helper keeps (security review of task 2, S2). Elevated,
/// it would otherwise inherit the user's, which the user can set without administrator rights
/// (`HKCU\Environment`): a changed `windir` or `SystemRoot` has steered elevated programs
/// before, and `COMPLUS_*`, `COR_*` or `__COMPAT_LAYER` change how programs load. Everything
/// else is dropped. `windows` and `system32` come from the Windows API, never the environment.
pub fn fixed_environment(windows: &str, system32: &str) -> Vec<(&'static str, String)> {
    let drive = windows.get(..2).unwrap_or("C:").to_string();
    vec![
        ("SystemRoot", windows.to_string()),
        ("windir", windows.to_string()),
        ("SystemDrive", drive),
        ("ComSpec", format!("{system32}\\cmd.exe")),
        (
            "PATH",
            format!("{system32};{windows};{system32}\\Wbem;{system32}\\WindowsPowerShell\\v1.0"),
        ),
        ("PATHEXT", ".COM;.EXE".to_string()),
        ("TEMP", format!("{windows}\\Temp")),
        ("TMP", format!("{windows}\\Temp")),
    ]
}

/// The accounts allowed to own, or write to, the helper and the folders it sits in: SYSTEM,
/// the Administrators group, and TrustedInstaller (Windows' own installer service).
pub const TRUSTED_SIDS: [&str; 3] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// One entry of an access list, as the adapter read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// Who it is for, as a string SID (`S-1-...`); `"?"` when it couldn't be read.
    pub sid: String,
    /// The rights it grants (or denies).
    pub mask: u32,
    /// True for an "allow" entry, false for "deny". An entry of a kind the adapter doesn't know
    /// is read as an allow of every right for `"?"`, so it is never trusted by mistake.
    pub allow: bool,
    /// It applies only to children created later, not to this object.
    pub inherit_only: bool,
}

/// What the adapter read about one file or folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    /// The owner's string SID (an owner can always change the access list).
    pub owner: String,
    /// The access list; `None` is a "null DACL", which lets everyone do everything.
    pub dacl: Option<Vec<Ace>>,
}

/// Where the object is relative to the helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// The helper itself, or the folder it is in: nobody else may change anything in it.
    Own,
    /// A folder above: nobody else may rename, delete or re-permission what is inside, but
    /// adding new items is harmless (e.g. users may create folders at a drive's root).
    Above,
}

// The rights that matter (winnt.h).
const FILE_WRITE_DATA: u32 = 0x2; // = FILE_ADD_FILE on a folder
const FILE_APPEND_DATA: u32 = 0x4; // = FILE_ADD_SUBDIRECTORY on a folder
const FILE_WRITE_EA: u32 = 0x10;
const FILE_DELETE_CHILD: u32 = 0x40;
const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
const DELETE: u32 = 0x1_0000;
const WRITE_DAC: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;
const MAXIMUM_ALLOWED: u32 = 0x200_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// The rights an untrusted account must not have on an object at `place`.
fn dangerous(place: Place) -> u32 {
    let take_over = DELETE | WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD | GENERIC_ALL;
    match place {
        Place::Own => {
            take_over
                | FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES
                | GENERIC_WRITE
                | MAXIMUM_ALLOWED
        }
        Place::Above => take_over | MAXIMUM_ALLOWED,
    }
}

/// Why `sec` (an object at `place`) is not admin-owned, or `None` if it is. Pure.
pub fn problem(sec: &Security, place: Place) -> Option<String> {
    let trusted = |sid: &str| TRUSTED_SIDS.contains(&sid);
    if !trusted(&sec.owner) {
        return Some(format!("it is owned by {}", sec.owner));
    }
    let Some(dacl) = &sec.dacl else {
        return Some("it has no access list, so everyone may change it".into());
    };
    let bad = dangerous(place);
    dacl.iter()
        .find(|a| a.allow && !a.inherit_only && !trusted(&a.sid) && a.mask & bad != 0)
        .map(|a| format!("{} may change it (rights {:#x})", a.sid, a.mask & bad))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM: &str = "S-1-5-18";
    const ADMINS: &str = "S-1-5-32-544";
    const USERS: &str = "S-1-5-32-545";
    const AUTH_USERS: &str = "S-1-5-11";
    const CREATOR_OWNER: &str = "S-1-3-0";
    const ME: &str = "S-1-5-21-1-2-3-1001";
    const FULL: u32 = 0x1F_01FF;
    const READ_EXECUTE: u32 = 0x12_00A9;

    fn ace(sid: &str, mask: u32) -> Ace {
        Ace {
            sid: sid.into(),
            mask,
            allow: true,
            inherit_only: false,
        }
    }

    fn program_files_like() -> Security {
        Security {
            owner: TRUSTED_SIDS[2].into(),
            dacl: Some(vec![
                ace(SYSTEM, FULL),
                ace(ADMINS, FULL),
                ace(TRUSTED_SIDS[2], FULL),
                ace(USERS, READ_EXECUTE),
                Ace {
                    inherit_only: true,
                    ..ace(CREATOR_OWNER, GENERIC_ALL)
                },
            ]),
        }
    }

    #[test]
    fn only_exactly_one_known_word_is_an_action() {
        let args = |list: &[&str]| -> Vec<OsString> { list.iter().map(OsString::from).collect() };
        assert_eq!(parse_args(&args(&["noop"])), Some(AdminAction::Noop));
        for bad in [
            &[][..],
            &["noop", "noop"],
            &["NOOP"],
            &["noop "],
            &["--noop"],
            &["C:\\Windows\\System32\\cmd.exe"],
            &["noop", "C:\\x"],
            &[""],
        ] {
            assert_eq!(parse_args(&args(bad)), None, "{bad:?}");
        }
        for a in AdminAction::ALL {
            assert!(
                a.arg().chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "{a:?}: action words are fixed lower-case text"
            );
            assert_eq!(parse_args(&args(&[a.arg()])), Some(a));
        }
    }

    #[test]
    fn exit_codes_round_trip_and_anything_else_is_a_failure() {
        let mut codes = std::collections::BTreeSet::new();
        for e in Exit::ALL {
            assert_eq!(Exit::from_code(u32::from(e.code())), e);
            assert!(codes.insert(e.code()), "{e:?} shares its code");
            assert!(!e.describe().is_empty());
        }
        for other in [1, 9, 101, 0xC000_0005, u32::MAX] {
            assert_eq!(Exit::from_code(other), Exit::Failed, "{other}");
        }
    }

    #[test]
    fn a_program_files_style_folder_is_admin_owned() {
        assert_eq!(problem(&program_files_like(), Place::Own), None);
        assert_eq!(problem(&program_files_like(), Place::Above), None);
    }

    #[test]
    fn any_write_by_an_ordinary_account_is_refused_on_the_helper_and_its_folder() {
        for right in [
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            FILE_WRITE_EA,
            FILE_DELETE_CHILD,
            FILE_WRITE_ATTRIBUTES,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_ALL,
            GENERIC_WRITE,
            MAXIMUM_ALLOWED,
        ] {
            for who in [USERS, AUTH_USERS, ME, CREATOR_OWNER, "?"] {
                let mut sec = program_files_like();
                if let Some(d) = sec.dacl.as_mut() {
                    d.push(ace(who, READ_EXECUTE | right));
                }
                assert!(problem(&sec, Place::Own).is_some(), "{who} {right:#x}");
            }
        }
    }

    #[test]
    fn above_the_helper_only_rename_delete_and_permission_rights_matter() {
        // A drive root lets users create folders (append) and files (write) at the top.
        let mut root = program_files_like();
        if let Some(d) = root.dacl.as_mut() {
            d.push(ace(AUTH_USERS, FILE_APPEND_DATA | 0x10_0000));
            d.push(ace(USERS, FILE_WRITE_DATA));
        }
        assert_eq!(problem(&root, Place::Above), None);
        for right in [
            DELETE,
            FILE_DELETE_CHILD,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_ALL,
        ] {
            let mut sec = program_files_like();
            if let Some(d) = sec.dacl.as_mut() {
                d.push(ace(USERS, right));
            }
            assert!(problem(&sec, Place::Above).is_some(), "{right:#x}");
        }
    }

    #[test]
    fn inherit_only_and_deny_entries_grant_nothing_here() {
        let mut sec = program_files_like();
        if let Some(d) = sec.dacl.as_mut() {
            d.push(Ace {
                inherit_only: true,
                ..ace(USERS, FULL)
            });
            d.push(Ace {
                allow: false,
                ..ace(ME, FULL)
            });
        }
        assert_eq!(problem(&sec, Place::Own), None);
    }

    #[test]
    fn each_action_runs_exactly_its_fixed_program() {
        const S32: &str = r"C:\Windows\System32";
        assert_eq!(plan(AdminAction::Noop, S32), None);
        assert_eq!(plan(AdminAction::RestorePoint, S32), None);
        assert_eq!(
            plan(AdminAction::HibernationOff, S32),
            Some(Plan {
                program: Program::Powercfg,
                args: vec!["/hibernate".into(), "off".into()],
                extra_env: vec![],
            })
        );
        let cache = plan(AdminAction::DeliveryOptimizationCache, S32).unwrap();
        assert_eq!(cache.program, Program::WindowsPowerShell);
        assert_eq!(
            cache.args,
            [
                "-NoProfile",
                "-NonInteractive",
                "-NoLogo",
                "-ExecutionPolicy",
                "RemoteSigned",
                "-Command",
                r"Import-Module -Name 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\DeliveryOptimization\DeliveryOptimization.psd1' -ErrorAction Stop; DeliveryOptimization\Delete-DeliveryOptimizationCache -Force -ErrorAction Stop",
            ]
        );
        // Pinned files are kept: never -IncludePinnedFiles.
        assert!(!cache.args.iter().any(|a| a.contains("IncludePinnedFiles")));
        assert_eq!(
            cache.extra_env,
            [
                (
                    "PSModulePath",
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules".to_string()
                ),
                ("PSModuleAnalysisCachePath", "NUL".to_string()),
            ]
        );
        // A System32 path that could break the quoting gives no plan at all.
        for bad in [r"C:\Win'dows\System32", r"C:\W$x\System32", r"C:\a;b"] {
            assert_eq!(
                plan(AdminAction::DeliveryOptimizationCache, bad),
                None,
                "{bad}"
            );
        }
        // Only System32 programs, by fixed relative path.
        for p in [Program::Powercfg, Program::WindowsPowerShell] {
            assert!(!p.below_system32().contains(".."));
            assert!(p.below_system32().ends_with(".exe"));
        }
    }

    #[test]
    fn only_a_zero_exit_counts_as_done() {
        assert_eq!(exit_for_program(Some(0)), Exit::Done);
        for code in [Some(1), Some(5), Some(u32::MAX), None] {
            assert_eq!(exit_for_program(code), Exit::Failed, "{code:?}");
        }
    }

    #[test]
    fn the_helpers_environment_is_fixed_and_comes_from_windows_only() {
        let env = fixed_environment("C:\\Windows", "C:\\Windows\\System32");
        let names: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            names,
            [
                "SystemRoot",
                "windir",
                "SystemDrive",
                "ComSpec",
                "PATH",
                "PATHEXT",
                "TEMP",
                "TMP"
            ]
        );
        for (name, value) in &env {
            assert!(
                value.starts_with("C:\\Windows") || *name == "SystemDrive" || *name == "PATHEXT",
                "{name}={value}"
            );
            for bad in ["%", "Users", "AppData"] {
                assert!(!value.contains(bad), "{name}={value}");
            }
        }
        for dropped in [
            "COMPLUS_",
            "COR_",
            "__COMPAT_LAYER",
            "PSModulePath",
            "USERPROFILE",
        ] {
            assert!(!names.iter().any(|n| n.starts_with(dropped)), "{dropped}");
        }
    }

    #[test]
    fn an_untrusted_owner_or_a_null_access_list_is_refused() {
        let mut mine = program_files_like();
        mine.owner = ME.into();
        assert!(problem(&mine, Place::Own).unwrap().contains("owned by"));
        assert!(problem(&mine, Place::Above).is_some());
        let open = Security {
            dacl: None,
            ..program_files_like()
        };
        assert!(problem(&open, Place::Own).is_some());
        assert!(problem(&open, Place::Above).is_some());
    }
}
