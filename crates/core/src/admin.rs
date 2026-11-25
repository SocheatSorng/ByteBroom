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
}

impl AdminAction {
    /// Every action, in a fixed order.
    pub const ALL: [AdminAction; 1] = [AdminAction::Noop];

    /// The command-line word for this action (fixed text, never built from input).
    pub fn arg(self) -> &'static str {
        match self {
            Self::Noop => "noop",
        }
    }
}

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
}

impl Exit {
    /// The process exit code.
    pub fn code(self) -> u8 {
        match self {
            Self::Done => 0,
            Self::BadArgs => 2,
            Self::UntrustedLocation => 3,
            Self::NotElevated => 4,
            Self::Failed => 5,
        }
    }

    /// Read an exit code back. Anything unknown (a crash, another program) is a failure.
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Self::Done,
            2 => Self::BadArgs,
            3 => Self::UntrustedLocation,
            4 => Self::NotElevated,
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
        }
    }
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
        for e in [
            Exit::Done,
            Exit::BadArgs,
            Exit::UntrustedLocation,
            Exit::NotElevated,
            Exit::Failed,
        ] {
            assert_eq!(Exit::from_code(u32::from(e.code())), e);
        }
        for other in [1, 6, 101, 0xC000_0005, u32::MAX] {
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
