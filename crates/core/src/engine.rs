//! The delete engine: acts only on targets the policy allows, re-checked at the moment of action.
//!
//! Each target is opened without following it, checked against the [`Policy`], and deleted
//! through that same handle. Folders are emptied bottom-up: the folder is checked, its children
//! are handled one by one (each re-opened and re-checked), then the folder is re-opened,
//! re-checked and removed if it is empty. Anything that can't go is skipped and reported; the
//! rest still goes (the owner's decision 3).

use crate::paths::WinPath;
use crate::policy::{Policy, Refusal};
use crate::win::{self, Access, OpenError};
use std::fmt;

/// Folders deeper than this are left alone (and reported), so a pathological tree can't exhaust
/// the stack.
pub const MAX_DEPTH: usize = 256;

/// Why an item was left in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// The policy refused it (link, outside the chosen folders, protected area).
    Refused(Refusal),
    /// Another program holds it open.
    InUse,
    /// It was already gone.
    NotFound,
    /// Windows denied access.
    AccessDenied,
    /// The folder still holds items that were skipped.
    NotEmpty,
    /// Nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// Windows reported a name or path ByteBroom won't act on.
    Unsupported(String),
    /// Deleting failed for another reason.
    Failed(String),
    /// Recycling would turn into a permanent delete (no bin, bin off, too big).
    CannotRecycle(String),
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(r) => write!(f, "{r}"),
            Self::InUse => write!(f, "in use by another program"),
            Self::NotFound => write!(f, "already gone"),
            Self::AccessDenied => write!(f, "access denied"),
            Self::NotEmpty => write!(f, "kept: it still holds items that were skipped"),
            Self::TooDeep => write!(f, "nested too deeply"),
            Self::Unsupported(why) => write!(f, "unsupported: {why}"),
            Self::Failed(why) => write!(f, "could not delete: {why}"),
            Self::CannotRecycle(why) => write!(f, "{why}"),
        }
    }
}

impl From<OpenError> for SkipReason {
    fn from(err: OpenError) -> Self {
        match err {
            OpenError::InUse => Self::InUse,
            OpenError::NotFound => Self::NotFound,
            OpenError::AccessDenied => Self::AccessDenied,
            OpenError::UnsupportedPath(e) => Self::Unsupported(e.to_string()),
            OpenError::Other(e) => Self::Failed(e.to_string()),
        }
    }
}

/// One item that was left in place, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The path as requested.
    pub path: WinPath,
    /// Why it stayed.
    pub reason: SkipReason,
}

/// What one run did.
#[derive(Debug, Default, Clone)]
pub struct Outcome {
    /// Every file and folder that is gone.
    pub removed: Vec<WinPath>,
    /// Everything left in place, with the reason.
    pub skipped: Vec<Skipped>,
    /// Bytes that really came back: a file with other hard links frees nothing.
    pub bytes_freed: u64,
    /// Bytes sent to the Recycle Bin. On the same drive they free nothing until it is emptied.
    pub bytes_recycled: u64,
    /// Items that are gone but need the user's attention (e.g. not found in the bin).
    pub warnings: Vec<Skipped>,
}

impl Outcome {
    fn skip(&mut self, path: &WinPath, reason: SkipReason) {
        self.skipped.push(Skipped {
            path: path.clone(),
            reason,
        });
    }
}

/// Permanently delete each target (files, or folders with everything inside), within `policy`.
pub fn delete_permanently(policy: &Policy, targets: &[WinPath]) -> Outcome {
    let mut out = Outcome::default();
    for target in targets {
        delete_one(policy, target, 0, &mut out);
    }
    out
}

/// Open for delete and check. `None` means the item was skipped (already recorded in `out`).
fn open_checked(policy: &Policy, path: &WinPath, out: &mut Outcome) -> Option<win::Opened> {
    let opened = match win::open_no_follow(path, Access::Delete) {
        Ok(o) => o,
        Err(e) => {
            out.skip(path, e.into());
            return None;
        }
    };
    if let Err(refusal) = policy.check_target(&opened.resolved) {
        out.skip(path, SkipReason::Refused(refusal));
        return None;
    }
    Some(opened)
}

/// Returns true when `path` is gone afterwards.
fn delete_one(policy: &Policy, path: &WinPath, depth: usize, out: &mut Outcome) -> bool {
    if depth > MAX_DEPTH {
        out.skip(path, SkipReason::TooDeep);
        return false;
    }
    let Some(opened) = open_checked(policy, path, out) else {
        return false;
    };

    if !opened.is_directory {
        let freed = if opened.link_count > 1 {
            0
        } else {
            opened.size
        };
        let real = opened.resolved.final_path.clone();
        return match win::delete_by_handle(opened) {
            Ok(()) => {
                out.bytes_freed += freed;
                out.removed.push(real);
                true
            }
            Err(e) => {
                out.skip(path, SkipReason::Failed(e.to_string()));
                false
            }
        };
    }

    // A folder: work from the checked real path, and don't hold its handle while recursing.
    let real = opened.resolved.final_path.clone();
    drop(opened);
    let names = match win::list_children(&real) {
        Ok(n) => n,
        Err(e) => {
            out.skip(path, SkipReason::Failed(e.to_string()));
            return false;
        }
    };
    let mut all_gone = true;
    for name in names {
        match real.join(&name) {
            Ok(child) => all_gone &= delete_one(policy, &child, depth + 1, out),
            Err(e) => {
                // A child whose name ByteBroom won't handle (e.g. ends with a dot): leave it.
                all_gone = false;
                out.skip(&real, SkipReason::Unsupported(format!("{name:?}: {e}")));
            }
        }
    }
    if !all_gone {
        out.skip(path, SkipReason::NotEmpty);
        return false;
    }

    // Re-open and re-check before removing the (now empty) folder.
    let Some(again) = open_checked(policy, path, out) else {
        return false;
    };
    if again.resolved.final_path != real {
        out.skip(
            path,
            SkipReason::Unsupported("the folder changed while it was being emptied".into()),
        );
        return false;
    }
    match win::delete_by_handle(again) {
        Ok(()) => {
            out.removed.push(real);
            true
        }
        Err(e) if e.raw_os_error() == Some(145) => {
            // ERROR_DIR_NOT_EMPTY: something new appeared meanwhile.
            out.skip(path, SkipReason::NotEmpty);
            false
        }
        Err(e) => {
            out.skip(path, SkipReason::Failed(e.to_string()));
            false
        }
    }
}
