//! Sending items to the Recycle Bin, without ever letting Windows silently delete them for good.
//!
//! Windows turns "recycle" into a permanent delete, without asking when no UI is shown, when the
//! drive has no Recycle Bin (subst, network, most USB drives), when the bin is turned off for the
//! drive, or when the item is bigger than the bin's maximum size. [`preflight`] refuses all of
//! those up front; after recycling, the engine also checks that the bin grew by the item's size.

use crate::engine::{Outcome, SkipReason, Skipped, Target, not_as_expected};
use crate::paths::WinPath;
use crate::policy::Policy;
use crate::scan::FileIdentity;
use crate::win::dir::{LockedDir, lock_dir};
use crate::win::{self, Access};
use std::collections::HashMap;
use std::fmt;

/// What Windows says about one drive's Recycle Bin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinFacts {
    /// A fixed, local disk (not network, removable or RAM disk).
    pub fixed_local: bool,
    /// The letter is a `subst` alias for a folder.
    pub subst: bool,
    /// Windows reports a Recycle Bin for the drive.
    pub bin_present: bool,
    /// "Don't move files to the Recycle Bin" is on for this drive.
    pub nuke_on_delete: bool,
    /// The bin's maximum size for this drive, in bytes.
    pub max_bytes: u64,
}

/// Why an item can't be recycled safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecycleRefusal {
    /// The drive has no Recycle Bin; Windows would delete for good.
    NoBin,
    /// The Recycle Bin is turned off for this drive.
    BinTurnedOff,
    /// Bigger than the bin can hold; Windows would delete for good.
    TooBig {
        /// The item's size.
        item: u64,
        /// The bin's maximum size.
        max: u64,
    },
}

impl fmt::Display for RecycleRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBin => write!(
                f,
                "this drive has no Recycle Bin; choose permanent delete or move instead"
            ),
            Self::BinTurnedOff => write!(
                f,
                "the Recycle Bin is turned off for this drive; choose permanent delete or move instead"
            ),
            Self::TooBig { item, max } => write!(
                f,
                "too big for the Recycle Bin ({} MB, the bin holds {} MB); choose permanent delete or move instead",
                item / 1_000_000,
                max / 1_000_000
            ),
        }
    }
}

/// Decide whether recycling an item of `item_bytes` on a drive with these facts is safe.
pub fn preflight(facts: &BinFacts, item_bytes: u64) -> Result<(), RecycleRefusal> {
    if !facts.fixed_local || facts.subst || !facts.bin_present {
        return Err(RecycleRefusal::NoBin);
    }
    if facts.nuke_on_delete {
        return Err(RecycleRefusal::BinTurnedOff);
    }
    if item_bytes > facts.max_bytes {
        return Err(RecycleRefusal::TooBig {
            item: item_bytes,
            max: facts.max_bytes,
        });
    }
    Ok(())
}

/// Send each target to the Recycle Bin, within `policy`. Recycling on the same drive frees no
/// space until the bin is emptied, so `bytes_freed` stays 0 and `bytes_recycled` counts instead.
pub fn recycle(policy: &Policy, targets: &[WinPath]) -> Outcome {
    let targets: Vec<Target> = targets.iter().map(Target::any).collect();
    recycle_targets(policy, &targets)
}

/// Like [`recycle`], and each file with a recorded identity must still have it.
///
/// The shell recycles by path, so it can't use our handle (security review note 3). What is
/// done instead: the identity is compared on the handle that passed the policy, while every
/// folder above the item is held (no folder can be swapped); a second handle that only reads
/// attributes (so it never blocks the shell) stays on the checked file while the shell runs;
/// afterwards the item the shell reports it created in the bin (`IFileOperation`) must have the
/// watched file's ID (security review S2). What is left: a rename in the instant before the
/// shell opens the path would make the shell recycle another file. That file is then in the
/// Recycle Bin (restorable), and the result warns. Folders, and files without a recorded
/// identity, are checked by the policy only (review note N3): a folder swapped for a junction
/// in that instant is recycled as the link itself, never followed.
pub fn recycle_targets(policy: &Policy, targets: &[Target]) -> Outcome {
    recycle_with(policy, targets, &win::recycle::shell_recycle)
}

/// [`recycle_targets`] with the shell call passed in, so tests can check what reaches the
/// shell without ever using a real Recycle Bin.
pub fn recycle_with(
    policy: &Policy,
    targets: &[Target],
    shell: &dyn Fn(&WinPath) -> Result<Option<WinPath>, i32>,
) -> Outcome {
    let mut out = Outcome::default();
    let mut facts: HashMap<char, BinFacts> = HashMap::new();
    for target in targets {
        recycle_one(
            policy,
            &target.path,
            target.expect.as_ref(),
            0,
            shell,
            &mut facts,
            &mut out,
        );
    }
    out
}

/// Is the item the shell reported (`created`) the file `watch` has open? It must be inside a
/// Recycle Bin, open without following links, and have the same file ID; the watch handle must
/// also still see its file there.
fn same_file_recycled(watch: &win::Opened, created: Option<&WinPath>) -> bool {
    created.is_some_and(|c| is_in_recycle_bin(c) && is_same_open_file(watch, c))
}

/// Is the object at `at` (opened without following it) the very file `watch` has open: same
/// file ID, not a link, and where the watch handle now sees its file?
pub fn is_same_open_file(watch: &win::Opened, at: &WinPath) -> bool {
    let Ok(there) = win::open_no_follow(at, Access::Inspect) else {
        return false;
    };
    let id = watch.file_id();
    id.is_some()
        && there.file_id() == id
        && !there.resolved.is_reparse_point
        && watch
            .current_path()
            .is_ok_and(|now| now == there.resolved.final_path)
}

/// True when `path` is inside the Recycle Bin of its own drive (`X:\$Recycle.Bin\...`). Pure.
pub fn is_in_recycle_bin(path: &WinPath) -> bool {
    path.parts()
        .first()
        .is_some_and(|top| top.eq_ignore_ascii_case("$Recycle.Bin"))
        && path.parts().len() > 1
}

#[allow(clippy::too_many_arguments)]
fn recycle_one(
    policy: &Policy,
    path: &WinPath,
    expect: Option<&FileIdentity>,
    depth: usize,
    shell: &dyn Fn(&WinPath) -> Result<Option<WinPath>, i32>,
    facts: &mut HashMap<char, BinFacts>,
    out: &mut Outcome,
) {
    if depth > crate::engine::MAX_DEPTH {
        out.skipped.push(skip(path, SkipReason::TooDeep));
        return;
    }
    let opened = match win::open_no_follow(path, Access::Delete) {
        Ok(o) => o,
        Err(e) => {
            out.skipped.push(skip(path, e.into()));
            return;
        }
    };
    if let Err(refusal) = policy.check_target(&opened.resolved) {
        out.skipped.push(skip(path, SkipReason::Refused(refusal)));
        return;
    }
    let real = opened.resolved.final_path.clone();
    let is_directory = opened.is_directory;

    // The shell takes a path, so hold every folder from the allowed root down to the item's
    // parent until it is done: none can be renamed or swapped for a junction meanwhile
    // (security review, must-fix 3). Taken while our handle on the item is still open.
    let _chain = match hold_chain(policy, &real) {
        Ok(chain) => chain,
        Err(why) => {
            out.skipped.push(skip(path, SkipReason::Unsupported(why)));
            return;
        }
    };
    // The bin facts belong to the drive letter; the item must really be on that volume.
    let drive = real.drive();
    let drive_serial = win::open_no_follow(&WinPath::drive_root(drive), Access::Inspect)
        .map(|d| d.volume_serial)
        .ok();
    if drive_serial != Some(opened.volume_serial) {
        out.skipped.push(skip(
            path,
            SkipReason::CannotRecycle(
                "the item is not on the volume of its drive letter; choose permanent delete or move instead"
                    .into(),
            ),
        ));
        return;
    }
    if let Some(what) = expect.and_then(|e| not_as_expected(&opened, e)) {
        out.skipped
            .push(skip(path, SkipReason::ChangedSinceScan(what)));
        return;
    }
    let size = if is_directory {
        win::recycle::measure(&real)
    } else {
        opened.size
    };
    // A file with a recorded identity is watched while the shell runs, through a handle that
    // only reads attributes: such a handle never blocks the shell from moving the file. It must
    // be the same file the checked handle has open.
    let watch = match expect {
        None => None,
        Some(_) => match win::open_no_follow(&real, Access::Inspect) {
            Ok(w) if w.file_id().is_some() && w.file_id() == opened.file_id() => Some(w),
            _ => {
                out.skipped.push(skip(
                    path,
                    SkipReason::ChangedSinceScan("another file is in its place"),
                ));
                return;
            }
        },
    };
    // Close our delete handle on the item itself: the shell must be able to move it.
    drop(opened);

    let bin = facts
        .entry(drive)
        .or_insert_with(|| win::recycle::bin_facts(drive))
        .clone();
    if let Err(refusal) = preflight(&bin, size) {
        out.skipped
            .push(skip(path, SkipReason::CannotRecycle(refusal.to_string())));
        return;
    }

    let before = win::recycle::bin_size(drive);
    match shell(&real) {
        Ok(created) if !win::recycle::exists(&real) => {
            let after = win::recycle::bin_size(drive);
            // The item the shell says it put in the bin must be the very file we checked (same
            // file ID as the watch handle), not just any file under `$Recycle.Bin`, which the
            // user can write to (security review S2).
            if watch
                .as_ref()
                .is_some_and(|w| !same_file_recycled(w, created.as_ref()))
            {
                out.removed.push(real.clone());
                out.warnings.push(skip(
                    &real,
                    SkipReason::Failed(
                        "another file took its place just before it was recycled: check the Recycle Bin and restore what you did not mean to clean"
                            .into(),
                    ),
                ));
                return;
            }
            match (before, after) {
                (Some(b), Some(a)) if a.saturating_sub(b) >= size => {
                    out.removed.push(real);
                    out.bytes_recycled += size;
                }
                _ => {
                    // Gone, but the bin did not grow by its size: say so plainly.
                    out.removed.push(real.clone());
                    out.warnings.push(skip(
                        &real,
                        SkipReason::Failed(
                            "Windows may have deleted this permanently instead of recycling it"
                                .into(),
                        ),
                    ));
                }
            }
        }
        _ if is_directory => {
            // The folder couldn't move as a whole (e.g. a locked file inside): recycle what can
            // go, item by item, each re-checked, and keep the folder.
            match win::list_children(&real) {
                Ok(names) => {
                    for name in names {
                        match real.join(&name) {
                            Ok(child) => {
                                recycle_one(policy, &child, None, depth + 1, shell, facts, out)
                            }
                            Err(e) => out.skipped.push(skip(
                                &real,
                                SkipReason::Unsupported(format!("{name:?}: {e}")),
                            )),
                        }
                    }
                    if win::recycle::exists(&real) {
                        out.skipped.push(skip(path, SkipReason::NotEmpty));
                    }
                }
                Err(e) => out
                    .skipped
                    .push(skip(path, SkipReason::Failed(e.to_string()))),
            }
        }
        Ok(_) => out.skipped.push(skip(
            path,
            SkipReason::Failed("the Recycle Bin did not take it".into()),
        )),
        Err(code) => {
            // Tell "in use" apart from other failures.
            let reason = match win::open_no_follow(&real, Access::Delete) {
                Err(e) => e.into(),
                Ok(_) => SkipReason::Failed(format!("the shell reported error {code}")),
            };
            out.skipped.push(skip(path, reason));
        }
    }
}

/// Hold every folder from the allowed root that contains `item` down to `item`'s parent, each
/// opened without following it and without delete-sharing, and each at exactly the expected
/// real path. While the returned handles live, no folder on the way can be renamed or replaced.
pub fn hold_chain(policy: &Policy, item: &WinPath) -> Result<Vec<LockedDir>, String> {
    let root = policy
        .roots()
        .iter()
        .find(|root| item.is_strictly_inside(root))
        .ok_or("outside the folders chosen for this clean")?;
    let (_, parents) = item.parts().split_last().ok_or("no folder to hold")?;
    let mut chain = Vec::new();
    let mut current = WinPath::drive_root(item.drive());
    for (depth, part) in parents.iter().enumerate() {
        current = current.join(part).map_err(|e| e.to_string())?;
        if depth + 1 < root.parts().len() {
            continue; // above the root: not ours to hold
        }
        let held =
            lock_dir(&current).map_err(|e| format!("could not hold the folder {current}: {e}"))?;
        if held.path != current {
            return Err(format!("the folder {current} changed"));
        }
        chain.push(held);
    }
    Ok(chain)
}

fn skip(path: &WinPath, reason: SkipReason) -> Skipped {
    Skipped {
        path: path.clone(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> BinFacts {
        BinFacts {
            fixed_local: true,
            subst: false,
            bin_present: true,
            nuke_on_delete: false,
            max_bytes: 10_000_000_000,
        }
    }

    #[test]
    fn a_normal_fixed_drive_with_room_is_allowed() {
        assert_eq!(preflight(&good(), 1_000), Ok(()));
        assert_eq!(preflight(&good(), 10_000_000_000), Ok(()));
    }

    #[test]
    fn every_silent_permanent_delete_case_is_refused() {
        let no_bin = [
            BinFacts {
                fixed_local: false,
                ..good()
            },
            BinFacts {
                subst: true,
                ..good()
            },
            BinFacts {
                bin_present: false,
                ..good()
            },
        ];
        for facts in no_bin {
            assert_eq!(
                preflight(&facts, 1),
                Err(RecycleRefusal::NoBin),
                "{facts:?}"
            );
        }
        let off = BinFacts {
            nuke_on_delete: true,
            ..good()
        };
        assert_eq!(preflight(&off, 1), Err(RecycleRefusal::BinTurnedOff));
        assert_eq!(
            preflight(&good(), 10_000_000_001),
            Err(RecycleRefusal::TooBig {
                item: 10_000_000_001,
                max: 10_000_000_000
            })
        );
    }

    #[test]
    fn refusals_tell_the_user_what_to_do_instead() {
        for r in [
            RecycleRefusal::NoBin,
            RecycleRefusal::BinTurnedOff,
            RecycleRefusal::TooBig { item: 5, max: 1 },
        ] {
            assert!(
                r.to_string()
                    .ends_with("choose permanent delete or move instead"),
                "{r}"
            );
        }
    }
}
