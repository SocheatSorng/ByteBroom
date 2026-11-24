//! Sending items to the Recycle Bin, without ever letting Windows silently delete them for good.
//!
//! Windows turns "recycle" into a permanent delete, without asking when no UI is shown, when the
//! drive has no Recycle Bin (subst, network, most USB drives), when the bin is turned off for the
//! drive, or when the item is bigger than the bin's maximum size. [`preflight`] refuses all of
//! those up front; after recycling, the engine also checks that the bin grew by the item's size.

use crate::engine::{Outcome, SkipReason, Skipped};
use crate::paths::WinPath;
use crate::policy::Policy;
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
    let mut out = Outcome::default();
    let mut facts: HashMap<char, BinFacts> = HashMap::new();
    for target in targets {
        recycle_one(policy, target, 0, &mut facts, &mut out);
    }
    out
}

fn recycle_one(
    policy: &Policy,
    path: &WinPath,
    depth: usize,
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
    let size = if is_directory {
        win::recycle::measure(&real)
    } else {
        opened.size
    };
    // Close our handle: the shell must be able to move the item.
    drop(opened);

    let drive = real.drive();
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
    match win::recycle::shell_recycle(&real) {
        Ok(()) if !win::recycle::exists(&real) => {
            let after = win::recycle::bin_size(drive);
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
                            Ok(child) => recycle_one(policy, &child, depth + 1, facts, out),
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
        Ok(()) => out.skipped.push(skip(
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
