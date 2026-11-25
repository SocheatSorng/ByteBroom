//! The restore point the helper makes before any system change (phase 4, task 2; owner's
//! decision 5). Pure; the Windows call is `win::restore`.
//!
//! What Microsoft documents for `SRSetRestorePointW` (task 0):
//!
//! - success gives a restore point's sequence number;
//! - "Windows skips creating this new restore point if any restore points have been created in
//!   the last 24 hours" and then still reports success, with the earlier point's number. Either
//!   way, a restore point from the last day is in place, so both count as [`RestorePoint::InPlace`];
//! - `ERROR_SERVICE_DISABLED`: System Restore is off; `ERROR_DISK_FULL`: it is paused for low
//!   disk space; `ERROR_BAD_ENVIRONMENT`: safe mode.
//!
//! The rule (security review of task 1, N1): every action that changes the system makes or
//! confirms its restore point **inside the helper, in the same run**, through [`guarded`], and
//! does nothing unless a restore point is in place. The unelevated app never sequences it.

#![forbid(unsafe_code)]

use crate::admin::Exit;

/// What asking Windows for a restore point gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePoint {
    /// A restore point is in place: made now, or one from the last 24 hours (Windows makes at
    /// most one a day). Its sequence number.
    InPlace(i64),
    /// System Restore is turned off for this PC.
    Off,
    /// System Restore is paused because the disk is low on space.
    LowDisk,
    /// Windows can't make restore points now (e.g. safe mode), or System Restore isn't on this
    /// edition of Windows.
    Unavailable,
    /// Anything else, with Windows' error code.
    Failed(u32),
}

/// How many times the helper asks Windows to list a point it just made, and the pause between.
/// Three minutes in all: the snapshot behind the point is taken after the call returns.
pub const CONFIRM_TRIES: u32 = 90;
/// See [`CONFIRM_TRIES`].
pub const CONFIRM_PAUSE: std::time::Duration = std::time::Duration::from_secs(2);
/// ByteBroom's own code in [`RestorePoint::Failed`]: Windows said the point was made, but it
/// never appeared in the list of restore points.
pub const NOT_LISTED: u32 = 0xB0B0_0001;

/// Count a point as in place only once Windows lists it (the owner's check, 2026-11-25:
/// `SRSetRestorePointW` reported success and System Restore logged the point, but the shadow
/// copy behind it was taken after the helper exited, failed, and no point was left). `listed`
/// asks Windows whether `sequence` is in the list (`None`: the question failed); `pause` waits
/// between tries. The helper stays running meanwhile. Pure.
pub fn confirm_listed(
    sequence: i64,
    mut listed: impl FnMut(i64) -> Option<bool>,
    mut pause: impl FnMut(),
    tries: u32,
) -> RestorePoint {
    for attempt in 0..tries {
        if attempt > 0 {
            pause();
        }
        if listed(sequence) == Some(true) {
            return RestorePoint::InPlace(sequence);
        }
    }
    RestorePoint::Failed(NOT_LISTED)
}

const ERROR_BAD_ENVIRONMENT: u32 = 10;
const ERROR_DISK_FULL: u32 = 112;
const ERROR_SERVICE_DISABLED: u32 = 1058;

/// Read the result of the `BEGIN_SYSTEM_CHANGE` call: whether it succeeded, the status it set
/// and the sequence number it returned. Pure.
pub fn from_call(succeeded: bool, status: u32, sequence: i64) -> RestorePoint {
    if succeeded {
        // Success must come with a real restore point number; anything else isn't one.
        return if status == 0 && sequence > 0 {
            RestorePoint::InPlace(sequence)
        } else {
            RestorePoint::Failed(status)
        };
    }
    match status {
        ERROR_SERVICE_DISABLED => RestorePoint::Off,
        ERROR_DISK_FULL => RestorePoint::LowDisk,
        ERROR_BAD_ENVIRONMENT => RestorePoint::Unavailable,
        other => RestorePoint::Failed(other),
    }
}

/// The helper's answer for a restore point result on its own (the `restore-point` action).
pub fn exit_for(point: RestorePoint) -> Exit {
    match point {
        RestorePoint::InPlace(_) => Exit::Done,
        RestorePoint::Off => Exit::RestoreOff,
        RestorePoint::LowDisk => Exit::RestoreLowDisk,
        RestorePoint::Unavailable | RestorePoint::Failed(_) => Exit::RestoreFailed,
    }
}

/// Proof that a restore point is in place in this run. Only [`guarded`] can make one (its field
/// is private), and every function that changes the system takes one, so an action that skips
/// the restore point doesn't compile (security review of task 2, S1).
#[derive(Debug)]
pub struct PointInPlace {
    sequence: i64,
}

impl PointInPlace {
    /// The restore point's sequence number.
    pub fn sequence(&self) -> i64 {
        self.sequence
    }
}

/// Run `act` only if `make_point` puts a restore point in place first; otherwise answer why
/// not, and do nothing. Every system-changing action goes through this: it is the only place
/// a [`PointInPlace`] is made.
pub fn guarded(
    make_point: impl FnOnce() -> RestorePoint,
    act: impl FnOnce(PointInPlace) -> Exit,
) -> Exit {
    match make_point() {
        RestorePoint::InPlace(sequence) => act(PointInPlace { sequence }),
        other => exit_for(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn success_counts_only_with_a_real_number() {
        assert_eq!(from_call(true, 0, 88), RestorePoint::InPlace(88));
        // The 24-hour skip: success with the earlier point's number.
        assert_eq!(from_call(true, 0, 87), RestorePoint::InPlace(87));
        assert_eq!(from_call(true, 0, 0), RestorePoint::Failed(0));
        assert_eq!(from_call(true, 0, -1), RestorePoint::Failed(0));
        assert_eq!(from_call(true, 5, 88), RestorePoint::Failed(5));
    }

    #[test]
    fn each_documented_failure_is_told_apart() {
        assert_eq!(from_call(false, 1058, 0), RestorePoint::Off);
        assert_eq!(from_call(false, 112, 0), RestorePoint::LowDisk);
        assert_eq!(from_call(false, 10, 0), RestorePoint::Unavailable);
        assert_eq!(from_call(false, 5, 0), RestorePoint::Failed(5));
        assert_eq!(
            from_call(false, 1058, 88),
            RestorePoint::Off,
            "a failure is never InPlace"
        );
    }

    #[test]
    fn answers_for_the_window() {
        assert_eq!(exit_for(RestorePoint::InPlace(1)), Exit::Done);
        assert_eq!(exit_for(RestorePoint::Off), Exit::RestoreOff);
        assert_eq!(exit_for(RestorePoint::LowDisk), Exit::RestoreLowDisk);
        assert_eq!(exit_for(RestorePoint::Unavailable), Exit::RestoreFailed);
        assert_eq!(exit_for(RestorePoint::Failed(5)), Exit::RestoreFailed);
    }

    #[test]
    fn nothing_is_changed_without_a_restore_point_in_place() {
        for point in [
            RestorePoint::Off,
            RestorePoint::LowDisk,
            RestorePoint::Unavailable,
            RestorePoint::Failed(5),
        ] {
            let ran = Cell::new(false);
            let exit = guarded(
                || point,
                |_| {
                    ran.set(true);
                    Exit::Done
                },
            );
            assert!(!ran.get(), "{point:?}");
            assert_ne!(exit, Exit::Done, "{point:?}");
        }
        let ran = Cell::new(false);
        let exit = guarded(
            || RestorePoint::InPlace(9),
            |proof| {
                assert_eq!(proof.sequence(), 9, "the action gets the point's number");
                ran.set(true);
                Exit::Failed
            },
        );
        assert!(ran.get());
        assert_eq!(exit, Exit::Failed, "the action's own answer comes back");
    }

    #[test]
    fn a_point_counts_only_once_windows_lists_it() {
        // Listed on the third ask: in place, after two pauses.
        let (asks, pauses) = (Cell::new(0), Cell::new(0));
        let point = confirm_listed(
            42,
            |seq| {
                assert_eq!(seq, 42);
                asks.set(asks.get() + 1);
                Some(asks.get() == 3)
            },
            || pauses.set(pauses.get() + 1),
            CONFIRM_TRIES,
        );
        assert_eq!(point, RestorePoint::InPlace(42));
        assert_eq!((asks.get(), pauses.get()), (3, 2));

        // Never listed, or the question keeps failing: not in place, after every try.
        for answer in [Some(false), None] {
            let asks = Cell::new(0);
            let point = confirm_listed(
                42,
                |_| {
                    asks.set(asks.get() + 1);
                    answer
                },
                || {},
                5,
            );
            assert_eq!(point, RestorePoint::Failed(NOT_LISTED), "{answer:?}");
            assert_eq!(asks.get(), 5);
            assert_eq!(exit_for(point), Exit::RestoreFailed);
        }
        // Three minutes in all.
        assert_eq!(
            CONFIRM_PAUSE * (CONFIRM_TRIES - 1),
            std::time::Duration::from_secs(178)
        );
    }

    #[test]
    fn the_point_comes_first() {
        let order = std::cell::RefCell::new(Vec::new());
        guarded(
            || {
                order.borrow_mut().push("point");
                RestorePoint::InPlace(1)
            },
            |_| {
                order.borrow_mut().push("act");
                Exit::Done
            },
        );
        assert_eq!(*order.borrow(), ["point", "act"]);
    }
}
