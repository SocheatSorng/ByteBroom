//! `bytebroom-admin.exe`: ByteBroom's elevated helper (phase 4).
//!
//! The window stays unelevated; when the owner asks for a red-tier action, it starts this
//! helper through UAC with one action word. The helper, in this order:
//!
//! 1. loads DLLs from System32 only, replaces its whole environment with a fixed one built
//!    from the Windows API (no user-set variable survives), and makes System32 its current
//!    folder;
//! 2. takes exactly one action word from the fixed list, or stops (`BadArgs`);
//! 3. checks that it lives in an admin-owned place, or stops (`UntrustedLocation`);
//! 4. checks that it is elevated, or stops (`NotElevated`);
//! 5. does that one action and answers with its exit code only.
//!
//! It reads no file the user can write and writes no file the app reads. Nothing here may
//! delete files (owner's decision 6).

#![forbid(unsafe_code)]

use bytebroom_core::admin::{AdminAction, Exit, parse_args};
use bytebroom_core::restore::{RestorePoint, guarded};
use bytebroom_core::win::admin::{
    enter_system32, is_elevated, load_dlls_from_system32_only, location_problem, own_exe,
    reset_environment,
};
use bytebroom_core::win::restore::make_restore_point;
use std::process::ExitCode;

/// Decide whether to act, from the facts in check order. Pure.
fn gate(
    action: Option<AdminAction>,
    location_ok: bool,
    elevated: bool,
) -> Result<AdminAction, Exit> {
    let action = action.ok_or(Exit::BadArgs)?;
    if !location_ok {
        return Err(Exit::UntrustedLocation);
    }
    if !elevated {
        return Err(Exit::NotElevated);
    }
    Ok(action)
}

/// Carry out one action. `make_point` makes the restore point (the real one in `main`; tests
/// pass a stand-in, so they never make a real restore point).
fn run(action: AdminAction, make_point: impl FnOnce(&str) -> RestorePoint) -> Exit {
    let description = action.restore_description();
    match action {
        AdminAction::Noop => Exit::Done,
        // The restore point on its own; later actions use `guarded` the same way, with their
        // change as the second step.
        AdminAction::RestorePoint => guarded(|| make_point(description), |_point| Exit::Done),
    }
}

fn main() -> ExitCode {
    if !load_dlls_from_system32_only() || !reset_environment() || !enter_system32() {
        return ExitCode::from(Exit::Failed.code());
    }
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let action = parse_args(&args);
    // Only look at the location for a valid request; a bad one stops before anything else.
    let location_ok =
        action.is_some() && own_exe().is_some_and(|exe| location_problem(&exe).is_none());
    let exit = match gate(action, location_ok, action.is_some() && is_elevated()) {
        Ok(action) => run(action, make_restore_point),
        Err(stop) => stop,
    };
    ExitCode::from(exit.code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_runs_unless_every_check_passes_in_order() {
        let a = Some(AdminAction::Noop);
        assert_eq!(gate(a, true, true), Ok(AdminAction::Noop));
        assert_eq!(gate(None, true, true), Err(Exit::BadArgs));
        assert_eq!(gate(None, false, false), Err(Exit::BadArgs));
        assert_eq!(gate(a, false, true), Err(Exit::UntrustedLocation));
        assert_eq!(gate(a, false, false), Err(Exit::UntrustedLocation));
        assert_eq!(gate(a, true, false), Err(Exit::NotElevated));
    }

    #[test]
    fn the_noop_does_nothing_and_succeeds() {
        let asked = std::cell::Cell::new(false);
        let exit = run(AdminAction::Noop, |_| {
            asked.set(true);
            RestorePoint::InPlace(1)
        });
        assert_eq!(exit, Exit::Done);
        assert!(!asked.get(), "the no-op makes no restore point");
    }

    /// Review S1: every action except the no-op must ask for a restore point first and stop
    /// without one. A new action that skips the guard fails here at once.
    #[test]
    fn every_action_but_the_noop_stops_without_a_restore_point() {
        for action in AdminAction::ALL {
            if action == AdminAction::Noop {
                continue;
            }
            for (point, expected) in [
                (RestorePoint::Off, Exit::RestoreOff),
                (RestorePoint::LowDisk, Exit::RestoreLowDisk),
                (RestorePoint::Failed(5), Exit::RestoreFailed),
            ] {
                let asked = std::cell::Cell::new(false);
                let exit = run(action, |_| {
                    asked.set(true);
                    point
                });
                assert!(asked.get(), "{action:?} must ask for a restore point");
                assert_eq!(exit, expected, "{action:?} with {point:?}");
            }
        }
    }

    #[test]
    fn the_restore_point_action_answers_what_windows_said() {
        let with = |point: RestorePoint| {
            let named = std::cell::RefCell::new(String::new());
            let exit = run(AdminAction::RestorePoint, |d| {
                *named.borrow_mut() = d.to_string();
                point
            });
            assert!(
                named.borrow().starts_with("ByteBroom"),
                "{}",
                named.borrow()
            );
            exit
        };
        assert_eq!(with(RestorePoint::InPlace(88)), Exit::Done);
        assert_eq!(with(RestorePoint::Off), Exit::RestoreOff);
        assert_eq!(with(RestorePoint::LowDisk), Exit::RestoreLowDisk);
        assert_eq!(with(RestorePoint::Unavailable), Exit::RestoreFailed);
        assert_eq!(with(RestorePoint::Failed(5)), Exit::RestoreFailed);
    }
}
