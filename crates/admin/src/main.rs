//! `bytebroom-admin.exe`: ByteBroom's elevated helper (phase 4).
//!
//! The window stays unelevated; when the owner asks for a red-tier action, it starts this
//! helper through UAC with one action word. The helper, in this order:
//!
//! 1. loads DLLs from System32 only and makes System32 its current folder;
//! 2. takes exactly one action word from the fixed list, or stops (`BadArgs`);
//! 3. checks that it lives in an admin-owned place, or stops (`UntrustedLocation`);
//! 4. checks that it is elevated, or stops (`NotElevated`);
//! 5. does that one action and answers with its exit code only.
//!
//! It reads no file the user can write and writes no file the app reads. Nothing here may
//! delete files (owner's decision 6).

#![forbid(unsafe_code)]

use bytebroom_core::admin::{AdminAction, Exit, parse_args};
use bytebroom_core::win::admin::{
    enter_system32, is_elevated, load_dlls_from_system32_only, location_problem, own_exe,
};
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

/// Carry out one action.
fn run(action: AdminAction) -> Exit {
    match action {
        AdminAction::Noop => Exit::Done,
    }
}

fn main() -> ExitCode {
    if !load_dlls_from_system32_only() || !enter_system32() {
        return ExitCode::from(Exit::Failed.code());
    }
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let action = parse_args(&args);
    // Only look at the location for a valid request; a bad one stops before anything else.
    let location_ok =
        action.is_some() && own_exe().is_some_and(|exe| location_problem(&exe).is_none());
    let exit = match gate(action, location_ok, action.is_some() && is_elevated()) {
        Ok(action) => run(action),
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
        assert_eq!(run(AdminAction::Noop), Exit::Done);
    }
}
