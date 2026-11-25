//! Harness for phase 4 task 2: start the installed helper through UAC with the
//! `restore-point` action, exactly as the app will, and print its answer. It makes one System
//! Restore point (or confirms one from the last 24 hours, as Windows allows one a day) and
//! changes nothing else; the owner clicks the UAC prompt.
//!
//! Run (in an ordinary, unelevated PowerShell, after tools/install-helper.ps1):
//! `cargo run --release -p bytebroom-admin --example elevate_restore_point`
#![allow(clippy::print_stdout)]

use bytebroom_core::admin::AdminAction;
use bytebroom_core::win::admin::{helper_path, run_elevated};

fn main() {
    match helper_path() {
        Some(p) => println!("Helper: {p}"),
        None => println!("Helper: Program Files can't be found"),
    }
    match run_elevated(AdminAction::RestorePoint, 0) {
        Ok(exit) => println!("Answer: {exit:?} ({})", exit.describe()),
        Err(e) => println!("Not run: {e:?}"),
    }
}
