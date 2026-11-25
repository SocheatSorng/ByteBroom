//! Harness for phase 4 task 1: start the installed helper through UAC with the `noop` action,
//! exactly as the app will, and print its answer. It touches no file and changes nothing; the
//! owner clicks the UAC prompt.
//!
//! Run (unelevated, after tools/install-helper.ps1):
//! `cargo run --release -p bytebroom-admin --example elevate_noop`
#![allow(clippy::print_stdout)]

use bytebroom_core::admin::AdminAction;
use bytebroom_core::win::admin::{helper_path, run_elevated};

fn main() {
    match helper_path() {
        Some(p) => println!("Helper: {p}"),
        None => println!("Helper: Program Files can't be found"),
    }
    match run_elevated(AdminAction::Noop, 0) {
        Ok(exit) => println!("Answer: {exit:?} ({})", exit.describe()),
        Err(e) => println!("Not run: {e:?}"),
    }
}
