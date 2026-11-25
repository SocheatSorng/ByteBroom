//! The real helper program, started as a child (never through UAC): from the build folder,
//! which ordinary users can change, it must refuse every request, and refuse bad arguments
//! before looking at anything else.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

fn helper(args: &[&str]) -> i32 {
    Command::new(env!("CARGO_BIN_EXE_bytebroom-admin"))
        .args(args)
        .status()
        .unwrap()
        .code()
        .unwrap()
}

#[test]
fn bad_arguments_stop_it_before_anything_else() {
    for args in [
        &[][..],
        &["bogus"],
        &["NOOP"],
        &["noop", "noop"],
        &["noop", "C:\\Windows"],
        &["C:\\Windows\\System32\\cmd.exe"],
    ] {
        assert_eq!(helper(args), 2, "{args:?}");
    }
}

#[test]
fn from_the_build_folder_it_refuses_as_an_untrusted_location() {
    // target\ is the owner's own folder: whether or not this test runs elevated (CI runners
    // are), the helper must refuse before acting.
    assert_eq!(helper(&["noop"]), 3);
}
