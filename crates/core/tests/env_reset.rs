//! Review of task 2, S2, on the real process environment: after `reset_environment`, nothing
//! but the fixed list is left, with values from the Windows API. Its own test program, with
//! one test, because it replaces the whole process environment.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Planting variables needs `set_var`, unsafe in Rust 2024 (not a Win32 call); test-only.
#![allow(unsafe_code)]

use bytebroom_core::admin::fixed_environment;
use bytebroom_core::win::admin::{reset_environment, system32, windows_dir};

#[test]
fn only_the_fixed_environment_is_left() {
    // Something a user could have set, which must not survive.
    // SAFETY: this test program has this one test, so nothing else reads the environment.
    unsafe {
        std::env::set_var("windir", r"C:\Users\Planted");
        std::env::set_var("COMPLUS_Version", "x");
        std::env::set_var("__COMPAT_LAYER", "RunAsInvoker");
    }
    assert!(reset_environment());
    let mut now: Vec<(String, String)> = std::env::vars().collect();
    now.sort();
    let mut expected: Vec<(String, String)> = fixed_environment(
        &windows_dir().unwrap().to_string(),
        &system32().unwrap().to_string(),
    )
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    expected.sort();
    assert_eq!(now, expected);
    assert!(!std::env::var("windir").unwrap().contains("Planted"));
}
