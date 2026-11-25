//! The WMI question the helper asks after making a restore point (`is_listed`), read-only:
//! it never makes, changes or removes a restore point. Unelevated, Windows may refuse the
//! question (`None`); either way a point that can't exist must never count as listed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// COM initialisation for this test thread (windows crate calls are unsafe); test-only.
#![allow(unsafe_code)]

use bytebroom_core::win::restore::is_listed;
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize};

#[test]
fn a_point_that_cant_exist_is_never_listed() {
    // SAFETY: plain COM initialisation of this test's thread, balanced below.
    let init = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    assert!(init.is_ok(), "{init:?}");
    for sequence in [i64::MAX, 0, -1] {
        assert_ne!(is_listed(sequence), Some(true), "{sequence}");
    }
    // SAFETY: balances the successful CoInitializeEx above.
    unsafe { CoUninitialize() };
}
