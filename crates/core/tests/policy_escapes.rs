//! Property tests: random, hostile path strings must never be allowed outside the root.
//!
//! The oracle is deliberately simple and independent of `is_strictly_inside`: a path is inside
//! the root only if its printed form starts with the root's printed form plus a backslash.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::{Policy, ResolvedPath, SystemLayout};
use proptest::prelude::*;

const ROOT: &str = "D:\\Scratch\\Root";

fn p(s: &str) -> WinPath {
    WinPath::parse(s).unwrap()
}

fn layout() -> SystemLayout {
    SystemLayout {
        system_root: p("C:\\Windows"),
        program_files: vec![p("C:\\Program Files"), p("C:\\Program Files (x86)")],
        program_data: p("C:\\ProgramData"),
        profiles_dir: p("C:\\Users"),
        profile_roots: vec![p("C:\\Users\\Ann")],
    }
}

fn policy() -> Policy {
    Policy::new(
        vec![ResolvedPath {
            final_path: p(ROOT),
            is_reparse_point: false,
        }],
        layout(),
    )
    .unwrap()
}

/// Characters that have special meaning somewhere in Windows path handling.
fn hostile_char() -> impl Strategy<Value = char> {
    prop::sample::select(vec![
        'a', 'B', 'z', '.', '\\', '/', ':', ' ', '~', '1', '?', '*', '$', '\u{0}', 'İ', 'ß', 'Ω',
    ])
}

fn hostile_suffix() -> impl Strategy<Value = String> {
    prop::collection::vec(hostile_char(), 0..24).prop_map(|cs| cs.into_iter().collect())
}

fn allowed(target: &WinPath) -> bool {
    policy()
        .check_target(&ResolvedPath {
            final_path: target.clone(),
            is_reparse_point: false,
        })
        .is_ok()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    #[test]
    fn nothing_outside_the_root_is_ever_allowed(prefix in prop::sample::select(vec![
        "D:\\Scratch\\Root\\", "D:\\Scratch\\Root", "D:\\Scratch\\", "d:\\scratch\\root\\",
        "\\\\?\\D:\\Scratch\\Root\\", "D:/Scratch/Root/", "C:\\", "\\\\server\\", "\\\\.\\D:\\",
    ]), suffix in hostile_suffix()) {
        let input = format!("{prefix}{suffix}");
        if let Ok(target) = WinPath::parse(&input) {
            let printed = target.to_string();
            if allowed(&target) {
                prop_assert!(
                    printed.starts_with(&format!("{ROOT}\\")),
                    "{input:?} -> {printed:?} was allowed outside {ROOT}"
                );
                prop_assert!(!target.parts().iter().any(|part| part == "." || part == ".."));
            }
            // Parsing the printed form gives the same path back (no hidden aliasing).
            prop_assert_eq!(WinPath::parse(&printed).unwrap(), target);
        }
    }

    #[test]
    fn a_dot_dot_part_is_always_refused(before in "[a-z]{1,8}", after in "[a-z]{0,8}") {
        let input = format!("{ROOT}\\{before}\\..\\{after}");
        prop_assert!(WinPath::parse(&input).is_err(), "{input} parsed");
    }

    #[test]
    fn printed_paths_never_carry_stream_or_device_syntax(suffix in hostile_suffix()) {
        if let Ok(target) = WinPath::parse(&format!("{ROOT}\\{suffix}")) {
            let tail = &target.to_string()[2..];
            prop_assert!(!tail.contains(':'), "stream syntax survived in {target}");
            prop_assert!(!tail.contains('*') && !tail.contains('?'));
            for part in target.parts() {
                prop_assert!(!part.ends_with('.') && !part.ends_with(' '), "{part:?}");
            }
        }
    }
}
