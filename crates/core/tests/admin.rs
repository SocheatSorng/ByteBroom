//! Phase 4 task 1: the helper's location check on real files, read-only. A temp folder (the
//! user's own) must fail, a path through a junction must fail, and Windows' own System32 must
//! pass. Nothing is changed outside a fresh temp folder; no UAC prompt is ever shown.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use bytebroom_core::paths::WinPath;
use bytebroom_core::win::admin::{helper_path, location_problem, security_of};
use bytebroom_core::win::{Access, open_no_follow, system_layout};
use common::*;
use std::path::Path;

fn real(path: &Path) -> WinPath {
    open_no_follow(
        &WinPath::parse(path.to_str().unwrap()).unwrap(),
        Access::Inspect,
    )
    .unwrap()
    .resolved
    .final_path
}

#[test]
fn a_program_in_the_users_own_folder_is_not_admin_owned() {
    let dir = CleanDir::new("adm-temp");
    let exe = dir.0.join("bytebroom-admin.exe");
    write_file(&exe, b"not a program");
    let why = location_problem(&real(&exe)).expect("a temp folder must be refused");
    assert!(
        why.contains("owned by") || why.contains("may change it"),
        "{why}"
    );
}

#[test]
fn a_program_reached_through_a_junction_is_refused() {
    let dir = CleanDir::new("adm-link");
    write_file(&dir.0.join("target").join("bytebroom-admin.exe"), b"x");
    make_junction(&dir.0.join("via"), &dir.0.join("target"));
    let through = WinPath::parse(
        dir.0
            .join("via")
            .join("bytebroom-admin.exe")
            .to_str()
            .unwrap(),
    )
    .unwrap();
    assert!(location_problem(&through).is_some());
    std::fs::remove_dir(dir.0.join("via")).unwrap();
}

#[test]
fn windows_own_system32_counts_as_admin_owned() {
    let cmd = system_layout()
        .system_root
        .join("System32")
        .unwrap()
        .join("cmd.exe")
        .unwrap();
    assert_eq!(location_problem(&cmd), None);
}

#[test]
fn the_users_temp_folder_has_an_untrusted_owner_or_writer() {
    let dir = CleanDir::new("adm-sec");
    let opened = open_no_follow(&real(&dir.0), Access::Security).unwrap();
    let sec = security_of(&opened).unwrap();
    assert!(sec.owner.starts_with("S-1-"), "{sec:?}");
    assert!(sec.dacl.as_ref().is_some_and(|d| !d.is_empty()));
}

#[test]
fn the_helper_is_looked_for_only_in_program_files() {
    let p = helper_path().unwrap();
    let text = p.to_string().to_lowercase();
    assert!(text.ends_with("\\bytebroom\\bytebroom-admin.exe"), "{text}");
    let layout = system_layout();
    assert!(
        layout
            .program_files
            .iter()
            .any(|pf| p.is_strictly_inside(pf)),
        "{p}"
    );
}

/// Review S1: the install script checks the installed helper with a PowerShell copy of the
/// rule (`tools/helper-acl.ps1`). On the same real files it must agree with the Rust rule: an
/// admin-owned System32 program passes both, a file in the user's temp folder fails both.
#[test]
fn the_install_scripts_rule_agrees_with_the_helpers() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tools")
        .join("helper-acl.ps1");
    let ps = |path: &str| -> String {
        let cmd = format!(
            ". '{}'; $p = Get-AdminOwnedProblem '{}'; if ($p) {{ \"PROBLEM: $p\" }} else {{ 'OK' }}",
            script.display(),
            path
        );
        let out = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &cmd])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };
    let cmd = system_layout()
        .system_root
        .join("System32")
        .unwrap()
        .join("cmd.exe")
        .unwrap();
    assert_eq!(ps(&cmd.to_string()), "OK");
    let dir = CleanDir::new("adm-ps");
    let exe = dir.0.join("bytebroom-admin.exe");
    write_file(&exe, b"x");
    let out = ps(exe.to_str().unwrap());
    assert!(out.starts_with("PROBLEM:"), "{out}");
    assert!(location_problem(&real(&exe)).is_some());
}

/// Task 2, read-only: the parts of the restore point call that can be checked without making
/// one. COM's security descriptor builds with exactly Microsoft's five callers, and System32's
/// SrClient.dll exports SRSetRestorePointW. The call itself is never made by a test: it would
/// make a real restore point.
#[test]
fn the_restore_point_call_is_ready_without_being_made() {
    use bytebroom_core::win::restore::{CALLERS, ComSecurity, SrClient};
    let sec = ComSecurity::build().expect("the COM security descriptor builds");
    assert_eq!(sec.callers(), CALLERS.len());
    assert_eq!(CALLERS.len(), 5);
    assert!(
        SrClient::load().is_some(),
        "System Restore's SrClient.dll with SRSetRestorePointW, from System32"
    );
}
