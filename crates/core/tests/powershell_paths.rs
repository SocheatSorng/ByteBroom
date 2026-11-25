//! Security review of task 8, S2: the PowerShell the helper starts must look for modules only in
//! admin-owned folders. This starts System32's Windows PowerShell, unelevated, with exactly the
//! environment, folder and switches the Delivery Optimization plan uses, but a `-Command` that
//! only prints the module path. It runs no cmdlet and changes nothing.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytebroom_core::admin::{AdminAction, fixed_environment, plan};
use bytebroom_core::win::admin::{system32, windows_dir};
use std::process::Command;

#[test]
fn the_helpers_powershell_finds_modules_only_in_admin_owned_folders() {
    let s32 = system32().unwrap().to_string();
    let windows = windows_dir().unwrap().to_string();
    let p = plan(AdminAction::DeliveryOptimizationCache, &s32).unwrap();
    // Same switches, but print the module path instead of running the cmdlet.
    let mut args: Vec<String> = p.args.clone();
    let last = args.last_mut().unwrap();
    *last = "[Console]::Out.Write($env:PSModulePath)".into();
    let out = Command::new(format!(r"{s32}\{}", p.program.below_system32()))
        .args(&args)
        .env_clear()
        .envs(fixed_environment(&windows, &s32))
        .envs(p.extra_env.iter().map(|(k, v)| (*k, v.as_str())))
        .current_dir(&s32)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let path = String::from_utf8(out.stdout).unwrap();
    let program_files = std::env::var("ProgramFiles").unwrap_or(r"C:\Program Files".into());
    let allowed = [
        format!(r"{s32}\WindowsPowerShell\v1.0\Modules").to_lowercase(),
        format!(r"{program_files}\WindowsPowerShell\Modules").to_lowercase(),
    ];
    let entries: Vec<&str> = path.split(';').filter(|e| !e.is_empty()).collect();
    assert!(!entries.is_empty(), "no module path at all");
    for entry in entries {
        let e = entry.trim_end_matches('\\').to_lowercase();
        assert!(
            allowed.contains(&e),
            "PowerShell would look for modules in {entry}, which isn't admin-owned"
        );
    }
}
