//! The installer, pinned (phase 6, owner's decision 1): a per-machine NSIS install into
//! `<Program Files>\ByteBroom`, with the elevated helper beside the window, exactly where
//! `bytebroom_core::win::admin::helper_path` looks for it.
//!
//! Checked against Tauri's generated `installer.nsi` (2026-11-26, tauri-cli 2.12.6): per-machine
//! sets `$INSTDIR` to `$PROGRAMFILES64\${PRODUCTNAME}`, and each `externalBin` is copied into
//! `$INSTDIR` with its target-triple suffix removed. Folders under Program Files inherit their
//! admin-only permissions, so the installer is what makes the helper admin-owned.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytebroom_core::win::admin::{HELPER_EXE, HELPER_FOLDER};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    fs::read_to_string(crate_dir().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn json(rel: &str) -> Value {
    serde_json::from_str(&read(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The sidecar's config name; Tauri adds `-<target triple>.exe` to find it and strips it on install.
const SIDECAR: &str = "binaries/bytebroom-admin";

#[test]
fn plain_builds_and_tests_never_bundle() {
    // So `cargo test` and clippy never need the staged helper: only build.ps1 and release.ps1
    // turn bundling on, with `--config tauri.installer.json`.
    let conf = json("tauri.conf.json");
    assert_eq!(conf["bundle"]["active"], false);
    assert!(conf["bundle"].get("externalBin").is_none());
}

#[test]
fn the_installer_is_per_machine_nsis_with_the_helper_inside() {
    let inst = json("tauri.installer.json");
    assert_eq!(inst["bundle"]["active"], true);
    assert_eq!(inst["bundle"]["targets"], serde_json::json!(["nsis"]));
    assert_eq!(
        inst["bundle"]["windows"]["nsis"]["installMode"], "perMachine",
        "per-machine installs into Program Files, which only administrators can change"
    );
    assert_eq!(inst["bundle"]["externalBin"], serde_json::json!([SIDECAR]));
}

#[test]
fn the_installed_helper_lands_where_the_window_looks_for_it() {
    // Install folder: `$PROGRAMFILES64\<productName>`; the helper: `<folder>\<sidecar name>.exe`.
    let conf = json("tauri.conf.json");
    assert_eq!(conf["productName"], HELPER_FOLDER);
    let installed = format!("{}.exe", SIDECAR.rsplit('/').next().unwrap());
    assert_eq!(installed, HELPER_EXE);
}

#[test]
fn build_ps1_stages_the_helper_under_the_sidecar_name_and_bundles_with_the_installer_config() {
    let build = read("../build.ps1");
    assert!(build.contains("cargo build --release -p bytebroom-admin"));
    assert!(build.contains("bytebroom-admin-x86_64-pc-windows-msvc.exe"));
    assert!(build.contains("--config tauri.installer.json"));
    // The helper is built and staged before the bundle that packs it.
    let helper = build.find("-p bytebroom-admin").unwrap();
    let bundle = build.find("--config tauri.installer.json").unwrap();
    assert!(helper < bundle, "build the helper first");
}

#[test]
fn the_staged_helper_is_never_committed() {
    let ignore = read("../.gitignore");
    assert!(ignore.lines().any(|l| l.trim() == "src-tauri/binaries/"));
}

#[test]
fn verify_install_is_read_only_and_checks_both_programs() {
    let script = read("../tools/verify-install.ps1");
    for name in [
        "'bytebroom.exe'",
        "'bytebroom-admin.exe'",
        "Join-Path $programFiles 'ByteBroom'",
    ] {
        assert!(script.contains(name), "verify-install.ps1 lacks {name}");
    }
    assert!(script.contains("Get-AdminOwnedProblem"));
    assert!(
        !script.contains("#Requires -RunAsAdministrator"),
        "runs unelevated"
    );
    for writer in [
        "Remove-Item",
        "Set-Acl",
        "Copy-Item",
        "Move-Item",
        "New-Item",
        "Set-Content",
        "Out-File",
        "icacls",
        "takeown",
        "Start-Process",
    ] {
        assert!(
            !script.contains(writer),
            "verify-install.ps1 must not use {writer}"
        );
    }
}
