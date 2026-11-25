//! Generates the app's permission manifest: one `allow-<command>` permission per command, so the
//! capability file must grant each command by name (nothing is allowed by default).
#![allow(clippy::expect_used)] // A failed build script should stop the build with its message.

/// Every command the window may call. `tests/boundary.rs` checks this matches `lib.rs`.
const COMMANDS: &[&str] = &[
    "start_scan",
    "cancel_scan",
    "scan_state",
    "preview",
    "clean",
    "pick_move_destination",
    "open_recycle_bin",
    "red_actions",
    "run_red_action",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri build step");
    // tauri-build links the app manifest (Common Controls v6, needed by Windows' task dialog)
    // into the app's binaries only. The dialog harness in examples/ needs it too, or it can't
    // even start (STATUS_ENTRYPOINT_NOT_FOUND).
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    let resource = std::path::Path::new(&out).join("resource.lib");
    if resource.exists() {
        println!("cargo:rustc-link-arg-examples={}", resource.display());
    }
}
