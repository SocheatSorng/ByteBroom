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
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("tauri build step");
}
