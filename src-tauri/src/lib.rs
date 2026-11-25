//! ByteBroom's window. The page refers to findings by the IDs a scan handed out; every decision is
//! made here, from Rust's own copy of the scan, by `bytebroom-core`.
//!
//! The command list is the boundary: `tests/boundary.rs` checks it against `build.rs`, the
//! capability file and an allow-list, and checks that no command takes text or a path.

#![forbid(unsafe_code)]

pub mod boundary;

use boundary::{Choice, PreviewId};
use serde::Serialize;
use tauri::{WebviewUrl, WebviewWindowBuilder};

/// An error the page can show. Text goes out to the page only, never in.
#[derive(Debug, Clone, Serialize)]
pub struct CommandError {
    /// What went wrong, in words for the owner.
    pub message: String,
}

impl CommandError {
    fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

type Reply<T> = Result<T, CommandError>;

const NOT_YET: &str = "not built yet";

/// Start a scan in the background (a new scan makes every earlier ID stale).
#[tauri::command]
fn start_scan() -> Reply<()> {
    Err(CommandError::new(NOT_YET))
}

/// Stop the running scan, if any.
#[tauri::command]
fn cancel_scan() -> Reply<()> {
    Err(CommandError::new(NOT_YET))
}

/// Progress and findings so far.
#[tauri::command]
fn scan_state() -> Reply<()> {
    Err(CommandError::new(NOT_YET))
}

/// Turn the owner's choices into a preview of exactly what would happen.
#[tauri::command]
fn preview(choices: Vec<Choice>) -> Reply<()> {
    let _ = choices;
    Err(CommandError::new(NOT_YET))
}

/// Act on exactly the confirmed preview, once.
#[tauri::command]
fn clean(preview_id: PreviewId) -> Reply<()> {
    let _ = preview_id;
    Err(CommandError::new(NOT_YET))
}

/// Ask the owner for a move destination with Windows' own folder dialog (run by Rust).
#[tauri::command]
fn pick_move_destination() -> Reply<()> {
    Err(CommandError::new(NOT_YET))
}

/// Open the Recycle Bin in Explorer, so the owner can restore or empty it.
#[tauri::command]
fn open_recycle_bin() -> Reply<()> {
    Err(CommandError::new(NOT_YET))
}

/// True for the app's own pages; the window never navigates anywhere else.
pub fn is_app_url(url: &tauri::Url) -> bool {
    matches!(
        (url.scheme(), url.host_str()),
        ("tauri", Some("localhost")) | ("http" | "https", Some("tauri.localhost"))
    ) && url.port().is_none()
}

/// Build and run the app. Returns when the window closes.
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            start_scan,
            cancel_scan,
            scan_state,
            preview,
            clean,
            pick_move_destination,
            open_recycle_bin,
        ])
        .setup(|app| {
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title(format!("ByteBroom {}", bytebroom_core::VERSION))
                .inner_size(1100.0, 760.0)
                .min_inner_size(720.0, 520.0)
                .on_navigation(is_app_url)
                .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_apps_own_pages_are_allowed() {
        for ok in [
            "tauri://localhost/index.html",
            "http://tauri.localhost/index.html",
            "https://tauri.localhost/",
        ] {
            assert!(is_app_url(&tauri::Url::parse(ok).unwrap()), "{ok}");
        }
        for bad in [
            "https://example.com/",
            "http://tauri.localhost.example.com/",
            "http://localhost:1420/",
            "http://tauri.localhost:8080/",
            "file:///C:/Windows/",
            "ms-settings:storagesense",
            "javascript:alert(1)",
        ] {
            assert!(!is_app_url(&tauri::Url::parse(bad).unwrap()), "{bad}");
        }
    }
}
