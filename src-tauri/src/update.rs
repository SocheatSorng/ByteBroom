//! Updates (phase 6, owner's decisions 2 and 5): at start the window asks Rust once whether a
//! newer ByteBroom is out; if so it shows "Update available: install?", and only on the owner's
//! yes does Rust download, check and run it.
//!
//! Everything that matters happens here, not in the page:
//! - the endpoint and the public key are fixed in `tauri.conf.json` (`tests/boundary.rs` pins
//!   them: https, this repo's Releases only, no `dangerous*` switch);
//! - the page sends nothing: `update_check` and `install_update` take no input;
//! - the plugin verifies the download against the owner's public key, and the signed version
//!   against the announced one (`requireSignedVersion`), before installing; `tests/updater.rs`
//!   proves a tampered file, another key and a mismatched version are refused;
//! - installing waits for any clean or put-back to finish (it takes the history lock they hold),
//!   because on Windows the plugin exits the app to run the installer.

use crate::history_cmd::History;
use crate::{CommandError, Layout, Reply};
use serde::Serialize;
use std::sync::{Arc, Mutex, PoisonError};
use tauri::{AppHandle, State};
use tauri_plugin_updater::{Update, UpdaterExt};

/// What the page may show about an update: its version number, nothing else (the release notes
/// in `latest.json` are not signed, so they're never shown).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateView {
    /// The new version, as plain `1.2.3`-style text.
    pub version: String,
}

/// The update found at start, if any, kept for `install_update`.
#[derive(Default)]
pub struct Updates {
    state: Mutex<Checked>,
}

#[derive(Default)]
enum Checked {
    #[default]
    NotYet,
    Done(Option<Box<Update>>),
}

/// A version the page may show: digits, letters, dots, `-` and `+` only, at most 32 characters,
/// starting with a digit. Anything else means "no update" (the announcement isn't signed).
pub fn shown_version(announced: &str) -> Option<String> {
    let ok = !announced.is_empty()
        && announced.len() <= 32
        && announced.starts_with(|c: char| c.is_ascii_digit())
        && announced
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'));
    ok.then(|| announced.to_string())
}

fn log(layout: &Layout, line: &str) {
    let base = bytebroom_core::win::locations::locations(&layout.0).local_app_data;
    crate::confirm::log(base.as_ref(), line);
}

/// Check once for a newer version. Being offline, or any other failure, just means "no update";
/// it's logged without detail beyond the kind of failure.
#[tauri::command]
pub async fn update_check(
    app: AppHandle,
    updates: State<'_, Arc<Updates>>,
    layout: State<'_, Layout>,
) -> Reply<Option<UpdateView>> {
    {
        let state = updates.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Checked::Done(found) = &*state {
            return Ok(found.as_deref().and_then(view));
        }
    }
    let found = match app.updater() {
        Ok(updater) => match updater.check().await {
            Ok(found) => found.filter(|u| view(u).is_some()).map(Box::new),
            Err(_) => {
                log(&layout, "update check: failed (offline or no release)");
                None
            }
        },
        Err(_) => {
            log(&layout, "update check: the updater is not set up");
            None
        }
    };
    let shown = found.as_deref().and_then(view);
    if let Some(v) = &shown {
        log(&layout, &format!("update check: {} available", v.version));
    }
    let mut state = updates.state.lock().unwrap_or_else(PoisonError::into_inner);
    *state = Checked::Done(found);
    Ok(shown)
}

fn view(update: &Update) -> Option<UpdateView> {
    shown_version(&update.version).map(|version| UpdateView { version })
}

/// Download, verify and install the update found at start. The owner has said yes in the page;
/// Windows then asks for administrator rights (UAC) for the per-machine installer, and the app
/// closes while it runs.
#[tauri::command]
pub async fn install_update(
    updates: State<'_, Arc<Updates>>,
    history: State<'_, Arc<History>>,
    layout: State<'_, Layout>,
) -> Reply<()> {
    let update = {
        let state = updates.state.lock().unwrap_or_else(PoisonError::into_inner);
        match &*state {
            Checked::Done(Some(u)) => (**u).clone(),
            _ => return Err(CommandError::new("there is no update to install")),
        }
    };
    // `download` verifies the signature and the signed version before returning the bytes.
    let bytes = match update.download(|_, _| {}, || {}).await {
        Ok(bytes) => bytes,
        Err(e) => {
            let refused = matches!(
                e,
                tauri_plugin_updater::Error::Minisign(_)
                    | tauri_plugin_updater::Error::Base64(_)
                    | tauri_plugin_updater::Error::SignatureUtf8(_)
                    | tauri_plugin_updater::Error::SignedVersionMismatch { .. }
                    | tauri_plugin_updater::Error::MissingSignedVersion
            );
            log(
                &layout,
                if refused {
                    "update install: REFUSED, the signature did not match"
                } else {
                    "update install: download failed"
                },
            );
            return Err(CommandError::new(if refused {
                "the update was refused: its signature doesn't match ByteBroom's key. Nothing was installed."
            } else {
                "the update couldn't be downloaded. Nothing was installed; try again later."
            }));
        }
    };
    log(
        &layout,
        &format!("update install: {} verified, starting", update.version),
    );
    let history = history.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        // No clean or put-back is running from here on: the app exits inside `install`.
        let _history = history.lock();
        // `install` verifies the bytes again before running the installer.
        update.install(bytes)
    })
    .await
    .map_err(|_| CommandError::new("the update stopped unexpectedly. Nothing was installed."))?
    .map_err(|_| CommandError::new("the installer couldn't start. Nothing was installed."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_version_text_reaches_the_page() {
        for ok in ["1.0.1", "1.2.3-beta.1", "2.0.0+build.5", "10.20.30"] {
            assert_eq!(shown_version(ok).as_deref(), Some(ok), "{ok}");
        }
        for bad in [
            "",
            "v1.0.1",
            "1.0.1<script>",
            "1.0.1 now",
            "1.0.1\n",
            "../1.0",
            "1.0.1\"",
            "1.0.\u{200b}1",
            "123456789012345678901234567890123",
        ] {
            assert_eq!(shown_version(bad), None, "{bad:?}");
        }
    }
}
