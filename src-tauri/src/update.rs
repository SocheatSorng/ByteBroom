//! Updates (phase 6, owner's decisions 2 and 5): at start the window asks Rust once whether a
//! newer ByteBroom is out; if so it shows "Update available: install?", and only on the owner's
//! yes does Rust download, check and run it.
//!
//! Everything that matters happens here, not in the page:
//! - the endpoint and the public key are fixed in `tauri.conf.json` (`tests/boundary.rs` pins
//!   them: https, this repo's Releases only, no insecure-transport switch, no override in code);
//! - the page sends nothing: `update_check` and `install_update` take no input;
//! - an announced update is used only if it is a plain version and its download is this repo's
//!   release of exactly that version (security review S8);
//! - the plugin verifies the download against the owner's public key, and the signed version
//!   against the announced one (`requireSignedVersion`), before installing; `tests/updater.rs`
//!   proves a tampered file, another key and a mismatched version are refused;
//! - installing is refused unless this window runs, unelevated, from the admin-owned install in
//!   `Program Files\ByteBroom` (security review M1, N3), and it waits for nothing: it is refused
//!   while a red-tier action runs, and takes the history lock that every clean and put-back holds,
//!   because on Windows the plugin exits the app to run the installer (S3). One install at a time.

use crate::history_cmd::History;
use crate::{CommandError, Layout, RedBusy, Reply};
use bytebroom_core::paths::WinPath;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use tauri::{AppHandle, State};
use tauri_plugin_updater::{Update, UpdaterExt};

/// Where every release's files are downloaded from: this repo's Releases, tag `v<version>`.
pub const RELEASE_DOWNLOADS: &str = "https://github.com/SocheatSorng/ByteBroom/releases/download/";

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
    installing: AtomicBool,
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

/// True when `url` is this repo's release of exactly `version` (no query, fragment or `..`).
pub fn is_release_download(version: &str, url: &str) -> bool {
    let prefix = format!("{RELEASE_DOWNLOADS}v{version}/");
    url.strip_prefix(&prefix).is_some_and(|file| {
        !file.is_empty()
            && file
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            && !file.contains("..")
    })
}

/// The window's own file once installed: beside the helper, `<Program Files>\ByteBroom`.
fn installed_window() -> Option<WinPath> {
    let helper = bytebroom_core::win::admin::helper_path()?;
    let parts = helper.parts();
    let mut dir = WinPath::drive_root(helper.drive());
    for part in &parts[..parts.len().checked_sub(1)?] {
        dir = dir.join(part).ok()?;
    }
    dir.join("bytebroom.exe").ok()
}

/// Why installing an update from this window is refused, or `None` if it may go ahead. Pure, so
/// the rule is tested; `install_update` feeds it the real facts.
pub fn install_refusal(
    own: Option<&WinPath>,
    installed: Option<&WinPath>,
    location_problem: impl Fn(&WinPath) -> Option<String>,
    elevated: bool,
) -> Option<String> {
    if elevated {
        return Some(
            "ByteBroom is running as administrator. Close it, open it normally, then install the update."
                .into(),
        );
    }
    let (Some(own), Some(installed)) = (own, installed) else {
        return Some(
            "ByteBroom can't tell where it is installed, so it won't update itself.".into(),
        );
    };
    if !own.eq_ignore_case(installed) {
        return Some(format!(
            "this copy of ByteBroom isn't the installed one in {installed}. Download the new version from the Releases page instead."
        ));
    }
    location_problem(own).map(|why| {
        format!("ByteBroom's install folder isn't protected as expected ({why}). Reinstall it.")
    })
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
            Ok(Some(u)) if view(&u).is_some() => Some(Box::new(u)),
            Ok(Some(_)) => {
                log(
                    &layout,
                    "update check: ignored an announcement that isn't this repo's release",
                );
                None
            }
            Ok(None) => None,
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
    let version = shown_version(&update.version)?;
    is_release_download(&version, update.download_url.as_str()).then_some(UpdateView { version })
}

/// Clears the "installing" flag when an install attempt ends without the app exiting.
struct Installing<'a>(&'a AtomicBool);

impl Drop for Installing<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
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
    use bytebroom_core::win::admin::{is_elevated, location_problem, own_exe};
    if let Some(why) = install_refusal(
        own_exe().as_ref(),
        installed_window().as_ref(),
        location_problem,
        is_elevated(),
    ) {
        log(
            &layout,
            "update install: refused, not the protected install",
        );
        return Err(CommandError::new(&format!("{why} Nothing was installed.")));
    }
    if updates
        .installing
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(CommandError::new("the update is already being installed"));
    }
    let _installing = Installing(&updates.installing);
    let Some(red_busy) = RedBusy::take() else {
        return Err(CommandError::new(
            "a red-tier action is still running. Nothing was installed; try again when it's done.",
        ));
    };
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
        // No clean, put-back or red action runs from here on: the app exits inside `install`.
        let _red = red_busy;
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

    #[test]
    fn downloads_come_only_from_this_repos_release_of_that_version() {
        let ok = "https://github.com/SocheatSorng/ByteBroom/releases/download/v1.0.1/ByteBroom_1.0.1_x64-setup.exe";
        assert!(is_release_download("1.0.1", ok));
        for bad in [
            // another repo, host or scheme
            "https://github.com/evil/ByteBroom/releases/download/v1.0.1/ByteBroom_1.0.1_x64-setup.exe",
            "https://example.com/SocheatSorng/ByteBroom/releases/download/v1.0.1/x.exe",
            "http://github.com/SocheatSorng/ByteBroom/releases/download/v1.0.1/x.exe",
            // another release of this repo
            "https://github.com/SocheatSorng/ByteBroom/releases/download/v0.9.0/x.exe",
            "https://github.com/SocheatSorng/ByteBroom/releases/download/v1.0.10/x.exe",
            // tricks after the prefix
            "https://github.com/SocheatSorng/ByteBroom/releases/download/v1.0.1/",
            "https://github.com/SocheatSorng/ByteBroom/releases/download/v1.0.1/../v0.9.0/x.exe",
            "https://github.com/SocheatSorng/ByteBroom/releases/download/v1.0.1/x.exe?x=1",
            "https://github.com/SocheatSorng/ByteBroom/releases/download/v1.0.1/x.exe#a",
        ] {
            assert!(!is_release_download("1.0.1", bad), "{bad}");
        }
    }

    #[test]
    fn only_the_unelevated_protected_install_updates_itself() {
        let p = |s: &str| WinPath::parse(s).unwrap();
        let installed = p("C:\\Program Files\\ByteBroom\\bytebroom.exe");
        let fine = |_: &WinPath| None;
        let open = |_: &WinPath| Some("Users can change it".to_string());

        assert_eq!(
            install_refusal(Some(&installed), Some(&installed), fine, false),
            None
        );
        // the same file, spelled with another case
        let lower = p("c:\\program files\\bytebroom\\BYTEBROOM.EXE");
        assert_eq!(
            install_refusal(Some(&lower), Some(&installed), fine, false),
            None
        );

        // a copy elsewhere (a custom install folder, a dev build)
        let elsewhere = p("D:\\Tools\\ByteBroom\\bytebroom.exe");
        assert!(install_refusal(Some(&elsewhere), Some(&installed), fine, false).is_some());
        // the right place, but someone other than administrators can change it
        assert!(install_refusal(Some(&installed), Some(&installed), open, false).is_some());
        // running as administrator: no update without Windows' own prompt
        assert!(install_refusal(Some(&installed), Some(&installed), fine, true).is_some());
        // unknown places
        assert!(install_refusal(None, Some(&installed), fine, false).is_some());
        assert!(install_refusal(Some(&installed), None, fine, false).is_some());
    }
}
