//! ByteBroom's window. The page refers to findings by the IDs a scan handed out; every decision is
//! made here, from Rust's own copy of the scan, by `bytebroom-core`.
//!
//! The command list is the boundary: `tests/boundary.rs` checks it against `build.rs`, the
//! capability file and an allow-list, and checks that no command takes text or a path.

#![forbid(unsafe_code)]

pub mod boundary;
pub mod session;
pub mod view;

use boundary::{Choice, PreviewId};
use bytebroom_core::paths::WinPath;
use bytebroom_core::policy::{SystemLayout, denied_reason};
use serde::Serialize;
use session::{Reporter, Session};
use std::sync::Arc;
use std::time::SystemTime;
use tauri::{AppHandle, State, WebviewUrl, WebviewWindowBuilder};
use view::{CleanView, PreviewView, ScanView};

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

/// The real scan of this PC, run on the session's thread. Only reads.
fn scan_this_pc(r: Reporter) {
    use bytebroom_core::scan::{ScanOptions, scan_in_steps};
    use bytebroom_core::walk::WalkOptions;
    use bytebroom_core::win::locations::locations;
    use bytebroom_core::win::red::red_sizes;
    use bytebroom_core::win::system_layout;

    let layout = system_layout();
    let at = locations(&layout);
    r.skipped(at.skipped.clone());
    // Red-tier sizes on their own thread, so they don't hold up the list.
    let red = {
        let (r, at, layout) = (r.clone(), at.clone(), layout.clone());
        std::thread::Builder::new()
            .name("red sizes".into())
            .spawn(move || {
                let opts = WalkOptions {
                    cancel: Some(&r.cancel),
                    ..WalkOptions::default()
                };
                r.red(red_sizes(&at, &layout, &opts));
            })
    };
    let opts = ScanOptions {
        now: SystemTime::now(),
        cancel: Some(&r.cancel),
    };
    let report = scan_in_steps(&at, &layout, &opts, |first| r.first_step(&first.findings));
    r.finished(report.findings, report.cancelled);
    if let Ok(red) = red {
        let _ = red.join();
    }
}

/// Start a scan in the background (a new scan makes every earlier ID stale).
#[tauri::command]
fn start_scan(session: State<'_, Arc<Session>>) -> Reply<()> {
    let (_, thread) = session.start(scan_this_pc);
    thread
        .map(|_| ())
        .map_err(|_| CommandError::new("Windows could not start the scan"))
}

/// Stop the running scan, if any. What it found so far stays listed.
#[tauri::command]
fn cancel_scan(session: State<'_, Arc<Session>>) {
    session.cancel();
}

/// Progress, red-tier sizes and, when they changed since version `seen`, the findings.
#[tauri::command]
fn scan_state(session: State<'_, Arc<Session>>, layout: State<'_, Layout>, seen: u32) -> ScanView {
    view::scan_view(&session.snapshot(), seen, &layout.0)
}

/// Turn the owner's choices into a preview of exactly what would happen. Rust looks every ID up
/// in its own copy of the scan; the preview is kept for `clean`.
#[tauri::command]
fn preview(
    session: State<'_, Arc<Session>>,
    layout: State<'_, Layout>,
    choices: Vec<Choice>,
) -> Reply<PreviewView> {
    session
        .make_preview(&choices, &layout.0)
        .map(|ready| view::preview_view(&ready))
        .map_err(|e| CommandError::new(&e))
}

/// The system layout (Windows, Program Files, profiles), read once at start.
pub struct Layout(pub SystemLayout);

/// Why `dest` can't take moved files, or `None` if it can: it must be on a fixed drive and off
/// the hard floor (Windows, Program Files, a profile root, a drive root). Pure; the move itself
/// checks the folder again on disk when it runs.
pub fn destination_problem(
    dest: &WinPath,
    fixed_drives: &[char],
    layout: &SystemLayout,
) -> Option<String> {
    if !fixed_drives
        .iter()
        .any(|d| d.eq_ignore_ascii_case(&dest.drive()))
    {
        return Some("choose a folder on a fixed drive (not removable or network)".into());
    }
    denied_reason(dest, layout).map(|why| format!("that folder is protected ({why})"))
}

/// Where moves are journalled: `ByteBroom\moves.journal` in the owner's local app data, outside
/// any repo. `None` when that folder can't be found or made.
fn journal_path(layout: &SystemLayout) -> Option<std::path::PathBuf> {
    let at = bytebroom_core::win::locations::locations(layout);
    let dir = std::path::PathBuf::from(at.local_app_data?.to_string()).join("ByteBroom");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("moves.journal"))
}

/// Act on exactly the confirmed preview, once: Rust takes the preview it built (the page sends
/// only its ID), checks every item again right before acting, and reports what happened.
#[tauri::command]
async fn clean(
    session: State<'_, Arc<Session>>,
    layout: State<'_, Layout>,
    preview_id: PreviewId,
) -> Reply<CleanView> {
    let ready = session
        .take_preview(preview_id)
        .map_err(|e| CommandError::new(&e))?;
    let layout = layout.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let journal = journal_path(&layout).ok_or_else(|| {
            CommandError::new("ByteBroom's folder in local app data can't be made")
        })?;
        let ctx = bytebroom_core::act::Context {
            layout: &layout,
            now: SystemTime::now(),
            journal: &journal,
            recycle: &bytebroom_core::recycle::recycle,
        };
        let results = bytebroom_core::act::carry_out(&ready.findings, &ready.preview, &ctx);
        Ok(view::clean_view(&results, ready.preview.move_to.as_ref()))
    })
    .await
    .map_err(|_| {
        CommandError::new("the clean stopped unexpectedly; scan again to see what is left")
    })?
}

/// Ask the owner for a move destination with Windows' own folder dialog, run by Rust (the page
/// has no dialog permission and never sends a path). Returns the folder to show, or `None` if
/// the owner closed the dialog.
#[tauri::command]
async fn pick_move_destination(
    app: AppHandle,
    session: State<'_, Arc<Session>>,
    layout: State<'_, Layout>,
) -> Reply<Option<String>> {
    use bytebroom_core::win::{Access, open_no_follow};
    use tauri_plugin_dialog::DialogExt;

    let Some(picked) = app
        .dialog()
        .file()
        .set_title("Move to which folder? (on another drive)")
        .blocking_pick_folder()
    else {
        return Ok(None);
    };
    let fail = |m: &str| CommandError::new(m);
    let path = picked
        .into_path()
        .map_err(|_| fail("that folder can't be used"))?;
    let text = path
        .to_str()
        .ok_or_else(|| fail("that folder's name can't be used"))?;
    let asked = WinPath::parse(text).map_err(|_| fail("that folder can't be used"))?;
    let opened = open_no_follow(&asked, Access::Inspect).map_err(|e| fail(&e.to_string()))?;
    if opened.resolved.is_reparse_point || !opened.is_directory {
        return Err(fail("choose a real folder (not a link or shortcut)"));
    }
    let dest = opened.resolved.final_path;
    let fixed = bytebroom_core::win::locations::fixed_drives();
    if let Some(problem) = destination_problem(&dest, &fixed, &layout.0) {
        return Err(fail(&problem));
    }
    session.set_move_to(dest.clone());
    Ok(Some(dest.to_string()))
}

/// Open the Recycle Bin in Explorer, so the owner can restore or empty it. Runs Windows' own
/// Explorer from the Windows folder, with a fixed argument.
#[tauri::command]
fn open_recycle_bin(layout: State<'_, Layout>) -> Reply<()> {
    let explorer = std::path::PathBuf::from(layout.0.system_root.to_string()).join("explorer.exe");
    std::process::Command::new(explorer)
        .arg("shell:RecycleBinFolder")
        .spawn()
        .map(|_| ())
        .map_err(|_| CommandError::new("Explorer could not be opened"))
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
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(Session::default()))
        .manage(Layout(bytebroom_core::win::system_layout()))
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
    fn moves_go_only_to_unprotected_folders_on_fixed_drives() {
        let p = |s: &str| WinPath::parse(s).unwrap();
        let layout = SystemLayout {
            system_root: p("C:\\Windows"),
            program_files: vec![p("C:\\Program Files")],
            program_data: p("C:\\ProgramData"),
            profiles_dir: p("C:\\Users"),
            profile_roots: vec![p("C:\\Users\\Ann")],
            extra_denied: Vec::new(),
        };
        let fixed = ['C', 'D'];
        assert_eq!(destination_problem(&p("D:\\Keep"), &fixed, &layout), None);
        assert_eq!(
            destination_problem(&p("d:\\Keep\\Old"), &fixed, &layout),
            None
        );
        for bad in [
            "E:\\Stick",
            "D:\\",
            "C:\\Windows\\Temp2",
            "C:\\Program Files\\X",
            "C:\\Users\\Ann",
        ] {
            assert!(
                destination_problem(&p(bad), &fixed, &layout).is_some(),
                "{bad}"
            );
        }
    }

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
