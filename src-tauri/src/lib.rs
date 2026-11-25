//! ByteBroom's window. The page refers to findings by the IDs a scan handed out; every decision is
//! made here, from Rust's own copy of the scan, by `bytebroom-core`.
//!
//! The command list is the boundary: `tests/boundary.rs` checks it against `build.rs`, the
//! capability file and an allow-list, and checks that no command takes text or a path.

#![forbid(unsafe_code)]

pub mod boundary;
pub mod confirm;
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

/// The owner's local app data folder, where ByteBroom keeps its journal and log.
fn local_app_data(layout: &SystemLayout) -> Option<WinPath> {
    bytebroom_core::win::locations::locations(layout).local_app_data
}

/// The move journal, `ByteBroom\moves.journal` in the owner's local app data, outside any repo.
/// The folder and file are opened without following links (security review note 7).
fn open_journal(layout: &SystemLayout) -> Result<bytebroom_core::relocate::Journal, String> {
    let base = local_app_data(layout).ok_or("local app data can't be found")?;
    let dir = bytebroom_core::relocate::app_folder(&base)?;
    bytebroom_core::relocate::Journal::open(&dir, "moves.journal")
}

/// Act on exactly the confirmed preview, once: Rust takes the preview it built (the page sends
/// only its ID), checks every item again right before acting, and reports what happened.
///
/// The page's confirmations are for the owner's convenience; this is the one a page can't skip.
/// When the preview touches any amber item (the owner's own files), Rust asks again in Windows'
/// own dialog, over the main window, with the count and size, before anything is done
/// (security review). Only "Clean them", pressed after reading, goes ahead; see `confirm`.
#[tauri::command]
async fn clean(
    app: AppHandle,
    session: State<'_, Arc<Session>>,
    layout: State<'_, Layout>,
    preview_id: PreviewId,
) -> Reply<CleanView> {
    let (ready, guard) = session
        .take_preview(preview_id)
        .map_err(|e| CommandError::new(&e))?;
    if let Some(question) = amber_question(&ready) {
        let items = ready.preview.confirm_amber.len();
        let base = local_app_data(&layout.0);
        // The dialog blocks until answered, so it runs off the async runtime.
        let verdict = tauri::async_runtime::spawn_blocking(move || {
            confirm::ask(&app, &question, items, base.as_ref())
        })
        .await
        .unwrap_or(confirm::Verdict::Unavailable);
        if let Some(why) = confirm::refusal(verdict) {
            guard.nothing_done();
            return Err(CommandError::new(why));
        }
    }
    let layout = layout.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let journal = open_journal(&layout).map_err(|why| {
            CommandError::new(&format!(
                "nothing was cleaned: ByteBroom's folder in local app data can't be used ({why})"
            ))
        })?;
        let ctx = bytebroom_core::act::Context {
            layout: &layout,
            now: SystemTime::now(),
            journal: &journal,
            recycle: &bytebroom_core::recycle::recycle_targets,
        };
        let results = bytebroom_core::act::carry_out(&ready.findings, &ready.preview, &ctx);
        Ok(view::clean_view(&results, ready.preview.move_to.as_ref()))
    })
    .await
    .map_err(|_| {
        CommandError::new("the clean stopped unexpectedly; scan again to see what is left")
    })?
}

/// The question Rust asks in its own dialog before a clean that touches amber items, or `None`
/// when the preview has none. Names how many, how big, what happens, and up to five paths.
pub fn amber_question(ready: &session::Ready) -> Option<String> {
    let pv = &ready.preview;
    if pv.confirm_amber.is_empty() {
        return None;
    }
    let amber: Vec<&bytebroom_core::scan::Finding> = pv
        .confirm_amber
        .iter()
        .filter_map(|n| ready.findings.get(*n))
        .collect();
    let bytes: u64 = amber.iter().map(|f| f.bytes).sum();
    let mut text = format!(
        "{} of your own file{} ({}) will be cleaned as the preview showed:\n",
        amber.len(),
        if amber.len() == 1 { "" } else { "s" },
        bytebroom_core::summary::human_bytes(bytes),
    );
    for a in &pv.actions {
        let n = a
            .items
            .iter()
            .filter(|i| pv.confirm_amber.contains(i))
            .count();
        if n > 0 {
            let what = match a.action {
                bytebroom_core::preview::Action::Delete => "deleted for good",
                bytebroom_core::preview::Action::Move => "moved",
                bytebroom_core::preview::Action::Recycle => "sent to the Recycle Bin",
            };
            text.push_str(&format!("\n- {n} {what}"));
        }
    }
    text.push_str("\n\n");
    for f in amber.iter().take(5) {
        text.push_str(&format!("{}\n", f.path));
    }
    if amber.len() > 5 {
        text.push_str(&format!("and {} more\n", amber.len() - 5));
    }
    Some(text)
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

static RED_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Held while a red-tier action runs; released when dropped, even on an error.
pub struct RedBusy(());

impl RedBusy {
    /// Take the one slot, or `None` if an action is already running.
    pub fn take() -> Option<Self> {
        use std::sync::atomic::Ordering;
        RED_BUSY
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self(()))
    }
}

impl Drop for RedBusy {
    fn drop(&mut self) {
        RED_BUSY.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// The red tier's actions and their texts (phase 4).
#[tauri::command]
fn red_actions() -> Vec<view::RedActionView> {
    view::red_action_views()
}

/// Do one red-tier action the owner confirmed on the page, then measure the red sizes again.
/// The page's typed confirm can be skipped by a page, so a native question always comes first:
/// Windows' own dialog for the Recycle Bin (decision 8), the UAC prompt for the rest; the
/// helper then makes a restore point before changing anything (decision 5).
#[tauri::command]
async fn run_red_action(
    app: AppHandle,
    layout: State<'_, Layout>,
    action: boundary::RedActionId,
) -> Reply<view::RedActionResult> {
    // One red action at a time, whatever the page sends (security review S1): a page can't
    // stack UAC prompts or run two helpers at once.
    let Some(_busy) = RedBusy::take() else {
        return Err(CommandError::new(
            "another red-tier action is still running; nothing new was started",
        ));
    };
    let layout = layout.0.clone();
    let base = local_app_data(&layout);
    let message = tauri::async_runtime::spawn_blocking(move || -> Result<String, String> {
        let red = action.action();
        match red.admin_action() {
            None => {
                // Windows reports an error when asked to empty an empty bin (owner's check,
                // 2026-11-25), so say so plainly instead of asking.
                if bytebroom_core::win::red::recycle_bin_size() == Some(0) {
                    return Ok("The Recycle Bin is already empty: nothing to do.".to_string());
                }
                let verdict = confirm::ask_empty_recycle_bin(&app, base.as_ref());
                if let Some(why) = confirm::empty_refusal(verdict) {
                    return Err(why.to_string());
                }
                let parent = confirm::main_window(&app).unwrap_or(0);
                bytebroom_core::win::recycle::empty_recycle_bin(parent)
                    .map(|()| "The Recycle Bin was emptied.".to_string())
                    .map_err(|_| {
                        "Windows did not empty the Recycle Bin."
                            .to_string()
                    })
            }
            Some(admin) => {
                use bytebroom_core::win::admin::{LaunchError, run_elevated};
                let parent = confirm::main_window(&app).unwrap_or(0);
                match run_elevated(admin, parent) {
                    Ok(bytebroom_core::admin::Exit::Done) => {
                        Ok(format!("{}: done.", red.title()))
                    }
                    Ok(exit) => Err(format!("{}: {}.", red.title(), exit.describe())),
                    Err(LaunchError::Cancelled) => {
                        Err("Cancelled at the Windows prompt: nothing was changed.".to_string())
                    }
                    Err(LaunchError::NotInstalled) => Err(
                        "The helper isn't installed: run ./tools/install-helper.ps1 as administrator. Nothing was changed."
                            .to_string(),
                    ),
                    Err(LaunchError::Untrusted(why)) => {
                        Err(format!("The helper wasn't started: {why}. Nothing was changed."))
                    }
                    Err(LaunchError::Failed(why)) => {
                        Err(format!("The helper couldn't run: {why}."))
                    }
                }
            }
        }
    })
    .await
    .map_err(|_| CommandError::new("the action could not run"))?
    .map_err(|e| CommandError::new(&e))?;
    let red = tauri::async_runtime::spawn_blocking(move || {
        use bytebroom_core::walk::WalkOptions;
        let at = bytebroom_core::win::locations::locations(&layout);
        bytebroom_core::win::red::red_sizes(&at, &layout, &WalkOptions::default())
    })
    .await
    .map_err(|_| CommandError::new("the sizes could not be measured again"))?;
    Ok(view::RedActionResult {
        message,
        red: view::red_views(&red),
    })
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
            red_actions,
            run_red_action,
        ])
        .setup(|app| {
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title(format!("ByteBroom {}", bytebroom_core::VERSION))
                .inner_size(1100.0, 760.0)
                .min_inner_size(720.0, 520.0)
                .on_navigation(is_app_url)
                // No pop-up windows of any kind (security review note 6).
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_asks_before_cleaning_amber_items_and_says_what_and_how_much() {
        use bytebroom_core::preview::{Action, Choice, preview};
        use bytebroom_core::rules::RULES;
        let p = |s: &str| WinPath::parse(s).unwrap();
        let f = |rule: &str, path: &str, bytes: u64| {
            let rule = RULES.iter().find(|r| r.id == rule).unwrap();
            let path = p(path);
            bytebroom_core::scan::Finding {
                rule,
                tier: rule.tier,
                root: p(path.to_string().rsplit_once('\\').unwrap().0),
                path,
                is_folder: false,
                bytes,
                files: 1,
                newest: std::time::UNIX_EPOCH,
                cloud: false,
                pre_ticked: rule.pre_ticked(),
                duplicate_of: None,
                identity: None,
            }
        };
        let findings = Arc::new(vec![
            f("user-temp", "C:\\T\\a.tmp", 10),
            f("large-files", "D:\\Big\\film.mkv", 3 * 1024 * 1024 * 1024),
            f("old-installers", "D:\\Dl\\setup.exe", 1024 * 1024),
        ]);
        let layout = SystemLayout {
            system_root: p("C:\\Windows"),
            program_files: vec![p("C:\\Program Files")],
            program_data: p("C:\\ProgramData"),
            profiles_dir: p("C:\\Users"),
            profile_roots: vec![p("C:\\Users\\Ann")],
            extra_denied: Vec::new(),
        };
        let ready = |choices: &[Choice]| session::Ready {
            id: PreviewId { scan: 1, number: 1 },
            preview: Arc::new(preview(&findings, choices, None, &layout).unwrap()),
            findings: findings.clone(),
        };
        let green_only = ready(&[Choice {
            index: 0,
            action: Action::Delete,
        }]);
        assert_eq!(amber_question(&green_only), None);
        let mixed = ready(&[
            Choice {
                index: 0,
                action: Action::Delete,
            },
            Choice {
                index: 1,
                action: Action::Delete,
            },
            Choice {
                index: 2,
                action: Action::Recycle,
            },
        ]);
        let q = amber_question(&mixed).unwrap();
        assert!(q.starts_with("2 of your own files ("), "{q}");
        assert!(q.contains("- 1 deleted for good"), "{q}");
        assert!(q.contains("- 1 sent to the Recycle Bin"), "{q}");
        assert!(
            q.contains("D:\\Big\\film.mkv") && q.contains("D:\\Dl\\setup.exe"),
            "{q}"
        );
        assert!(!q.contains("a.tmp"), "only amber items are listed: {q}");
    }

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
