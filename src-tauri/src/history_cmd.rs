//! The History view's commands (phase 5), and the only place in the window that opens, reads,
//! writes or clears ByteBroom's journals. `crates/core/tests/locked.rs` checks that.
//!
//! The journals are user-writable, so nothing here runs elevated (rule S3; security review,
//! phase 5, S1): putting back and clearing are refused when the window has an administrator
//! token, and the core functions refuse too.

use crate::view;
use crate::{CommandError, Layout, Reply, boundary, local_app_data};
use bytebroom_core::history::{
    HISTORY_FILES, RecycledJournal, group_by_clean, move_history, refuse_if_elevated,
};
use bytebroom_core::policy::SystemLayout;
use bytebroom_core::relocate::{Journal, JournalEntry};
use bytebroom_core::win::dir::LockedDir;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tauri::State;

/// Is the window running with an administrator token? Windows' own answer.
fn elevated() -> bool {
    bytebroom_core::win::admin::is_elevated()
}

/// ByteBroom's folder in the owner's local app data, held, reached without following links.
pub(crate) fn app_dir(layout: &SystemLayout) -> Result<LockedDir, String> {
    let base = local_app_data(layout).ok_or("local app data can't be found")?;
    bytebroom_core::relocate::app_folder(&base)
}

/// The move journal, `ByteBroom\moves.journal` in the owner's local app data, outside any repo.
/// The folder and file are opened without following links (security review note 7).
pub(crate) fn open_journal(dir: &LockedDir) -> Result<Journal, String> {
    Journal::open(dir, HISTORY_FILES[0])
}

/// Decision 2: record what one clean recycled in `recycled.journal` (names stay in local app
/// data; the log keeps counts only). Returns the owner's note if it could not.
pub(crate) fn record_recycled(
    dir: &LockedDir,
    clean: u64,
    results: &[bytebroom_core::act::ActionResult],
) -> Option<String> {
    let records = bytebroom_core::history::recycled_records(clean, results);
    RecycledJournal::open(dir)
        .and_then(|j| j.append(&records))
        .err()
        .map(|why| {
            format!(
                "The clean is done, but the history could not list what was recycled ({why}). \
                 Those items are in the Recycle Bin."
            )
        })
}

/// The history list the page was last given. Its mutex is also the one lock every journal
/// write and read in this window takes, so a clean, a put-back and a clear never overlap.
#[derive(Default)]
pub struct History {
    inner: Mutex<HistoryList>,
}

/// The moves the last History view listed, by its numbering.
#[derive(Default)]
pub(crate) struct HistoryList {
    list: u32,
    groups: Vec<Vec<JournalEntry>>,
}

impl History {
    pub(crate) fn lock(&self) -> MutexGuard<'_, HistoryList> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Why a still-moved file can't be put back now, from a quick look that only reads. Putting
/// back checks everything again.
fn put_back_unavailable(entry: &JournalEntry) -> Option<&'static str> {
    use bytebroom_core::win::{Access, OpenError, open_no_follow};
    match open_no_follow(&entry.dest, Access::Inspect) {
        Ok(o) if o.is_directory || o.resolved.is_reparse_point => {
            return Some("the moved file is not a plain file any more");
        }
        Ok(_) => {}
        Err(OpenError::NotFound) => {
            return Some("the moved file isn't there (is its drive plugged in?)");
        }
        Err(_) => return Some("the moved file can't be opened"),
    }
    match open_no_follow(&entry.source, Access::Inspect) {
        Err(OpenError::NotFound) => None,
        _ => Some("something is already at the original place"),
    }
}

/// Read both journals and number a new list. Must be called with the history lock held.
fn read_history(
    list: &mut HistoryList,
    layout: &SystemLayout,
) -> Result<view::HistoryView, String> {
    let dir = app_dir(layout)?;
    let journal = open_journal(&dir)?;
    let lines = journal.lines().map_err(|e| e.to_string())?;
    let groups = group_by_clean(&move_history(&lines));
    let recycled = RecycledJournal::open(&dir)?
        .records()
        .map_err(|e| e.to_string())?;
    list.list = list.list.wrapping_add(1);
    list.groups = groups
        .iter()
        .map(|g| g.iter().map(|r| r.entry.clone()).collect())
        .collect();
    Ok(view::history_view(
        list.list,
        &groups,
        &recycled,
        &put_back_unavailable,
    ))
}

/// What ByteBroom moved (by clean) and recycled. Only reads.
#[tauri::command]
pub async fn history(
    history: State<'_, Arc<History>>,
    layout: State<'_, Layout>,
) -> Reply<view::HistoryView> {
    let (history, layout) = (history.inner().clone(), layout.0.clone());
    tauri::async_runtime::spawn_blocking(move || read_history(&mut history.lock(), &layout))
        .await
        .map_err(|_| CommandError::new("the history could not be read"))?
        .map_err(|e| CommandError::new(&format!("the history could not be read: {e}")))
}

/// Put back one move, or every still-moved file of one clean. The page sends only the IDs of
/// the list it was given; Rust re-reads the journal for every file (`undo_entries`), checks
/// both ends on disk (`undo_move`) and never runs elevated (rule S3). The page's own confirm is
/// the only question (decision 4): nothing is deleted until the restored file matches.
#[tauri::command]
pub async fn put_back(
    history: State<'_, Arc<History>>,
    layout: State<'_, Layout>,
    which: boundary::PutBackId,
) -> Reply<view::PutBackView> {
    let (history, layout) = (history.inner().clone(), layout.0.clone());
    tauri::async_runtime::spawn_blocking(move || -> Result<view::PutBackView, String> {
        refuse_if_elevated(elevated())?;
        let mut list = history.lock();
        if which.list != list.list {
            return Err("the history changed: look at it again, then choose".into());
        }
        let group = usize::try_from(which.group)
            .ok()
            .and_then(|g| list.groups.get(g))
            .ok_or("that clean is not in the history")?;
        let wanted: Vec<JournalEntry> = match which.item {
            Some(i) => vec![
                usize::try_from(i)
                    .ok()
                    .and_then(|i| group.get(i))
                    .ok_or("that file is not in the history")?
                    .clone(),
            ],
            None => group.clone(),
        };
        let dir = app_dir(&layout)?;
        let journal = open_journal(&dir)?;
        // A whole clean: only what is still moved (put-back ones would just be refused).
        let lines = journal.lines().map_err(|e| e.to_string())?;
        let still: Vec<JournalEntry> = move_history(&lines)
            .into_iter()
            .filter(|r| r.undone.is_none())
            .map(|r| r.entry)
            .collect();
        let wanted: Vec<JournalEntry> = if which.item.is_none() {
            wanted.into_iter().filter(|e| still.contains(e)).collect()
        } else {
            wanted
        };
        if wanted.is_empty() {
            return Err("nothing in that clean is still moved".into());
        }
        let at = bytebroom_core::win::locations::locations(&layout);
        let results = bytebroom_core::history::undo_entries(
            elevated(),
            &journal,
            &wanted,
            &|e| bytebroom_core::history::undo_policy(&at, &layout, e),
            &bytebroom_core::relocate::undo_move,
        );
        drop(journal);
        let message = view::put_back_message(&wanted, &results);
        let history = read_history(&mut list, &layout)?;
        Ok(view::PutBackView { message, history })
    })
    .await
    .map_err(|_| CommandError::new("putting back stopped unexpectedly; look at the history again"))?
    .map_err(|e| CommandError::new(&e))
}

/// Clear the history: both journals are deleted (decision 5). The files they list stay exactly
/// where they are, but moved files can no longer be put back from ByteBroom. The page asks
/// first. Never elevated.
#[tauri::command]
pub async fn clear_history(
    history: State<'_, Arc<History>>,
    layout: State<'_, Layout>,
) -> Reply<view::HistoryView> {
    let (history, layout) = (history.inner().clone(), layout.0.clone());
    tauri::async_runtime::spawn_blocking(move || -> Result<view::HistoryView, String> {
        refuse_if_elevated(elevated())?;
        let mut list = history.lock();
        let dir = app_dir(&layout)?;
        bytebroom_core::history::clear_history(elevated(), &dir)?;
        drop(dir);
        read_history(&mut list, &layout)
    })
    .await
    .map_err(|_| CommandError::new("the history could not be cleared"))?
    .map_err(|e| CommandError::new(&e))
}
