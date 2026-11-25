//! Windows' own dialog that `clean` shows before acting on amber items (the owner's own files),
//! and the log of every answer.
//!
//! Phase 3's open bug: the owner never saw this dialog, yet the clean went ahead. Every failure
//! inside the dialog plugin and `rfd` gives "Cancel", so only a press on "Clean them" (a click,
//! or Enter, since it was the default button) could let it through. The likeliest story is a
//! second click or Enter carried over from the page's own confirm, landing on a dialog that had
//! no parent window. So (with the security review's S1):
//!
//! - the dialog is ByteBroom's own task dialog (`bytebroom_core::win::taskdialog`), owned by the
//!   main window, with **Cancel as the default button**;
//! - only the confirming button goes ahead; Cancel, Esc, closing it, no window, or a dialog that
//!   can't be shown all cancel;
//! - an answer given within [`MIN_READ`] of Windows creating the dialog can't have followed
//!   reading it, so it cancels too;
//! - every answer is logged with how long the dialog was open and whether it had a parent,
//!   in `ByteBroom\bytebroom.log` (no file names: only counts and the answer).

use bytebroom_core::paths::WinPath;
use bytebroom_core::win::taskdialog::{self, Answer, Asked, Question};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, Runtime};

/// The button that cleans. Only this button goes ahead.
pub const CLEAN_THEM: &str = "Clean them";
/// The dialog's title.
pub const TITLE: &str = "ByteBroom: clean your own files?";
/// Answers faster than this are taken as not read.
pub const MIN_READ: Duration = Duration::from_secs(1);
/// The log is started again (the old one kept as `bytebroom.log.old`) above this size.
pub const LOG_LIMIT: u64 = 256 * 1024;

/// What the owner's answer means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// "Clean them", pressed after the dialog had been open long enough to read.
    Clean,
    /// Cancel, Esc, or the dialog closed.
    Cancelled,
    /// "Clean them", but too fast to have been read: taken as a stray click or key.
    TooFast,
    /// No main window to show the dialog over, so it was not shown.
    NoWindow,
    /// Windows could not show the dialog.
    Unavailable,
}

/// Decide what an answer means. Pure.
pub fn verdict(asked: &Asked) -> Verdict {
    match asked.answer {
        Answer::Confirm if asked.open_for >= MIN_READ => Verdict::Clean,
        Answer::Confirm => Verdict::TooFast,
        Answer::Cancel => Verdict::Cancelled,
        Answer::Unavailable => Verdict::Unavailable,
    }
}

/// The message the page shows when the clean does not go ahead, or `None` for [`Verdict::Clean`].
pub fn refusal(v: Verdict) -> Option<&'static str> {
    match v {
        Verdict::Clean => None,
        Verdict::Cancelled => Some("cancelled: nothing was cleaned. Preview again to choose."),
        Verdict::TooFast => Some(
            "nothing was cleaned: the Windows dialog was answered in under a second, before it \
             could be read. Preview again, and read the dialog before choosing.",
        ),
        Verdict::NoWindow => Some("nothing was cleaned: ByteBroom's window could not be found."),
        Verdict::Unavailable => {
            Some("nothing was cleaned: Windows could not show the confirmation dialog.")
        }
    }
}

/// One log line: when, how many amber items, whether the dialog had a parent, the answer, how
/// long it was open, and the verdict. Holds no file names. Pure.
pub fn log_line(
    at: SystemTime,
    items: usize,
    parent: bool,
    asked: Option<&Asked>,
    v: Verdict,
) -> String {
    log_line_for(at, AMBER, items, parent, asked, v)
}

/// The log's name for the amber question.
pub const AMBER: &str = "amber-confirm";
/// The log's name for the Recycle Bin question (security review S3).
pub const EMPTY_BIN: &str = "empty-recycle-bin";

/// The message the page shows when the Recycle Bin is not emptied, or `None` to go ahead.
pub fn empty_refusal(v: Verdict) -> Option<&'static str> {
    match v {
        Verdict::Clean => None,
        Verdict::Cancelled => Some("Cancelled: the Recycle Bin was not emptied."),
        Verdict::TooFast => Some(
            "The Recycle Bin was not emptied: the Windows dialog was answered in under a second, \
             before it could be read. Try again, and read the dialog before choosing.",
        ),
        Verdict::NoWindow => {
            Some("The Recycle Bin was not emptied: ByteBroom's window could not be found.")
        }
        Verdict::Unavailable => {
            Some("The Recycle Bin was not emptied: Windows could not show the confirmation dialog.")
        }
    }
}

/// [`log_line`] for any question, named by `kind`. Pure.
pub fn log_line_for(
    at: SystemTime,
    kind: &str,
    items: usize,
    parent: bool,
    asked: Option<&Asked>,
    v: Verdict,
) -> String {
    let secs = at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (answer, open_for) = match asked {
        None => ("not shown".to_string(), Duration::ZERO),
        Some(a) => (format!("{:?}", a.answer), a.open_for),
    };
    format!(
        "{secs}\t{kind}\titems={items}\tparent={}\tanswer={answer}\topen_ms={}\t{v:?}",
        if parent { "main window" } else { "none" },
        open_for.as_millis(),
    )
}

/// Ask the owner in Windows' own dialog, over the main window, and log the answer. Blocks until
/// the owner answers: call it off the async runtime.
pub fn ask<R: Runtime>(
    app: &AppHandle<R>,
    question: &str,
    items: usize,
    local_app_data: Option<&WinPath>,
) -> Verdict {
    ask_with(
        app,
        &Question {
            title: TITLE,
            text: question,
            confirm: CLEAN_THEM,
        },
        AMBER,
        items,
        local_app_data,
    )
}

/// The dialog's title before emptying the Recycle Bin (phase 4, decision 8).
pub const EMPTY_TITLE: &str = "ByteBroom: empty the Recycle Bin?";
/// The button that empties it. Only this button goes ahead.
pub const EMPTY_IT: &str = "Empty it";

/// Ask, in the same dialog with the same rules (Cancel the default, too-fast answers cancel,
/// logged), before emptying the Recycle Bin, which can't be undone.
pub fn ask_empty_recycle_bin<R: Runtime>(
    app: &AppHandle<R>,
    local_app_data: Option<&WinPath>,
) -> Verdict {
    ask_with(
        app,
        &Question {
            title: EMPTY_TITLE,
            text: "Everything in the Recycle Bin, on every drive, will be deleted for good. This can't be undone, and a restore point doesn't bring it back.",
            confirm: EMPTY_IT,
        },
        EMPTY_BIN,
        0,
        local_app_data,
    )
}

/// The main window's handle, if it has one.
pub fn main_window<R: Runtime>(app: &AppHandle<R>) -> Option<isize> {
    app.get_webview_window("main")
        .and_then(|w| w.hwnd().ok())
        .map(|h| h.0 as isize)
        .filter(|h| *h != 0)
}

fn ask_with<R: Runtime>(
    app: &AppHandle<R>,
    question: &Question,
    kind: &str,
    items: usize,
    local_app_data: Option<&WinPath>,
) -> Verdict {
    let parent = app
        .get_webview_window("main")
        .and_then(|w| w.hwnd().ok())
        .map(|h| h.0 as isize)
        .filter(|h| *h != 0);
    let Some(parent) = parent else {
        let v = Verdict::NoWindow;
        log(
            local_app_data,
            &log_line_for(SystemTime::now(), kind, items, false, None, v),
        );
        return v;
    };
    let asked = taskdialog::ask(parent, question);
    let v = verdict(&asked);
    log(
        local_app_data,
        &log_line_for(SystemTime::now(), kind, items, true, Some(&asked), v),
    );
    v
}

/// Append `line` to `ByteBroom\bytebroom.log` in the owner's local app data, opened without
/// following links. Logging is best effort: a failure here never lets a clean through (the
/// verdict is decided before) and never stops a cancel.
pub fn log(local_app_data: Option<&WinPath>, line: &str) {
    use std::io::Write;
    let Some(base) = local_app_data else { return };
    let Ok(dir) = bytebroom_core::relocate::app_folder(base) else {
        return;
    };
    if let Ok((mut file, _)) = dir.open_append("bytebroom.log") {
        if file.metadata().map(|m| m.len()).unwrap_or(0) > LOG_LIMIT {
            // Start again: keep one old copy, renamed through the held folder (no links).
            drop(file);
            let _ = dir.replace_name("bytebroom.log", "bytebroom.log.old");
            let Ok((again, _)) = dir.open_append("bytebroom.log") else {
                return;
            };
            file = again;
        }
        let _ = writeln!(file, "{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LONG: Duration = Duration::from_secs(3);

    fn asked(answer: Answer, open_for: Duration) -> Asked {
        Asked { answer, open_for }
    }

    #[test]
    fn only_the_clean_button_read_for_a_second_goes_ahead() {
        assert_eq!(verdict(&asked(Answer::Confirm, LONG)), Verdict::Clean);
        assert_eq!(verdict(&asked(Answer::Confirm, MIN_READ)), Verdict::Clean);
        assert_eq!(verdict(&asked(Answer::Cancel, LONG)), Verdict::Cancelled);
        assert_eq!(
            verdict(&asked(Answer::Unavailable, LONG)),
            Verdict::Unavailable
        );
    }

    #[test]
    fn a_clean_answer_faster_than_reading_is_refused() {
        for fast in [0, 50, 400, 999] {
            assert_eq!(
                verdict(&asked(Answer::Confirm, Duration::from_millis(fast))),
                Verdict::TooFast,
                "{fast} ms"
            );
        }
        assert_eq!(
            verdict(&asked(Answer::Cancel, Duration::ZERO)),
            Verdict::Cancelled
        );
    }

    #[test]
    fn every_verdict_but_clean_stops_with_a_message() {
        assert_eq!(refusal(Verdict::Clean), None);
        for v in [
            Verdict::Cancelled,
            Verdict::TooFast,
            Verdict::NoWindow,
            Verdict::Unavailable,
        ] {
            assert!(refusal(v).unwrap().contains("nothing was cleaned"), "{v:?}");
        }
    }

    #[test]
    fn the_log_line_says_what_happened_and_names_no_file() {
        let at = UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let line = log_line(
            at,
            2,
            true,
            Some(&asked(Answer::Confirm, Duration::from_millis(2345))),
            Verdict::Clean,
        );
        assert_eq!(
            line,
            "1790000000\tamber-confirm\titems=2\tparent=main window\tanswer=Confirm\topen_ms=2345\tClean"
        );
        assert!(log_line(at, 1, false, None, Verdict::NoWindow).contains("answer=not shown"));
        // The Recycle Bin question is logged under its own name.
        assert!(
            log_line_for(at, EMPTY_BIN, 0, true, None, Verdict::Cancelled)
                .starts_with("1790000000\tempty-recycle-bin\titems=0")
        );
    }

    #[test]
    fn the_recycle_bin_refusals_speak_of_the_bin() {
        assert_eq!(empty_refusal(Verdict::Clean), None);
        for v in [
            Verdict::Cancelled,
            Verdict::TooFast,
            Verdict::NoWindow,
            Verdict::Unavailable,
        ] {
            let text = empty_refusal(v).unwrap();
            assert!(text.contains("not emptied"), "{v:?}: {text}");
            assert!(!text.contains("Preview"), "{v:?}: {text}");
        }
    }

    #[test]
    fn only_one_red_action_runs_at_a_time() {
        let first = crate::RedBusy::take().expect("free at first");
        assert!(crate::RedBusy::take().is_none(), "a second one is refused");
        drop(first);
        assert!(
            crate::RedBusy::take().is_some(),
            "free again once the first ends"
        );
    }
}
