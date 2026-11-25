//! Windows' own dialog that `clean` shows before acting on amber items (the owner's own files),
//! and the log of every answer.
//!
//! Phase 3's open bug: the owner never saw this dialog, yet the clean went ahead. Every failure
//! inside the dialog plugin and `rfd` gives "Cancel", so only a press on "Clean them" (a click,
//! or Enter, since it is the default button) could let it through. The likeliest story is a
//! second click or Enter carried over from the page's own confirm, landing on a dialog that had
//! no parent window. So:
//!
//! - the dialog has the main window as its parent (it opens over it, modal to it);
//! - only the exact answer "Clean them" goes ahead; anything else, or no window, cancels;
//! - an answer given within [`MIN_READ`] of the dialog opening can't have followed reading it,
//!   so it cancels too;
//! - every answer is logged with how long the dialog was open and whether it had a parent,
//!   in `ByteBroom\bytebroom.log` (no file names: only counts and the answer).

use bytebroom_core::paths::WinPath;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_dialog::{
    DialogExt, MessageDialogButtons, MessageDialogKind, MessageDialogResult,
};

/// The button that cleans. Only this exact answer goes ahead.
pub const CLEAN_THEM: &str = "Clean them";
/// The dialog's title.
pub const TITLE: &str = "ByteBroom: clean your own files?";
/// Answers faster than this are taken as not read.
pub const MIN_READ: Duration = Duration::from_secs(1);

/// What the owner's answer means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// "Clean them", pressed after the dialog had been open long enough to read.
    Clean,
    /// Cancel, the dialog closed, or any answer other than "Clean them".
    Cancelled,
    /// "Clean them", but too fast to have been read: taken as a stray click or key.
    TooFast,
    /// No main window to show the dialog over, so it was not shown.
    NoWindow,
}

/// Decide what an answer means. Pure.
pub fn verdict(answer: &MessageDialogResult, open_for: Duration) -> Verdict {
    match answer {
        MessageDialogResult::Custom(label) if label == CLEAN_THEM => {
            if open_for < MIN_READ {
                Verdict::TooFast
            } else {
                Verdict::Clean
            }
        }
        _ => Verdict::Cancelled,
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
    }
}

/// One log line: when, how many amber items, whether the dialog had a parent, the raw answer,
/// how long it was open, and the verdict. Holds no file names. Pure.
pub fn log_line(
    at: SystemTime,
    items: usize,
    parent: bool,
    answer: Option<&MessageDialogResult>,
    open_for: Duration,
    v: Verdict,
) -> String {
    let secs = at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let answer = match answer {
        None => "not shown".to_string(),
        Some(MessageDialogResult::Custom(label)) if label == CLEAN_THEM => "Clean them".into(),
        Some(MessageDialogResult::Custom(_)) => "other button".into(),
        Some(other) => format!("{other:?}"),
    };
    format!(
        "{secs}\tamber-confirm\titems={items}\tparent={}\tanswer={answer}\topen_ms={}\t{v:?}",
        if parent { "main window" } else { "none" },
        open_for.as_millis(),
    )
}

/// Ask the owner in Windows' own dialog, over the main window, and log the answer.
pub fn ask<R: Runtime>(
    app: &AppHandle<R>,
    question: String,
    items: usize,
    local_app_data: Option<&WinPath>,
) -> Verdict {
    let Some(window) = app.get_webview_window("main") else {
        let v = Verdict::NoWindow;
        log(
            local_app_data,
            &log_line(SystemTime::now(), items, false, None, Duration::ZERO, v),
        );
        return v;
    };
    let shown = Instant::now();
    let answer = app
        .dialog()
        .message(question)
        .title(TITLE)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            CLEAN_THEM.into(),
            "Cancel".into(),
        ))
        .parent(&window)
        .blocking_show_with_result();
    let open_for = shown.elapsed();
    let v = verdict(&answer, open_for);
    log(
        local_app_data,
        &log_line(SystemTime::now(), items, true, Some(&answer), open_for, v),
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
        let _ = writeln!(file, "{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LONG: Duration = Duration::from_secs(3);

    #[test]
    fn only_the_exact_clean_button_read_for_a_second_goes_ahead() {
        let clean = MessageDialogResult::Custom(CLEAN_THEM.into());
        assert_eq!(verdict(&clean, LONG), Verdict::Clean);
        assert_eq!(verdict(&clean, MIN_READ), Verdict::Clean);
        for not in [
            MessageDialogResult::Custom("Cancel".into()),
            MessageDialogResult::Custom("clean them".into()),
            MessageDialogResult::Custom(String::new()),
            MessageDialogResult::Ok,
            MessageDialogResult::Yes,
            MessageDialogResult::Cancel,
            MessageDialogResult::No,
        ] {
            assert_eq!(verdict(&not, LONG), Verdict::Cancelled, "{not:?}");
        }
    }

    #[test]
    fn a_clean_answer_faster_than_reading_is_refused() {
        let clean = MessageDialogResult::Custom(CLEAN_THEM.into());
        for fast in [0, 50, 400, 999] {
            assert_eq!(
                verdict(&clean, Duration::from_millis(fast)),
                Verdict::TooFast,
                "{fast} ms"
            );
        }
        // A fast Cancel is just a cancel.
        let cancel = MessageDialogResult::Custom("Cancel".into());
        assert_eq!(verdict(&cancel, Duration::ZERO), Verdict::Cancelled);
    }

    #[test]
    fn every_verdict_but_clean_stops_with_a_message() {
        assert_eq!(refusal(Verdict::Clean), None);
        for v in [Verdict::Cancelled, Verdict::TooFast, Verdict::NoWindow] {
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
            Some(&MessageDialogResult::Custom(CLEAN_THEM.into())),
            Duration::from_millis(2345),
            Verdict::Clean,
        );
        assert_eq!(
            line,
            "1790000000\tamber-confirm\titems=2\tparent=main window\tanswer=Clean them\topen_ms=2345\tClean"
        );
        let other = log_line(
            at,
            1,
            false,
            Some(&MessageDialogResult::Custom("D:\\secret\\name.txt".into())),
            Duration::ZERO,
            Verdict::Cancelled,
        );
        assert!(!other.contains("secret"), "{other}");
        assert!(
            log_line(at, 1, false, None, Duration::ZERO, Verdict::NoWindow)
                .contains("answer=not shown")
        );
    }
}
