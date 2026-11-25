//! Windows' task dialog, for the one question ByteBroom asks in Rust before cleaning the owner's
//! own files (security review of the phase 3 carry-overs, S1).
//!
//! The dialog plugin (via `rfd`) made the confirming button the default and started no clock of
//! its own, so a stray Enter could confirm. Here:
//!
//! - **Cancel is the default button**, and Esc or the close box also cancel;
//! - the dialog is **owned by the given window** and centred on it;
//! - the time it was open is measured **from the moment Windows created it** (`TDN_CREATED`), so
//!   a dialog that appears late can't be answered "fast" without the clock knowing.
//!
//! `TaskDialogIndirect` exists only in Common Controls 6, which a program gets through its
//! manifest (the app has one). It is looked up at run time, so programs without the manifest
//! (tests, the scan tool) still start; there the dialog is reported unavailable, which callers
//! treat as "not confirmed".
//!
//! This is the only user-interface code in the core crate: it lives here because unsafe Win32
//! calls are allowed only in `core::win`.

use std::cell::Cell;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::UI::Controls::{
    TASKDIALOG_BUTTON, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TD_WARNING_ICON, TDCBF_CANCEL_BUTTON,
    TDF_ALLOW_DIALOG_CANCELLATION, TDF_POSITION_RELATIVE_TO_WINDOW, TDN_CREATED,
};
use windows_sys::Win32::UI::WindowsAndMessaging::IDCANCEL;

/// The ID of the one custom (confirming) button.
const ID_CONFIRM: i32 = 1000;

/// What the owner did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Pressed the confirming button.
    Confirm,
    /// Pressed Cancel, pressed Esc, or closed the dialog.
    Cancel,
    /// The dialog could not be shown (no Common Controls 6, or Windows refused).
    Unavailable,
}

/// The answer, and how long the dialog had been on screen when it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asked {
    /// What the owner did.
    pub answer: Answer,
    /// From Windows creating the dialog to the answer (zero if it never appeared).
    pub open_for: Duration,
}

/// The parts of the question.
#[derive(Debug, Clone)]
pub struct Question<'a> {
    /// The window title.
    pub title: &'a str,
    /// The text.
    pub text: &'a str,
    /// The confirming button's label (Cancel is Windows' own button).
    pub confirm: &'a str,
}

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(Some(0)).collect()
}

type TaskDialogIndirectFn = unsafe extern "system" fn(
    *const TASKDIALOGCONFIG,
    *mut i32,
    *mut i32,
    *mut windows_sys::core::BOOL,
) -> windows_sys::core::HRESULT;

/// `TaskDialogIndirect` from Common Controls 6, if this process has it.
fn task_dialog_indirect() -> Option<TaskDialogIndirectFn> {
    let name = wide("comctl32.dll");
    // SAFETY: `name` is NUL-terminated and outlives the call. Only System32 is searched; a
    // manifest asking for Common Controls 6 redirects to the side-by-side copy.
    let module = unsafe {
        LoadLibraryExW(
            name.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return None;
    }
    // SAFETY: `module` is loaded (never freed: it stays for the process); the name is a
    // NUL-terminated ASCII string.
    let proc = unsafe { GetProcAddress(module, c"TaskDialogIndirect".as_ptr().cast()) }?;
    // SAFETY: the export has exactly this signature (commctrl.h).
    Some(unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, TaskDialogIndirectFn>(proc)
    })
}

/// Called by Windows for the dialog's events; records when it was created.
unsafe extern "system" fn on_event(
    _hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    _lparam: LPARAM,
    data: isize,
) -> windows_sys::core::HRESULT {
    if msg == TDN_CREATED as u32 && data != 0 {
        // SAFETY: `data` is the address of the `Cell` that `ask` keeps alive for the whole
        // TaskDialogIndirect call, on this same thread.
        let created = unsafe { &*(data as *const Cell<Option<Instant>>) };
        created.set(Some(Instant::now()));
    }
    0
}

/// Ask `question` in a warning task dialog owned by `parent` (a window handle; 0 for none).
/// Blocks until the owner answers. Cancel is the default button.
pub fn ask(parent: isize, question: &Question) -> Asked {
    let unavailable = Asked {
        answer: Answer::Unavailable,
        open_for: Duration::ZERO,
    };
    let Some(show) = task_dialog_indirect() else {
        return unavailable;
    };
    let title = wide(question.title);
    let text = wide(question.text);
    let confirm = wide(question.confirm);
    let buttons = [TASKDIALOG_BUTTON {
        nButtonID: ID_CONFIRM,
        pszButtonText: confirm.as_ptr(),
    }];
    let created: Cell<Option<Instant>> = Cell::new(None);
    let config = TASKDIALOGCONFIG {
        cbSize: size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: parent as HWND,
        dwFlags: TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW,
        dwCommonButtons: TDCBF_CANCEL_BUTTON,
        pszWindowTitle: title.as_ptr(),
        Anonymous1: TASKDIALOGCONFIG_0 {
            pszMainIcon: TD_WARNING_ICON,
        },
        pszContent: text.as_ptr(),
        cButtons: buttons.len() as u32,
        pButtons: buttons.as_ptr(),
        nDefaultButton: IDCANCEL,
        pfCallback: Some(on_event),
        lpCallbackData: &raw const created as isize,
        ..TASKDIALOGCONFIG::default()
    };
    let mut pressed: i32 = 0;
    // SAFETY: `config` and every string and button it points to live until the call returns;
    // the callback data points to `created`, which also outlives the call; the optional out
    // pointers may be null.
    let hr = unsafe {
        show(
            &config,
            &mut pressed,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    let open_for = created.get().map(|at| at.elapsed()).unwrap_or_default();
    if hr != 0 {
        return unavailable;
    }
    Asked {
        answer: answer_for(pressed),
        open_for,
    }
}

/// Which answer a pressed button ID means. Only the confirming button confirms. Pure.
pub fn answer_for(pressed: i32) -> Answer {
    if pressed == ID_CONFIRM {
        Answer::Confirm
    } else {
        Answer::Cancel
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_confirming_button_confirms() {
        assert_eq!(answer_for(ID_CONFIRM), Answer::Confirm);
        for other in [0, IDCANCEL, 1, 6, 7, ID_CONFIRM + 1, -1] {
            assert_eq!(answer_for(other), Answer::Cancel, "{other}");
        }
    }

    #[test]
    fn without_common_controls_6_the_dialog_is_unavailable_never_confirmed() {
        // Test programs have no manifest, so this is the "can't show it" path; it must not
        // block, and must not confirm.
        let asked = ask(
            0,
            &Question {
                title: "t",
                text: "x",
                confirm: "Yes",
            },
        );
        assert_eq!(asked.answer, Answer::Unavailable);
        assert_eq!(asked.open_for, Duration::ZERO);
    }
}
