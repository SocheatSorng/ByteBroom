//! Recycling one item through the shell's `IFileOperation`, which reports where the item went
//! (security review of the phase 3 carry-overs, S2).
//!
//! `SHFileOperationW` only says "done". `IFileOperation` calls a progress sink after each
//! delete with the item it created in the Recycle Bin (`PostDeleteItem`'s `psiNewlyCreated`).
//! The engine opens that item and compares its file ID with the file it checked, so "the checked
//! file was recycled" no longer rests on a path the user can write to.
//!
//! `windows-sys` has the functions and the class ID but not the COM interfaces, so the few
//! method tables used here are declared by hand, in the order of the Windows SDK's
//! `shobjidl_core.h`. The work runs on its own thread, in a single-threaded apartment, as
//! `IFileOperation` requires.

use crate::paths::WinPath;
use std::cell::{Cell, RefCell};
use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::System::Com::{
    CLSCTX_ALL, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance, CoInitializeEx,
    CoTaskMemFree, CoUninitialize,
};
use windows_sys::Win32::UI::Shell::{
    FOF_ALLOWUNDO, FOF_NO_UI, FOFX_RECYCLEONDELETE, FileOperation, SHCreateItemFromParsingName,
    SIGDN_FILESYSPATH,
};
use windows_sys::core::{GUID, HRESULT};

const S_OK: HRESULT = 0;
const E_NOINTERFACE: HRESULT = 0x8000_4002_u32 as i32;
/// `E_FAIL`, reported when the shell gives no code of its own.
const E_FAIL: HRESULT = 0x8000_4005_u32 as i32;

const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_c000_000000000046);
const IID_IFILEOPERATION: GUID = GUID::from_u128(0x947aab5f_0a5c_4c13_b4d6_4bf7836fc9f8);
const IID_IFILEOPERATIONPROGRESSSINK: GUID =
    GUID::from_u128(0x04b0f1a7_9490_44bc_96e1_4296a31252e2);
const IID_ISHELLITEM: GUID = GUID::from_u128(0x43826d1e_e718_42ee_bc55_a1e261c37bfe);

type Raw = *mut c_void;

/// `IUnknown`'s three methods, first in every COM method table.
#[repr(C)]
struct UnknownVtbl {
    query_interface: unsafe extern "system" fn(Raw, *const GUID, *mut Raw) -> HRESULT,
    add_ref: unsafe extern "system" fn(Raw) -> u32,
    release: unsafe extern "system" fn(Raw) -> u32,
}

/// `IFileOperation`, in SDK order. Methods ByteBroom doesn't call are kept as placeholders so the
/// offsets stay right.
#[repr(C)]
struct FileOperationVtbl {
    unknown: UnknownVtbl,
    advise: unsafe extern "system" fn(Raw, Raw, *mut u32) -> HRESULT,
    unadvise: unsafe extern "system" fn(Raw, u32) -> HRESULT,
    set_operation_flags: unsafe extern "system" fn(Raw, u32) -> HRESULT,
    _set_progress_message: usize,
    _set_progress_dialog: usize,
    _set_properties: usize,
    _set_owner_window: usize,
    _apply_properties_to_item: usize,
    _apply_properties_to_items: usize,
    _rename_item: usize,
    _rename_items: usize,
    _move_item: usize,
    _move_items: usize,
    _copy_item: usize,
    _copy_items: usize,
    delete_item: unsafe extern "system" fn(Raw, Raw, Raw) -> HRESULT,
    _delete_items: usize,
    _new_item: usize,
    perform_operations: unsafe extern "system" fn(Raw) -> HRESULT,
    get_any_operations_aborted:
        unsafe extern "system" fn(Raw, *mut windows_sys::core::BOOL) -> HRESULT,
}

/// `IShellItem`, in SDK order.
#[repr(C)]
struct ShellItemVtbl {
    unknown: UnknownVtbl,
    _bind_to_handler: usize,
    _get_parent: usize,
    get_display_name: unsafe extern "system" fn(Raw, i32, *mut *mut u16) -> HRESULT,
    _get_attributes: usize,
    _compare: usize,
}

/// `IFileOperationProgressSink`, in SDK order: 16 methods after `IUnknown`.
#[repr(C)]
struct SinkVtbl {
    unknown: UnknownVtbl,
    start_operations: unsafe extern "system" fn(Raw) -> HRESULT,
    finish_operations: unsafe extern "system" fn(Raw, HRESULT) -> HRESULT,
    pre_rename_item: unsafe extern "system" fn(Raw, u32, Raw, *const u16) -> HRESULT,
    post_rename_item: unsafe extern "system" fn(Raw, u32, Raw, *const u16, HRESULT, Raw) -> HRESULT,
    pre_move_item: unsafe extern "system" fn(Raw, u32, Raw, Raw, *const u16) -> HRESULT,
    post_move_item:
        unsafe extern "system" fn(Raw, u32, Raw, Raw, *const u16, HRESULT, Raw) -> HRESULT,
    pre_copy_item: unsafe extern "system" fn(Raw, u32, Raw, Raw, *const u16) -> HRESULT,
    post_copy_item:
        unsafe extern "system" fn(Raw, u32, Raw, Raw, *const u16, HRESULT, Raw) -> HRESULT,
    pre_delete_item: unsafe extern "system" fn(Raw, u32, Raw) -> HRESULT,
    post_delete_item: unsafe extern "system" fn(Raw, u32, Raw, HRESULT, Raw) -> HRESULT,
    pre_new_item: unsafe extern "system" fn(Raw, u32, Raw, *const u16) -> HRESULT,
    post_new_item: unsafe extern "system" fn(
        Raw,
        u32,
        Raw,
        *const u16,
        *const u16,
        u32,
        HRESULT,
        Raw,
    ) -> HRESULT,
    update_progress: unsafe extern "system" fn(Raw, u32, u32) -> HRESULT,
    reset_timer: unsafe extern "system" fn(Raw) -> HRESULT,
    pause_timer: unsafe extern "system" fn(Raw) -> HRESULT,
    resume_timer: unsafe extern "system" fn(Raw) -> HRESULT,
}

/// Our progress sink: a COM object whose first field is its method table. It lives in a `Box`
/// owned by [`recycle_reporting`] for the whole operation; COM's reference count is tracked but
/// never frees it (the box does, after the operation has let go).
#[repr(C)]
struct Sink {
    vtbl: *const SinkVtbl,
    refs: Cell<u32>,
    /// The deleted item's HRESULT and where it went (`None`: deleted for good, or not reported).
    reported: RefCell<Option<(HRESULT, Option<String>)>>,
}

unsafe extern "system" fn sink_qi(this: Raw, iid: *const GUID, out: *mut Raw) -> HRESULT {
    // SAFETY: COM passes a valid IID pointer and a valid out pointer.
    let (iid, out) = unsafe { (&*iid, &mut *out) };
    let same = |g: &GUID| {
        g.data1 == iid.data1 && g.data2 == iid.data2 && g.data3 == iid.data3 && g.data4 == iid.data4
    };
    if same(&IID_IUNKNOWN) || same(&IID_IFILEOPERATIONPROGRESSSINK) {
        *out = this;
        // SAFETY: `this` is our Sink.
        unsafe { sink_add_ref(this) };
        S_OK
    } else {
        *out = std::ptr::null_mut();
        E_NOINTERFACE
    }
}
unsafe extern "system" fn sink_add_ref(this: Raw) -> u32 {
    // SAFETY: `this` points to our Sink, alive for the whole operation, on this thread.
    let s = unsafe { &*this.cast::<Sink>() };
    s.refs.set(s.refs.get() + 1);
    s.refs.get()
}
unsafe extern "system" fn sink_release(this: Raw) -> u32 {
    // SAFETY: as in `sink_add_ref`. The Box owner frees it, never COM.
    let s = unsafe { &*this.cast::<Sink>() };
    s.refs.set(s.refs.get().saturating_sub(1));
    s.refs.get()
}
unsafe extern "system" fn ok0(_: Raw) -> HRESULT {
    S_OK
}
unsafe extern "system" fn ok_hr(_: Raw, _: HRESULT) -> HRESULT {
    S_OK
}
unsafe extern "system" fn ok_pre_rename(_: Raw, _: u32, _: Raw, _: *const u16) -> HRESULT {
    S_OK
}
unsafe extern "system" fn ok_post_rename(
    _: Raw,
    _: u32,
    _: Raw,
    _: *const u16,
    _: HRESULT,
    _: Raw,
) -> HRESULT {
    S_OK
}
unsafe extern "system" fn ok_pre_move(_: Raw, _: u32, _: Raw, _: Raw, _: *const u16) -> HRESULT {
    S_OK
}
unsafe extern "system" fn ok_post_move(
    _: Raw,
    _: u32,
    _: Raw,
    _: Raw,
    _: *const u16,
    _: HRESULT,
    _: Raw,
) -> HRESULT {
    S_OK
}
unsafe extern "system" fn ok_pre_delete(_: Raw, _: u32, _: Raw) -> HRESULT {
    S_OK
}
unsafe extern "system" fn ok_post_new(
    _: Raw,
    _: u32,
    _: Raw,
    _: *const u16,
    _: *const u16,
    _: u32,
    _: HRESULT,
    _: Raw,
) -> HRESULT {
    S_OK
}
unsafe extern "system" fn ok_progress(_: Raw, _: u32, _: u32) -> HRESULT {
    S_OK
}

/// The file-system path of a shell item, if it has one.
///
/// # Safety
/// `item` must be a valid `IShellItem` pointer (or null).
unsafe fn item_path(item: Raw) -> Option<String> {
    if item.is_null() {
        return None;
    }
    // SAFETY: a valid IShellItem starts with a pointer to its method table.
    let vtbl = unsafe { &**item.cast::<*const ShellItemVtbl>() };
    let mut name: *mut u16 = std::ptr::null_mut();
    // SAFETY: `item` is valid; `name` receives a CoTaskMem string we free below.
    let hr = unsafe { (vtbl.get_display_name)(item, SIGDN_FILESYSPATH, &mut name) };
    if hr != S_OK || name.is_null() {
        return None;
    }
    // SAFETY: the shell returned a NUL-terminated string.
    let len = (0..).take_while(|&i| unsafe { *name.add(i) } != 0).count();
    // SAFETY: `len` units were just read as valid.
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(name, len) }).ok();
    // SAFETY: allocated by the shell with CoTaskMemAlloc.
    unsafe { CoTaskMemFree(name.cast()) };
    text
}

unsafe extern "system" fn post_delete(
    this: Raw,
    _flags: u32,
    _item: Raw,
    hr: HRESULT,
    created: Raw,
) -> HRESULT {
    // SAFETY: `this` is our Sink; `created` is an IShellItem or null, valid for this call.
    let s = unsafe { &*this.cast::<Sink>() };
    let path = unsafe { item_path(created) };
    *s.reported.borrow_mut() = Some((hr, path));
    S_OK
}

static SINK_VTBL: SinkVtbl = SinkVtbl {
    unknown: UnknownVtbl {
        query_interface: sink_qi,
        add_ref: sink_add_ref,
        release: sink_release,
    },
    start_operations: ok0,
    finish_operations: ok_hr,
    pre_rename_item: ok_pre_rename,
    post_rename_item: ok_post_rename,
    pre_move_item: ok_pre_move,
    post_move_item: ok_post_move,
    pre_copy_item: ok_pre_move,
    post_copy_item: ok_post_move,
    pre_delete_item: ok_pre_delete,
    post_delete_item: post_delete,
    pre_new_item: ok_pre_rename,
    post_new_item: ok_post_new,
    update_progress: ok_progress,
    reset_timer: ok0,
    pause_timer: ok0,
    resume_timer: ok0,
};

/// Release a COM object.
///
/// # Safety
/// `obj` must be a valid COM pointer we hold a reference on (or null).
unsafe fn release(obj: Raw) {
    if !obj.is_null() {
        // SAFETY: every COM object starts with a pointer to a table that starts with IUnknown.
        let vtbl = unsafe { &**obj.cast::<*const UnknownVtbl>() };
        // SAFETY: we own this reference.
        unsafe { (vtbl.release)(obj) };
    }
}

/// Move `path` to the Recycle Bin with no UI, and report where the shell put it: `Ok(Some(p))`
/// is the item's path inside the Recycle Bin, `Ok(None)` means the shell reported no item
/// there (it may have deleted it for good). `Err` carries the shell's code.
pub fn recycle_reporting(path: &WinPath) -> Result<Option<WinPath>, i32> {
    let text = path.to_string();
    std::thread::Builder::new()
        .name("recycle".into())
        .spawn(move || recycle_on_this_thread(&text))
        .map_err(|_| E_FAIL)?
        .join()
        .map_err(|_| E_FAIL)?
}

fn recycle_on_this_thread(path: &str) -> Result<Option<WinPath>, i32> {
    // SAFETY: plain COM initialisation of this new thread; undone below.
    let init = unsafe {
        CoInitializeEx(
            std::ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    if init < 0 {
        return Err(init);
    }
    let result = run_operation(path);
    // SAFETY: balances the successful CoInitializeEx above, after every COM object is released.
    unsafe { CoUninitialize() };
    result
}

fn run_operation(path: &str) -> Result<Option<WinPath>, i32> {
    let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
    let mut op: Raw = std::ptr::null_mut();
    // SAFETY: valid class and interface IDs; `op` receives an IFileOperation we release below.
    let hr = unsafe {
        CoCreateInstance(
            &FileOperation,
            std::ptr::null_mut(),
            CLSCTX_ALL,
            &IID_IFILEOPERATION,
            &mut op,
        )
    };
    if hr < 0 || op.is_null() {
        return Err(hr);
    }
    let mut item: Raw = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; `item` receives an IShellItem we release below.
    let hr = unsafe {
        SHCreateItemFromParsingName(
            wide.as_ptr(),
            std::ptr::null_mut(),
            &IID_ISHELLITEM,
            &mut item,
        )
    };
    if hr < 0 || item.is_null() {
        // SAFETY: we own `op`.
        unsafe { release(op) };
        return Err(hr);
    }
    let sink = Box::new(Sink {
        vtbl: &SINK_VTBL,
        refs: Cell::new(1),
        reported: RefCell::new(None),
    });
    let sink_ptr = (&raw const *sink).cast_mut().cast::<c_void>();
    // SAFETY: `op` is a valid IFileOperation.
    let vtbl = unsafe { &**op.cast::<*const FileOperationVtbl>() };
    let mut cookie = 0u32;
    let mut aborted: windows_sys::core::BOOL = 0;
    // SAFETY: every pointer is valid for the duration of these calls; the sink outlives the
    // operation (it is unadvised and `op` released before the box drops).
    let hr = unsafe {
        let mut hr =
            (vtbl.set_operation_flags)(op, FOF_ALLOWUNDO | FOF_NO_UI | FOFX_RECYCLEONDELETE);
        if hr >= 0 {
            hr = (vtbl.advise)(op, sink_ptr, &mut cookie);
        }
        if hr >= 0 {
            hr = (vtbl.delete_item)(op, item, std::ptr::null_mut());
        }
        if hr >= 0 {
            hr = (vtbl.perform_operations)(op);
        }
        if hr >= 0 {
            hr = (vtbl.get_any_operations_aborted)(op, &mut aborted);
        }
        if cookie != 0 {
            (vtbl.unadvise)(op, cookie);
        }
        release(item);
        release(op);
        hr
    };
    let reported = sink.reported.borrow_mut().take();
    if sink.refs.get() > 1 {
        // The shell still holds a reference it never gave back: keep the sink alive rather
        // than free memory it might still use.
        std::mem::forget(sink);
    }
    if hr < 0 {
        return Err(hr);
    }
    if aborted != 0 {
        return Err(E_FAIL);
    }
    match reported {
        Some((item_hr, _)) if item_hr < 0 => Err(item_hr),
        Some((_, Some(p))) => Ok(WinPath::parse(&p).ok()),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_item_fails_cleanly_and_nothing_is_recycled() {
        // A path that can't exist (a fresh random name in a folder that isn't there): COM starts
        // on its own thread, the shell can't make an item, and the call returns an error.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("bytebroom-missing-{nanos}"));
        let path = WinPath::parse(&dir.join("nothing.tmp").to_string_lossy())
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(recycle_reporting(&path).is_err());
    }
}
