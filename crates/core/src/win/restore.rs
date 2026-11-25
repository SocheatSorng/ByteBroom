//! Windows side of the restore point (phase 4, task 2), as Microsoft's "Using System Restore"
//! sample does it (https://learn.microsoft.com/en-us/windows/win32/sr/using-system-restore):
//!
//! 1. COM, multithreaded, with explicit COM security: only Administrators, SYSTEM,
//!    LocalService, NetworkService and Principal Self may call back into the process, at
//!    packet-privacy authentication and identify-level impersonation, with
//!    `EOAC_DISABLE_AAA | EOAC_NO_CUSTOM_MARSHAL`. System Restore's services call back, so the
//!    sample requires this for any process that calls `SRSetRestorePointW`.
//! 2. `SrClient.dll` loaded at run time (Microsoft: not linked at load time), from System32
//!    only, and `SRSetRestorePointW` looked up in it.
//! 3. `BEGIN_SYSTEM_CHANGE` (type `MODIFY_SETTINGS`, sequence 0, a fixed description), then
//!    `END_SYSTEM_CHANGE` with the returned sequence number, which completes the point before
//!    anything is changed.
//!
//! Only the elevated helper calls [`make_restore_point`]; tests never do (it would make a real
//! restore point). COM security can be set once per process, which suits the one-shot helper.

use crate::restore::{RestorePoint, from_call};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::FreeLibrary;
use windows_sys::Win32::Security::{
    ACL, ACL_REVISION, AddAccessAllowedAce, CreateWellKnownSid, InitializeAcl,
    InitializeSecurityDescriptor, PSID, SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE,
    SetSecurityDescriptorDacl, SetSecurityDescriptorGroup, SetSecurityDescriptorOwner,
    WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinLocalServiceSid, WinLocalSystemSid,
    WinNetworkServiceSid, WinSelfSid,
};
use windows_sys::Win32::System::Com::{
    COINIT_MULTITHREADED, CoInitializeEx, CoInitializeSecurity, CoUninitialize, EOAC_DISABLE_AAA,
    EOAC_NO_CUSTOM_MARSHAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IDENTIFY,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::Restore::{
    BEGIN_SYSTEM_CHANGE, END_SYSTEM_CHANGE, MODIFY_SETTINGS, RESTOREPOINTINFOW, STATEMGRSTATUS,
};

/// `SECURITY_DESCRIPTOR_REVISION` (winnt.h).
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

/// `COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL`, as in Microsoft's sample.
const COM_RIGHTS: u32 = 0x1 | 0x2;

/// The callers Microsoft's sample allows: Administrators, LocalService, NetworkService,
/// Principal Self and SYSTEM (SDDL `BA`, `LS`, `NS`, `PS`, `SY`).
pub const CALLERS: [WELL_KNOWN_SID_TYPE; 5] = [
    WinBuiltinAdministratorsSid,
    WinLocalServiceSid,
    WinNetworkServiceSid,
    WinSelfSid,
    WinLocalSystemSid,
];

type SetRestorePointFn =
    unsafe extern "system" fn(*const RESTOREPOINTINFOW, *mut STATEMGRSTATUS) -> i32;

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(Some(0)).collect()
}

/// A SID buffer, 4-byte aligned as SIDs expect (security review of task 2, note 1).
#[repr(C, align(4))]
struct SidBuf([u8; SECURITY_MAX_SID_SIZE as usize]);

/// The parts of COM's security descriptor, kept together so every pointer inside stays valid.
pub struct ComSecurity {
    sids: Vec<SidBuf>,
    acl: Vec<u64>,
    sd: Box<SECURITY_DESCRIPTOR>,
}

impl ComSecurity {
    /// Build the absolute security descriptor: owner and group Administrators, and an access
    /// list granting COM execute rights to [`CALLERS`] only.
    pub fn build() -> Option<Self> {
        let mut sids = Vec::with_capacity(CALLERS.len());
        for kind in CALLERS {
            let mut sid = SidBuf([0u8; SECURITY_MAX_SID_SIZE as usize]);
            let mut size = SECURITY_MAX_SID_SIZE;
            // SAFETY: `sid` is writable for `size` bytes; no domain SID is needed for these.
            let ok = unsafe {
                CreateWellKnownSid(
                    kind,
                    std::ptr::null_mut(),
                    sid.0.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            if ok == 0 {
                return None;
            }
            sids.push(sid);
        }
        // An ACL header plus, per entry, an ACE header and mask (8 bytes) and its SID.
        let acl_bytes = size_of::<ACL>() + sids.len() * (8 + SECURITY_MAX_SID_SIZE as usize);
        let mut acl = vec![0u64; acl_bytes.div_ceil(8)];
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        // SAFETY: `acl` is writable and aligned for `acl_bytes`.
        if unsafe { InitializeAcl(acl_ptr, acl_bytes as u32, ACL_REVISION) } == 0 {
            return None;
        }
        for sid in &mut sids {
            // SAFETY: the ACL was initialised with room for every entry; `sid` is a valid SID.
            let ok = unsafe {
                AddAccessAllowedAce(acl_ptr, ACL_REVISION, COM_RIGHTS, sid.0.as_mut_ptr().cast())
            };
            if ok == 0 {
                return None;
            }
        }
        // SAFETY: SECURITY_DESCRIPTOR is plain data; InitializeSecurityDescriptor fills it in.
        let mut sd: Box<SECURITY_DESCRIPTOR> = Box::new(unsafe { std::mem::zeroed() });
        let sd_ptr = (&raw mut *sd).cast::<std::ffi::c_void>();
        let admins: PSID = sids[0].0.as_mut_ptr().cast();
        // SAFETY: `sd` is a writable descriptor; the SIDs and ACL it points to live in `self`,
        // whose heap buffers don't move when `self` does.
        let ok = unsafe {
            InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION) != 0
                && SetSecurityDescriptorOwner(sd_ptr, admins, 0) != 0
                && SetSecurityDescriptorGroup(sd_ptr, admins, 0) != 0
                && SetSecurityDescriptorDacl(sd_ptr, 1, acl_ptr, 0) != 0
        };
        ok.then_some(Self { sids, acl, sd })
    }

    /// The number of callers in the access list (for tests).
    pub fn callers(&self) -> usize {
        // SAFETY: `acl` holds the initialised ACL.
        usize::from(unsafe { (*self.acl.as_ptr().cast::<ACL>()).AceCount }).min(self.sids.len())
    }
}

/// `SRSetRestorePointW` from System32's `SrClient.dll`, if this Windows has System Restore.
/// The library stays loaded until the returned guard drops.
pub struct SrClient {
    module: windows_sys::Win32::Foundation::HMODULE,
    set: SetRestorePointFn,
}

impl SrClient {
    /// Load it (System32 only).
    pub fn load() -> Option<Self> {
        let name = wide("srclient.dll");
        // SAFETY: NUL-terminated name; only System32 is searched.
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
        // SAFETY: `module` is loaded; the name is NUL-terminated ASCII.
        let Some(proc) = (unsafe { GetProcAddress(module, c"SRSetRestorePointW".as_ptr().cast()) })
        else {
            // SAFETY: loaded above, freed once.
            unsafe { FreeLibrary(module) };
            return None;
        };
        // SAFETY: the export has this signature (srrestoreptapi.h: BOOL SRSetRestorePointW(
        // PRESTOREPOINTINFOW, PSTATEMGRSTATUS)).
        let set = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, SetRestorePointFn>(proc)
        };
        Some(Self { module, set })
    }

    fn call(&self, info: &RESTOREPOINTINFOW) -> (bool, STATEMGRSTATUS) {
        let mut status = STATEMGRSTATUS::default();
        // SAFETY: `info` and `status` are valid, correctly packed structs for this call.
        let ok = unsafe { (self.set)(info, &mut status) } != 0;
        (ok, status)
    }
}

impl Drop for SrClient {
    fn drop(&mut self) {
        // SAFETY: loaded in `load`, freed once.
        unsafe { FreeLibrary(self.module) };
    }
}

/// Make a restore point named `description` (or confirm one from the last 24 hours), as the
/// elevated helper does before any system change. Never call this from a test.
pub fn make_restore_point(description: &str) -> RestorePoint {
    // SAFETY: plain COM initialisation of this thread; undone below.
    let init = unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
    if init < 0 {
        return RestorePoint::Failed(init as u32);
    }
    let result = with_com(description);
    // SAFETY: balances the successful CoInitializeEx above.
    unsafe { CoUninitialize() };
    result
}

fn with_com(description: &str) -> RestorePoint {
    let Some(security) = ComSecurity::build() else {
        return RestorePoint::Failed(0);
    };
    // SAFETY: the descriptor is a valid absolute one, alive for the rest of this process (it
    // is leaked below, as COM may keep using it); the other arguments are as in Microsoft's
    // sample.
    let hr = unsafe {
        CoInitializeSecurity(
            (&raw const *security.sd).cast_mut().cast(),
            -1,
            std::ptr::null(),
            std::ptr::null(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IDENTIFY,
            std::ptr::null(),
            (EOAC_DISABLE_AAA | EOAC_NO_CUSTOM_MARSHAL) as u32,
            std::ptr::null(),
        )
    };
    // COM keeps the descriptor for the process's lifetime; never free it.
    std::mem::forget(security);
    if hr < 0 {
        return RestorePoint::Failed(hr as u32);
    }
    let Some(client) = SrClient::load() else {
        return RestorePoint::Unavailable;
    };
    let mut info = RESTOREPOINTINFOW {
        dwEventType: BEGIN_SYSTEM_CHANGE,
        dwRestorePtType: MODIFY_SETTINGS,
        llSequenceNumber: 0,
        szDescription: [0; 256],
    };
    // A fixed description, cut to fit with its terminating NUL.
    let text: Vec<u16> = description.encode_utf16().take(255).collect();
    let mut desc = [0u16; 256];
    desc[..text.len()].copy_from_slice(&text);
    info.szDescription = desc;
    let (ok, status) = client.call(&info);
    let point = from_call(ok, status.nStatus, status.llSequenceNumber);
    if let RestorePoint::InPlace(sequence) = point {
        // Complete the point before anything is changed.
        let end = RESTOREPOINTINFOW {
            dwEventType: END_SYSTEM_CHANGE,
            llSequenceNumber: sequence,
            ..info
        };
        let (ended, end_status) = client.call(&end);
        if !ended {
            return RestorePoint::Failed(end_status.nStatus);
        }
    }
    point
}
