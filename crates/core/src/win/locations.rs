//! The scanner's locations on this PC.
//!
//! Values come from `SHGetKnownFolderPath`; the environment is only a cross-check (see
//! [`crate::locations`]). Each location that survives is then opened without following it: one
//! that can't be opened, isn't a folder, is a link or junction, or that Windows reports at a
//! different place (a link somewhere on the way) is not scanned.

use super::layout::{env_path, known_folder};
use super::{Access, open_no_follow};
use crate::locations::{Candidate, Locations, Sources, Which};
use crate::policy::SystemLayout;
use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows_sys::Win32::UI::Shell::{FOLDERID_Downloads, FOLDERID_LocalAppData, FOLDERID_Profile};

/// Letters of the fixed drives (no removable, network, optical or RAM drives).
pub fn fixed_drives() -> Vec<char> {
    // SAFETY: no arguments; returns a bit mask of the drive letters in use.
    let mask = unsafe { GetLogicalDrives() };
    (0u8..26)
        .filter(|bit| mask & (1 << bit) != 0)
        .map(|bit| char::from(b'A' + bit))
        .filter(|letter| {
            let root: Vec<u16> = format!("{letter}:\\")
                .encode_utf16()
                .chain(Some(0))
                .collect();
            // SAFETY: `root` is a NUL-terminated UTF-16 string that outlives the call.
            unsafe { GetDriveTypeW(root.as_ptr()) == DRIVE_FIXED }
        })
        .collect()
}

/// What Windows and the environment say about this user's folders.
pub fn sources() -> Sources {
    Sources {
        profile: Candidate {
            api: known_folder(&FOLDERID_Profile),
            env: env_path("USERPROFILE"),
        },
        local_app_data: Candidate {
            api: known_folder(&FOLDERID_LocalAppData),
            env: env_path("LOCALAPPDATA"),
        },
        downloads: Candidate {
            api: known_folder(&FOLDERID_Downloads),
            env: None,
        },
        fixed_drives: fixed_drives(),
    }
}

/// Drop every location that is not a real folder at exactly the place it claims, and store each
/// survivor with the exact spelling Windows reports (the engine compares paths case-exactly).
pub fn confirm_on_disk(mut locations: Locations) -> Locations {
    let checks: Vec<(Which, Result<crate::paths::WinPath, String>)> = locations
        .scanned()
        .into_iter()
        .map(|(which, path)| {
            let verdict = match open_no_follow(path, Access::Inspect) {
                Err(e) => Err(format!("it can't be opened ({e})")),
                Ok(o) if o.resolved.is_reparse_point => Err("it is a link or junction".into()),
                Ok(o) if !o.is_directory => Err("it is not a folder".into()),
                Ok(o) if !o.resolved.final_path.eq_ignore_case(path) => {
                    Err("Windows reports it at a different place (a link on the way)".into())
                }
                Ok(o) => Ok(o.resolved.final_path),
            };
            (which, verdict)
        })
        .collect();
    for (which, verdict) in checks {
        match verdict {
            Ok(real) => {
                let slot = match which {
                    Which::Profile => &mut locations.profile,
                    Which::LocalAppData => &mut locations.local_app_data,
                    Which::Downloads => &mut locations.downloads,
                };
                // Only respell what is still scanned: a dropped profile took LocalAppData with it.
                if let Some(path) = slot {
                    *path = real;
                }
            }
            Err(why) => locations.drop_location(which, why),
        }
    }
    // LocalAppData must still be inside the profile once both carry Windows' own spelling.
    if let (Some(local), Some(profile)) = (&locations.local_app_data, &locations.profile)
        && !local.is_strictly_inside(profile)
    {
        locations.drop_location(Which::LocalAppData, "it is not inside your profile folder");
    }
    locations
}

/// Build the locations from `sources` and check each one on disk. Tests call this with a fake
/// profile in a temp folder; [`locations`] calls it with the real values.
pub fn locations_from(sources: &Sources, layout: &SystemLayout) -> Locations {
    confirm_on_disk(Locations::resolve(sources, layout))
}

/// The scanner's locations for the user running ByteBroom.
pub fn locations(layout: &SystemLayout) -> Locations {
    locations_from(&sources(), layout)
}
