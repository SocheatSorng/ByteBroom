//! Phase 2 task 9: the scan tool links nothing that acts and writes no files.
//!
//! The binary is built in release, where the linker drops every function nothing calls, and then
//! two independent things are read:
//! - its symbol file (`.pdb`), which names every function linked in: the scanner's are there, the
//!   engine's are not;
//! - its import table (inside the `.exe`), which names every Windows function it can call: no
//!   delete, move, copy, rename, recycle or empty.
//!
//! A debug build can't be used: it keeps whole compiled units, so unused engine functions appear.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

/// Build the release binary (its own `target\release` folder, so it never waits on this test
/// run's debug build) and return the folder it is in.
fn release_dir() -> PathBuf {
    let root = workspace_root();
    let status = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["build", "--release", "--quiet", "-p", "bytebroom-scan"])
        .status()
        .unwrap();
    assert!(status.success(), "release build failed");
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    target.join("release")
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn the_release_binary_links_no_engine_functions_and_imports_nothing_that_acts() {
    let dir = release_dir();
    let pdb = fs::read(dir.join("bytebroom_scan.pdb")).unwrap();
    let exe = fs::read(dir.join("bytebroom-scan.exe")).unwrap();

    // Positive controls: the check reads the right files.
    for linked in ["find_duplicates", "summarize", "human_bytes"] {
        assert!(contains(&pdb, linked), "{linked} should be linked");
    }
    for imported in [
        "SHQueryRecycleBinW",
        "FindFirstFileExW",
        "GetFileInformationByHandleEx",
    ] {
        assert!(contains(&exe, imported), "{imported} should be imported");
    }

    // Function names only. Module and type names are not reliable here: the linker merges
    // identical generic code (e.g. `Vec<T>::grow_one` for same-sized T) under one of its names,
    // which can be a type from code that is not linked at all.
    for acting in [
        "delete_permanently",
        "delete_by_handle",
        "dispose",
        "shell_recycle",
        "recycle_one",
        "hold_chain",
        "run_move",
        "undo_move",
        "read_journal",
        "lock_dir",
        "remove_if_empty",
        "plan_clean",
        "check_root",
    ] {
        assert!(!contains(&pdb, acting), "the scan tool links {acting}");
    }
    for call in [
        "SHFileOperationW",
        "SHEmptyRecycleBinW",
        "SetFileInformationByHandle",
        "DeleteFileW",
        "RemoveDirectoryW",
        "MoveFileW",
        "MoveFileExW",
        "MoveFileWithProgressW",
        "CopyFileW",
        "CopyFileExW",
        "ReplaceFileW",
        "SetEndOfFile",
        "NtCreateFile",
        "NtSetInformationFile",
        "CreateDirectoryW",
        "CreateHardLinkW",
        "CreateSymbolicLinkW",
        "SetFileAttributesW",
        "SetFileTime",
    ] {
        assert!(!contains(&exe, call), "the scan tool imports {call}");
    }
}

/// Code with string literals and comments blanked out, so only what the code calls is checked.
fn code_only(source: &str) -> String {
    let mut out = String::new();
    for line in source.lines() {
        let line = line.split("//").next().unwrap_or("");
        let mut in_string = false;
        let mut escaped = false;
        for c in line.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                }
                continue;
            }
            if c == '"' {
                in_string = true;
                continue;
            }
            out.push(c);
        }
        out.push('\n');
    }
    out
}

#[test]
fn the_scan_tool_source_names_nothing_that_acts_or_writes_files() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let code = code_only(&fs::read_to_string(&path).unwrap()).to_lowercase();
        for banned in [
            "engine",
            "recycle::",
            "relocate",
            "clean::",
            "dispose",
            "delete",
            "remove",
            "rename",
            "copy",
            "fs::",
            "file::",
            "std::io",
            "write",
            "create",
            "command",
        ] {
            assert!(
                !code.contains(banned),
                "{} names `{banned}`",
                path.display()
            );
        }
    }
}

/// Security review S7: the core modules the scan runs must not write files or act either. `WriteFile`
/// can't be banned from the import table (printing to the terminal uses it), so a file write or a
/// log added to the scanner later would only be caught here. The list is narrower than the tool's
/// own (the walker copies bytes in memory with `copy_nonoverlapping`, for example).
#[test]
fn the_scanner_modules_name_nothing_that_acts_or_writes_files() {
    let core = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("core")
        .join("src");
    let modules = [
        core.join("scan.rs"),
        core.join("walk.rs"),
        core.join("red.rs"),
        core.join("locations.rs"),
        core.join("duplicates.rs"),
        core.join("summary.rs"),
        core.join("rules.rs"),
        core.join("win").join("walk.rs"),
        core.join("win").join("red.rs"),
        core.join("win").join("locations.rs"),
        core.join("win").join("hash.rs"),
    ];
    for path in modules {
        let code = code_only(&fs::read_to_string(&path).unwrap()).to_lowercase();
        for banned in [
            "fs::write",
            "fs::create",
            "fs::remove",
            "fs::rename",
            "fs::copy",
            "fs::hard_link",
            "file::create",
            "openoptions",
            "write_all",
            "writeln!",
            "engine::",
            "recycle::",
            "relocate::",
            "clean::",
            "dispose",
            "delete_by_handle",
            "access::delete",
            "access::move",
            "setfileinformation",
            "shfileoperation",
            "create_dir",
            "remove_dir",
            "remove_file",
            "lock_dir",
        ] {
            assert!(
                !code.contains(banned),
                "{} names `{banned}`",
                path.display()
            );
        }
    }
}

#[test]
fn code_only_blanks_strings_and_comments() {
    let code = code_only("let x = \"delete \\\" me\"; // remove\nfoo(\"a\");");
    assert!(!code.contains("delete") && !code.contains("remove") && !code.contains('a'));
    assert!(code.contains("let x =") && code.contains("foo("));
}
