# Spec: ByteBroom — V1

Status: draft, waiting for the owner's approval. Intent: `docs/intent/bytebroom.md`.

## Objective

ByteBroom is a Windows desktop app that frees disk space safely. It scans a drive, sorts what it finds
into three tiers with sizes, and acts only on items the user has previewed and confirmed. For each item
the user chooses one action: Recycle Bin, permanent delete, or move to another drive.

| Tier | What | Default | Confirmation |
|---|---|---|---|
| Green | Temp folders, app/browser/developer caches, crash dumps, thumbnail cache, Delivery Optimization, old logs | Pre-ticked | One confirm for the batch |
| Amber | Personal files (large/duplicate finder, Downloads, old installers), code projects, keys and vaults, leftovers of removed apps | Never pre-ticked | Extra confirm listing every amber item |
| Red | Windows, Program Files, pagefile/hiberfil/swapfile, restore points, Windows Update store, Recycle Bin contents | Never listed as files | Admin rights and a typed confirm; freed only through Windows' own tools |

Default action, changeable per item (owner's decision, 2026-11-25, `docs/phase3-plan.md`):

- **Green:** permanent delete. These are rebuilt by Windows or the app, and recycling them on the same
  drive frees nothing until the bin is emptied.
- **Amber:** the Recycle Bin.

Users: the owner on their own PC first, then other people who download it from GitHub Releases.

## Tech stack

- **Rust** (stable, pinned in `rust-toolchain.toml`), MSVC target, using the Visual Studio Build Tools 2022
  that are already on the owner's PC.
- **Core crate** `bytebroom-core`: scanning, tier rules, the delete engine. It uses the `windows` crate for
  Win32 calls and contains no UI code.
- **App**: Tauri 2 with an HTML/CSS/vanilla-JS window in WebView2. The window holds no file logic; it calls
  Tauri commands in Rust.
- **Updates**: the Tauri updater plugin, which checks a signature key that only the owner holds.
- **Installer**: Tauri bundler (NSIS), published on GitHub Releases.

## Commands (filled in and drift-tested from phase 1)

```
Format check:   cargo fmt --all -- --check
Lint:           cargo clippy --workspace --all-targets -- -D warnings
Test:           cargo test --workspace
Dependency audit (advisories, licenses, sources): cargo deny check
All checks:     ./check.ps1
Run the app:    cargo tauri dev          (phase 3)
Build:          ./build.ps1              (phase 3; release installer in phase 6)
```

## Project structure

```
crates/core/        bytebroom-core: path policy, delete engine, scanner, tier rules
crates/core/tests/  integration tests on fake trees in temp folders
src-tauri/          Tauri app (phase 3): commands, elevation, updater
ui/                 HTML/CSS/JS for the window (phase 3)
tools/              verify-tree.ps1 (independent checker), ui-harness/ (fake-data screenshots)
docs/               intent, spec, phase plans, recovery recipe
```

## Code style

`rustfmt` defaults and `clippy -D warnings`. Unsafe Win32 calls live only in `crates/core/src/win/`.
Every other module has `#![forbid(unsafe_code)]`. Errors are typed (`thiserror`) and never use `unwrap()`
outside tests. Decisions are made by pure functions that are easy to test, and the Windows calls are kept
in thin adapters:

```rust
/// Decide whether `target` may be acted on. Pure: the caller passes resolved facts.
pub fn check_target(target: &ResolvedPath, policy: &Policy) -> Result<Tier, Refusal> {
    if target.is_reparse_point {
        return Err(Refusal::ReparsePoint);
    }
    if !policy.allowed_roots.iter().any(|root| target.final_path.is_strictly_inside(root)) {
        return Err(Refusal::OutsideAllowedRoots);
    }
    policy.tier_of(&target.final_path).ok_or(Refusal::DeniedArea)
}
```

## Delete engine rules (the safety core)

1. **Only inside an allowed root.** Each scan names its roots. The engine opens the target without
   following its last component (`FILE_FLAG_OPEN_REPARSE_POINT`), then reads the real path from the
   handle (`GetFinalPathNameByHandle`). It acts only if that real path is strictly inside a resolved
   allowed root. A junction in the middle of the path that leads elsewhere is therefore refused. Paths are
   compared case-insensitively with the Windows ordinal rules, after normalisation (`\\?\`, 8.3 names,
   trailing dots and spaces).
2. **Hard floor (deny list):**
   - the system drive root, `%SystemRoot%` (except `%SystemRoot%\Temp`), Program Files (both), and
     ProgramData's top level;
   - `pagefile.sys`, `hiberfil.sys` and `swapfile.sys`;
   - `System Volume Information`, `$Recycle.Bin`, `Boot`, `EFI` and `Recovery`;
   - each user profile's root folder.

   These areas are never deleted as files, whatever the UI asks. Red-tier space is freed only through
   Windows' own tools (phase 4).
3. **No links.** Symlinks, junctions and other reparse points are never followed during a scan and never
   deleted as targets. Folders are deleted bottom-up using handles, and the delete is done through the
   same handle that passed the check (`FileDispositionInfoEx`), which closes the time-of-check gap.
4. **Recycle Bin only where it exists.** Before recycling, the engine checks that the drive has a Recycle
   Bin. It never lets Windows silently turn "recycle" into a permanent delete (subst, network or removable
   drives). The UI warns that recycling on the same drive frees no space until the bin is emptied.
5. **Move = copy, verify, then delete.** Each file is copied to the destination and checked by size and
   SHA-256 before the source is removed. Every move is written to a journal in `%LOCALAPPDATA%\ByteBroom`,
   so it can be undone. The journal is user-writable, so its entries are untrusted:
   - only the undo in the move module reads it (a test sweeps the source for any other reader
     or caller). Undo always runs unelevated, with the owner's own rights: run elevated, a
     forged entry could plant the owner's bytes in a folder only administrators may write;
   - undo re-checks both ends: the original folder against the policy, and the moved file at
     exactly the journalled path, off the hard floor, with one name and the journalled hash.

   The journal's folder and file are opened without following links.
6. **Files in use** are skipped and reported, never forced.
7. **Honest accounting.** "Space freed" counts only bytes that really come back. A hard link with other
   names left, or a file sent to a Recycle Bin on the same drive, counts as 0.

## Testing strategy

- **Unit tests** cover the pure functions: path policy, tier rules, accounting and journal parsing,
  including `proptest` cases that try escapes (`..`, `\\?\`, UNC, 8.3 names, alternate data streams,
  trailing dots, mixed case, device paths).
- **Integration tests** run the real Win32 engine on fake trees in a fresh temp folder only. Each test
  builds a tree with junctions, a file that is held open, hard links and a "sentinel" folder outside the
  allowed root. The sentinel must survive every test.
- **Independent check:** `tools/verify-tree.ps1` (PowerShell, not Rust) snapshots a tree with
  SHA-256 hashes before and after an operation. Tests use it to prove that only the intended files changed.
- **Safety sweep tests:** every deny-list path is refused; every action refuses targets outside the root;
  and the engine refuses to start when the allowed root is a drive root or a profile root.
- **Docs-drift test:** the commands, limits and messages in the README and guides must exist in the code.
- **CI** runs on `windows-latest`. Its runners are disposable, so the real Recycle Bin tests run there.
- A test is added for every bug found.

## Phases (riskiest first)

| # | Phase | Proves | Result |
|---|---|---|---|
| 1 | **Safe delete engine** (core crate only, no UI) | Deletions can't escape their root, links are refused, and the Recycle Bin, permanent delete and move all work and can be checked independently | Done 2026-11-25: 79 tests, security review fixed, owner's Recycle Bin check passed |
| 2 | **Scanner and tier rules** | The scan finds the green, amber and red categories on fake trees, sizes them correctly and doesn't follow links; a full scan of a large tree is fast enough | Done 2026-11-25: read-only scan tool, security review fixed, owner's totals matched Windows; real scan 175.5 s |
| 3 | **Window (unelevated)** | Scan → list → per-item action → preview → confirm, in a Tauri window; UI designer pass with fake data | Done 2026-11-25: security, UI and accessibility reviews fixed; owner's real clean, move and recycle verified. Open: the native amber confirm wasn't seen (see `docs/phase3-plan.md`) |
| 4 | **Elevation and the red tier** | A window-less helper (`bytebroom-admin.exe`, admin-owned folder) runs Windows' own tools on demand, one UAC prompt per action: a restore point first, then the Delivery Optimization cache or hibernation off; the window empties the Recycle Bin itself (no admin rights needed). Harness, review, restore point and recovery recipe first. Tools and decisions: `docs/phase4-plan.md` | Built; owner check pending |
| 5 | **Undo and history** | Undo a move from the journal, one file or one clean's moves, from the window, unelevated, checked by hash; show recycled items (`recycled.journal`) and restore them with Windows' own Recycle Bin; clear the history. Decisions: `docs/phase5-plan.md` | Done 2026-11-25: security review (1 must-fix) and UI pass fixed; owner's move, put-back (same SHA-256), recycle and clear check passed |
| 6 | **Release** | Installer, signed updater, GitHub Releases, publishing checklist, first push. Decisions: `docs/phase6-plan.md` | Built 2026-11-26, version 1.0.0: per-machine installer with the helper, signed updater, `release.ps1`; reviews, owner check and first push next |

Each phase gets `docs/phaseN-plan.md`, its own branch (`phase-N-...`), a security review whenever it
deletes, elevates or updates, and a real-world test by the owner. Its result is recorded in the table
above.

## Success criteria (V1)

- On the owner's PC, one session frees a lot of space on C: (the target is 30 GB or more; it depends on
  what is there), and Windows and every app still work afterwards.
- No test, harness or CI run has ever touched a file outside its temp root (the sentinel checks pass).
- Every moved file can be restored from the journal, and every recycled file can be restored from the
  Recycle Bin.
- Security reviews have no open must-fix items; the workflows are green.
- A stranger can install it from GitHub Releases, and updates install only when the signature checks out.

## Boundaries

- **Always:**
  - test on fake trees in temp folders;
  - run fmt, clippy, tests and `cargo deny` after every change and report the result;
  - re-check every target at the moment of the action;
  - write moves to the journal before deleting the source;
  - get a security review for deletion, elevation and updater changes.
- **Ask first:**
  - adding a crate dependency;
  - changing the deny list or tier rules;
  - changing CI or the release and updater setup;
  - anything that runs as administrator;
  - running ByteBroom on a real drive. The owner does that, with exact steps from Claude.
- **Never:**
  - delete files in the red tier;
  - follow a reparse point;
  - act on an item the user did not confirm;
  - touch the owner's real files, drives or Recycle Bin from a test;
  - click UAC or handle passwords;
  - commit scan results, logs, the updater's private key or personal paths;
  - push without being asked.

## Out of scope (deferred)

- Registry "cleaning": risky and gains almost nothing.
- Scheduled automatic cleaning: the owner chose manual runs.
- Microsoft Store and winget: more packaging and review steps.
- A paid code-signing certificate: may be added after V1.
- Translations: English only for V1.
- Other PCs on a network and network drives as targets.
- Reading the NTFS MFT directly for faster scans: only if phase 2 shows plain walking is too slow.

## Open questions

- Phase 2: the large-file threshold and the installer age. Decided in `docs/phase2-plan.md`: 500 MB
  and 30 days.
- Phase 4: which Windows tools free which red-tier items. Answered in `docs/phase4-plan.md`
  task 0 (2026-11-25), each against Microsoft's documentation with links.
  Built in tasks 1 to 5: the Recycle Bin, the Delivery Optimization cache and hibernation off; how
  to undo each and roll back is in `docs/recovery.md`.
