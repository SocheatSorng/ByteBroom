# Phase 5 plan: undo and history

Status: **decided, 2026-11-25.** The owner chose the recommended option for all six decisions
(see "Owner's decisions" below). Code starts once phase 4 is merged.
Branch: `phase-5-undo-history`, cut from `main` after phase 4 is merged.

## What this phase proves (from `docs/spec.md`)

- A move can be undone from the journal, from the window, safely.
- The owner can see what ByteBroom recycled and how to get it back.

## Before starting (carried over from phase 4)

1. **Phase 4's last owner check:** after 19:23 on 2026-11-26, run
   `cargo run --release -p bytebroom-admin --example elevate_restore_point`. Expected `Done`, and
   `rstrui.exe` lists "ByteBroom: restore point on request" (a fresh point, not a reused one).
2. **Merge phase 4** on the owner's yes: `git merge --ff-only phase-4-elevation` on `main`, then
   `./check.ps1` and `./build.ps1` on `main`.
3. Start the new branch from `main`. In a new worktree, fast-forward to `main` first.

## What already exists

- **The move journal:** `ByteBroom\moves.journal` in local app data, one line per moved file,
  version `bytebroom-move-v1`: time, SHA-256, size, source, destination (`core::relocate`).
- **`undo_move(policy, entry)`** (phase 1, tested, not yet in the window). The journal is
  user-writable, so entries are untrusted. It:
  - holds the original folder locked;
  - requires that folder to be inside the policy's allowed roots;
  - recreates the file *inside* it, never overwriting anything;
  - deletes the moved copy only after the restored file matches the recorded size and SHA-256.
- **Rule S3 from phase 4:** nothing elevated ever acts on a journal entry. Undo stays
  unelevated.
- **Recycling:** goes through `IFileOperation`, which reports the item it created in the bin.
  The log (`bytebroom.log`) holds counts only, never file names.

## Gaps to close

- The journal has no "undone" record. A second undo of the same entry fails, safely (the file
  exists), but the window can't tell "undone" from "still moved".
- The window has no history view and no undo button.
- Nothing records which items ByteBroom recycled. Windows' Recycle Bin shows them, mixed with
  everything else.

## Design (proposed)

- **History view** in the window: one list of past cleans, newest first.
  - **Moves:** read from the journal. Each shows "Put back", if both ends still check out.
  - **Recycled items:** read from ByteBroom's own record (decision 2). Each shows how to
    restore: "Open the Recycle Bin", or "Restore" (decision 3).
- **Undo a move:** the page sends only an ID from the history list it was given, never a path.
  - Rust re-reads the journal and calls `undo_move`.
  - Afterwards it appends an "undone" line, so the entry shows as undone.
  - The undone line uses a new journal version (`bytebroom-move-v2`, or a separate
    `bytebroom-undo-v1` line type). Old files still read, and an old line is never read as a new
    one (the owner's rule on stored data).
- **A native confirm before an undo?** Proposed: no. An undo only recreates a file where it was
  and deletes the moved copy after checking it. Decision 4 asks.
- **Tests:**
  - fake journals in temp folders only;
  - forged entries (paths outside the roots, swapped hashes, links) refused, building on
    `tests/locked.rs`;
  - undo twice refused, with a clear "already put back";
  - the boundary test pins the new commands (IDs only).

## Owner decisions (recommended option first)

1. **What may be undone:**
   - (a) **moves only (recommended):** the journal has everything needed, checked by hash;
   - (b) moves and recycled items.
   - Permanent deletes can never be undone.
2. **A record of what ByteBroom recycled** (file names, kept in local app data like the journal):
   - (a) **yes, `ByteBroom\recycled.journal` (recommended):** the window can list them; it is
     never committed, never sent, and can be cleared from the window;
   - (b) no, the window only says "open the Recycle Bin".
3. **Restoring a recycled item from ByteBroom:**
   - (a) **"Open the Recycle Bin" only (recommended):** Windows' own Restore is used, so
     ByteBroom never writes into `$Recycle.Bin`;
   - (b) a "Restore" button through the shell's own verb.
4. **Confirm before undoing a move:**
   - (a) **the page's own confirm only (recommended):** undo deletes nothing until the
     restored file matches;
   - (b) also Windows' own dialog, as for amber items.
5. **How long history is kept:**
   - (a) **until the owner clears it, with a "Clear history" button (recommended);** clearing
     never touches the files;
   - (b) a fixed limit (e.g. 90 days or 10,000 lines).
6. **Undo many at once:**
   - (a) **one clean's moves as a group, plus single items (recommended);**
   - (b) single items only.

## Owner's decisions (2026-11-25)

1. **(a) Moves only** can be undone. Recycled items are restored with Windows' own Restore.
2. **(a) Yes:** ByteBroom keeps `ByteBroom\recycled.journal` in local app data. It is never
   committed or sent, and can be cleared from the window.
3. **(a) "Open the Recycle Bin" only:** ByteBroom never writes into `$Recycle.Bin`. Task 0's
   check of the shell's restore verb is not needed.
4. **(a) The page's own confirm only** before "Put back". There is no native dialog.
5. **(a) History is kept until the owner clears it** with "Clear history". Clearing never
   touches the files.
6. **(a) One clean's moves can be put back as a group,** or as single items.

## Tasks (riskiest first)

Each task: code → tests → fmt + clippy → full tests → build → commit with a "why" message.

0. **Check the facts:**
   - the journal format and `undo_move`'s checks, against `tests/locked.rs`;
   - if decision 3 is (b), Microsoft's docs for restoring a Recycle Bin item through the shell.
1. **Journal v2 or undo line:** written and read, old lines still read, version tests,
   docs-drift.
2. **Undo in core:** `undo_entry(journal, id)`, which re-reads the entry, calls `undo_move` and
   appends "undone". Covered by forged-entry, double-undo and partial-failure tests.
3. **Recycled record** (if decision 2 is (a)): written after each confirmed recycle, from the
   item the shell reported. No names in `bytebroom.log`.
4. **Window:**
   - a History view: moves with "Put back", recycled items with "Open the Recycle Bin";
   - "Clear history";
   - new commands (IDs only) pinned in the boundary test, capability file and `build.rs`.
5. **Docs:** the README's history and undo section, the spec's phase 5 row, docs-drift.
6. **Security review** (`agent-skills:security-auditor`) of undo, the journals and the new
   commands. Every must-fix is fixed with a test.
7. **UI and accessibility pass** (`bytebroom-ui-designer`) with fake history in the harness.
8. **Owner check:**
   - move a test file to another drive, put it back, and check its hash;
   - try putting it back twice;
   - recycle a file and find it in the history;
   - then the merge with `--ff-only` on the owner's yes.

## Risks

- **A forged journal line** (it is user-writable): `undo_move` already refuses anything outside
  the roots and checks the hash. Undo stays unelevated.
- **The original folder is gone or replaced:** undo refuses and says why; it never creates
  folders outside the roots.
- **The destination drive is missing** (unplugged): "Put back" is unavailable, with the reason.
- **The history file lists file names:** it stays in local app data, is never committed or sent,
  and can be cleared.

## Results

2026-11-25, on `phase-5-undo-history` (cut from `main` after the owner merged phase 4):

- **Tasks 0-3** (`9f0ccb4`): moves are written as `bytebroom-move-v2` (clean number first); a
  put-back is `bytebroom-undone-v1`; v1 lines still read. `undo_entries` re-reads the journal per
  file. `undo_move` remakes a moved folder's missing folders, only inside the roots. Recycling
  records the bin item the shell reported in `recycled.journal`.
- **Tasks 4-5** (`dd2c553`): History view, `history` / `put_back` / `clear_history` (IDs only),
  README section, docs-drift checks.
- **Task 6, security review:** one must-fix and three should-fixes, all fixed with tests
  (`8462ced`):
  - S1 (must-fix): put back and clear refuse when the window runs as administrator;
  - S2: the window's journal use is in `history_cmd.rs` only, and the S3 tripwire is wider;
  - S3: a kept moved copy is reported, never "nothing changed";
  - S4: a junction planted on the way to the original folder is refused.
  The notes are also done: no put-back into the startup folder, WindowsApps or ByteBroom's own
  folder, and a test for a junction named like a journal.
- **Task 7, UI pass** (`393dbf2`): buttons stay in view at 720x520, results are announced from
  the dialog's own live region, focus goes to the next Put back button, long names wrap.
- Checks: `./check.ps1` passes (322 tests), and `./build.ps1` builds both binaries.
- **Owner's check, 2026-11-25: passed.**
  - The move to another drive, the History, the put-back (the same SHA-256 before and after), the
    recycled item in Windows' Recycle Bin and clear history all worked as written. A finished
    clean read "all put back".
  - Claude's read-only check: `move-me.bin` is back at 629,145,600 bytes and gone from the other
    drive, and both journals are empty after the clear (recreated when the History reread them).
  - The History also listed an older move from before phase 5 (a `bytebroom-move-v1` line, shown
    as a clean of its own, as designed). Clearing removed that record too; the file itself is
    still where it was moved. Lesson: an owner check that clears the history should say that it
    forgets every earlier move, not only the test's.
- **Open:** the merge, on the owner's yes.
- Known limit: a file can't be put back directly into a profile folder or a drive root (never a
  policy root); the window says so and the owner moves it by hand.
