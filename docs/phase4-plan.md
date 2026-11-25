# Phase 4 plan: elevation and the red tier

Status: decisions made (2026-11-25); the review's should-fixes come next, then task 0. Spec: `docs/spec.md`. Branch: `phase-4-elevation`.
Version after this phase: 0.4.0.

## What this phase proves

That ByteBroom can get administrator rights only when the owner asks, for exactly one job at a
time, and free red-tier space only through Windows' own tools. And that nothing elevated can be
steered by the page, by a user-writable file or by a swapped binary.

The riskiest part is the elevated code itself. Running as administrator, any path it follows,
any file it trusts or any argument it accepts from an unelevated process is a way to turn the
owner's account (or malware running as the owner) into full control of the PC. So phase 4 starts
by proving the smallest possible elevated piece, before any red-tier action exists.

## Carried over from phase 3 (done first, 2026-11-25)

Commit `7bca314`, all checks and the release build pass:

- **Open bug, the amber dialog:**
  - **Cause:** every failure path in the dialog plugin and `rfd` answers "Cancel", so only a press
    on "Clean them" (the default button) could let a clean through. The likeliest story is a stray
    second click or Enter, carried over from the page's own confirm onto a dialog that had no
    parent window.
  - **Fixes:**
    - the dialog opens over the main window;
    - only the exact answer "Clean them" counts;
    - an answer within one second is refused as unread;
    - every answer is logged to `ByteBroom\bytebroom.log`, with counts only.
  - **Harness check** (`src-tauri/examples/amber_dialog.rs`, which has no commands and touches no
    files): the dialog appeared over the window and stayed open for 10 seconds without a click,
    with nothing logged.
  - **Still to do:** the owner's real reproduction (owner check, below).
- **Security note 3:**
  - each file's identity is compared on the very handle that deletes, copies or recycles it;
  - for the Recycle Bin (the shell works by path), the identity is checked on the held handle;
  - an attribute-only handle then confirms that the checked file is what landed in
    `$Recycle.Bin`, and a warning is given if not;
  - the gap left over is documented in `recycle_targets`.
- **Security note 7:** the journal's folder and file, and the log, are opened from held handles
  without following links. A junction or a hard link in their place is refused.
- **Security review of these fixes** (2026-11-25): no must-fix. Should-fixes, to be fixed with
  tests before task 1:
  - **S1:** "Clean them" is still the default button, and the one-second timer starts before the
    dialog is really on screen. Fix: call `TaskDialogIndirect` ourselves (in `core::win`), with
    Cancel as the default and the timer started when the dialog is created.
  - **S2:** the Recycle Bin "watch" accepts any path under `$Recycle.Bin`, which the user can
    write to. Fix: compare against the item the shell reports it created
    (`IFileOperation` + `PostDeleteItem`), not the path.
  - **S3:** the journal's contents are user-writable. Rule: nothing elevated ever acts on a
    journal entry without re-checking both ends; phase 5's undo stays unelevated.
  - **Notes:**
    - N1: a name that differs only in case refuses (it fails safe), with a clearer message;
    - N3: document that folders and identity-less items are checked by the policy only;
    - N4: once elevated, UIPI also blocks fake clicks from unelevated programs;
    - N5: rotate `bytebroom.log`.

## Design (proposed; the decisions below choose between options)

- **A separate elevated helper**, `bytebroom-admin.exe`, with no window and no WebView:
  - it takes one argument, an action name from a fixed list (no paths, no free text);
  - it runs Windows' own tool for that action, from `System32`, with fixed arguments;
  - it writes a one-line result the app reads.

  The window stays unelevated. Each action is its own UAC prompt, clicked by the owner.
- **Elevate only an admin-owned binary:**
  - the app launches the helper only from an admin-owned folder (Program Files);
  - before acting, the helper itself checks that its own file and folder can't be written by
    ordinary users; if they can, it refuses.
- **The red tier in the window:**
  - each red item gets an action button with what it frees and whether it can be undone;
  - the owner types a confirm, then the UAC prompt appears;
  - sizes are measured again afterwards.
- **A restore point before any system change:** made by the helper (subject to Windows' one per
  24 hours limit). The result says whether a new one was made or the latest is recent.
- **Tests never change the real system:**
  - the helper's actions are pure plans (program + fixed arguments), checked by table tests;
  - running them goes through an injected runner, which records in tests;
  - the real runner exists only in the real build, and a test checks the test build can't
    reach it, and vice versa.

## Owner decisions

Decided by the owner on 2026-11-25:

1. **How to elevate:** a separate helper, `bytebroom-admin.exe` (no window, no WebView, a fixed
   list of action names). The window stays unelevated.
2. **Where the helper lives during phase 4:** `tools/install-helper.ps1`, which the owner runs as
   administrator. It copies the helper to `C:\Program Files\ByteBroom` and checks the folder's
   permissions; `tools/uninstall-helper.ps1` undoes it. The installer stays in phase 6.
3. **Red items with an action in V1:**
   - empty the Recycle Bin;
   - clear the Delivery Optimization cache;
   - shrink the hibernation file.

   Information only, with a button to Windows' own page where one exists:
   - the component store (DISM);
   - old restore points;
   - Windows.old and the Update store;
   - the page file.
4. **Hibernation file:** shrink it (`powercfg /h /type reduced`). Fast Startup keeps working;
   Hibernate leaves the power menu. Undo: `powercfg /h /type full`.
5. **Restore point:** automatic, before each action. A restore point from the last 24 hours
   counts. If System Restore is off or the restore point fails, the action stops and says why.
6. **Admin-only green items:** not in phase 4. The helper never deletes files.
7. **Typed confirm:** the action's short name ("recycle bin", "delivery optimization",
   "hibernation"), ignoring case.

## Tasks (riskiest first)

Each task: code → tests → fmt + clippy → full tests → build → commit with a "why" message.

- [ ] **0. Check each tool against Microsoft's documentation**
  - For every red item, record in this plan:
    - the Windows tool and its exact arguments;
    - whether it needs administrator rights;
    - what it frees, and whether it can be undone;
    - a link to Microsoft Learn.
  - Anything not documented by Microsoft is dropped or made information only.
- [ ] **1. The helper skeleton and the elevation path (no actions yet)**
  - Acceptance:
    - `bytebroom-admin.exe` accepts only the fixed action names; anything else exits with an
      error and does nothing;
    - it refuses to run from a folder ordinary users can write to;
    - the app starts it with `ShellExecuteExW("runas")` only from the admin-owned folder, waits,
      and reads the result;
    - a "no-op" action proves the round trip through a real UAC prompt (owner clicks).
  - Tests:
    - argument parsing (table);
    - the folder-ownership check on temp folders with chosen ACLs;
    - the app never builds a helper command line from page data (boundary test).
- [ ] **2. Restore point**
  - Acceptance:
    - the helper makes a restore point (System Restore must be on for the Windows drive), or
      reports that one was made in the last 24 hours, or that System Restore is off;
    - no red action runs without one of those answers.
  - Tests: the plan and the result parsing; the real call only in the owner's check.
- [ ] **3. Recovery recipe** in `docs/recovery.md`:
  - how to undo each action (for example `powercfg /hibernate on`);
  - how to roll back with System Restore, including from Windows' recovery screen;
  - what can't be undone (Windows.old, old restore points).
- [ ] **4. Red actions, one per commit** (the set from decision 3), each with:
  - its plan table test;
  - a recorded-runner test;
  - its text for the window (what it frees, whether it can be undone).
- [ ] **5. The window's red tier:**
  - buttons and the typed confirm (decision 7);
  - progress while the helper runs, the result and the sizes measured again;
  - the page sends only an action name, and the boundary test pins the new command.
- [ ] ~~**6. Admin-only green items**~~: not in phase 4 (decision 6).
- [ ] **7. Docs:**
  - the README: elevation, each red action, the recovery recipe;
  - the spec's phase 4 row and open question;
  - the docs-drift test covers the new commands and messages.
- [ ] **8. Security review** (`agent-skills:security-auditor`) of the helper, the elevation path,
  each action and the new command. Every must-fix is fixed with a test.
- [ ] **9. UI and accessibility pass** on the red tier through the harness.
- [ ] **10. Owner check:**
  - first, a restore point the owner checks exists, and the recovery recipe at hand;
  - then the owner's real reproduction of the amber dialog (below);
  - then each red action, one at a time, with exact steps.

  Claude verifies read-only (sizes, `powercfg /a`, `vssadmin list shadows`, the log). Merge with
  `--ff-only` on the owner's yes.

## Owner check for the phase 3 carry-overs (part of task 10)

1. Build: `./build.ps1`, then start `target\release\bytebroom.exe`.
2. Scan, then tick **one** amber installer you don't need, with the action **Recycle Bin**.
3. Preview, tick both confirms, press **Clean now**, then **don't click anything** for 10 seconds.
4. Expected: Windows' dialog "ByteBroom: clean your own files?" is over the ByteBroom window and
   stays there, and nothing is cleaned while you wait. Press **Cancel**: the page says nothing was
   cleaned.
5. Repeat and press **Clean them** after reading: the installer is in the Recycle Bin.
6. Tell Claude. Claude reads `ByteBroom\bytebroom.log` in your local app data (two lines,
   `Cancelled` and `Clean`, with how long the dialog was open).

## Risks

- **The elevated helper is attacked from the unelevated side:**
  - **swapped binary:** admin-owned folder only, checked by the app and by the helper;
  - **arguments:** a fixed list, no paths;
  - **planted files:** the helper reads no user-writable file; its result goes out only;
  - **DLL planting:** system DLLs are loaded from `System32` only (`SetDefaultDllDirectories`).
- **A Windows tool does more than expected:** task 0 checks each against Microsoft's
  documentation, and the restore point and recovery recipe come first.
- **Irreversible actions:** removing Windows.old ends the chance to go back to the previous
  Windows; deleting old restore points removes rollback points. The window says so before the
  typed confirm.
- **The 24-hour restore point limit:** the helper reports it plainly, instead of silently
  skipping the restore point.

## Results

(to be filled in)
