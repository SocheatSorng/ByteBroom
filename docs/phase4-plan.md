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
- **Security review of these fixes** (2026-11-25): no must-fix. The should-fixes were fixed with
  tests on 2026-11-25 (see "Review fixes" below). They were:
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

### Review fixes (2026-11-25)

- **S1:**
  - `core::win::taskdialog`, ByteBroom's own task dialog: Cancel is the default button, and Esc
    and the close box cancel;
  - it is owned by the main window, and the clock starts at `TDN_CREATED`;
  - `TaskDialogIndirect` is looked up at run time, so programs without the manifest start and
    report it "unavailable", which never confirms.

  Harness: Enter on the dialog gave `Cancelled`, logged with `parent=main window`.
- **S2:**
  - recycling goes through `IFileOperation` (`core::win::fileop`), whose `PostDeleteItem`
    reports the item created in the bin;
  - that item must have the checked file's file ID (`is_same_open_file`), or the result warns.

  Tested with stand-in shells, the file-ID comparison on temp files, and a missing item. The
  real call is proven only by the owner's opt-in one-file test, which now passes the file's
  identity.
- **S3:**
  - the rule is in `docs/spec.md` (rule 5), and a test sweeps the source for journal readers;
  - `undo_move` refuses a "moved file" that is not exactly at the journalled path, is in a
    protected area, or has other names.
- **N5:** `bytebroom.log` starts again above 256 KB, keeping one `.old` copy, renamed inside
  the held folder without following links.
- **Still notes:**
  - N1: a name differing only in case refuses, failing safe;
  - N4: UIPI blocks fake clicks once elevated.
- **Re-review** (2026-11-25): no must-fix. Fixed with tests:
  - **R1:** the shell parses names through its namespace, where a folder made into a "folder
    shortcut" by a planted `desktop.ini` could point elsewhere. The shell item must be exactly
    the checked path, both before the delete is queued and again in `PreDeleteItem`, which
    stops the shell otherwise. COM runs in-process only. The test builds a real folder shortcut
    in temp and parses through it (nothing is recycled).
  - **R2:**
    - undo always runs unelevated (rule in `docs/spec.md`);
    - the source sweep now fails on any mention of the journal readers or `undo_move` outside
      the move module, which also catches renamed imports.
  - **N1:** when Windows reports nothing in the bin, the warning says it may have deleted the
    item permanently, instead of "another file took its place".
  - **Owner check:** while the dialog is open, the ByteBroom window must not respond to clicks
    (the dialog runs on a worker thread; see the owner check steps).

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
   - turn hibernation off (decision 4).

   Information only (task 0 says which have a Windows page to open):
   - the component store (DISM);
   - old restore points;
   - Windows.old and the Update store;
   - the page file.
4. **Hibernation file:** turn hibernation off (`powercfg /hibernate off`); revised by the owner
   on 2026-11-25 after task 0.
   - It removes `hiberfil.sys`. Hibernate and Hybrid Sleep stop working; Fast Startup is
     already disabled by policy on the owner's PC.
   - Undo: `powercfg /hibernate on`.
   - (The first answer, "reduced", only keeps Fast Startup, which is off here.)
5. **Restore point:** automatic, before each elevated action. A restore point from the last
   24 hours counts. If System Restore is off or the restore point fails, the action stops and
   says why.
6. **Admin-only green items:** not in phase 4. The helper never deletes files.
7. **Typed confirm:** the action's short name ("recycle bin", "delivery optimization",
   "hibernation"), ignoring case.
8. **Empty the Recycle Bin** (owner, 2026-11-25, after task 0): in the unelevated window, with
   no helper, no UAC prompt and no restore point.
   - It needs no administrator rights, and a restore point can't bring emptied files back.
   - It still takes the typed confirm "recycle bin" and says it can't be undone.

   The helper's actions are therefore: restore point, Delivery Optimization cache, hibernation
   off.

## Tasks (riskiest first)

Each task: code → tests → fmt + clippy → full tests → build → commit with a "why" message.

- [x] **0. Check each tool against Microsoft's documentation** (2026-11-25)

  Read on Microsoft Learn and Microsoft Support. "Not stated" means the page doesn't say; it
  is checked on the owner's PC or treated as unknown, never assumed. Read-only checks on the
  owner's PC: `Get-Command Delete-DeliveryOptimizationCache` and `powercfg /a`.

  **Actions (decision 3)**

  - **Empty the Recycle Bin:** `SHEmptyRecycleBinW(hwnd, NULL, SHERB_NOCONFIRMATION |
    SHERB_NOPROGRESSUI | SHERB_NOSOUND)`.
    - A `NULL` root empties "all Recycle Bins on all drives"; it returns `S_OK` or an
      `HRESULT`.
    - No administrator requirement is stated: it is the user's own bin.
    - It can't be undone: the files are gone for good.
    - [SHEmptyRecycleBinW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shemptyrecyclebinw)
  - **Clear the Delivery Optimization cache:** `Delete-DeliveryOptimizationCache -Force`
    (module `DeliveryOptimization`), in Windows PowerShell started from `System32` by full path.
    - Without `-IncludePinnedFiles`, pinned files are kept.
    - It needs "an elevated PowerShell session".
    - "Deletion can't be undone"; Windows re-downloads what it needs. The FAQ says Windows also
      clears this cache itself after a while, or when it grows too big.
    - **On the owner's PC:** the cmdlet is present (DeliveryOptimization 1.0.2.0, Windows 10
      19045).
    - [Delete-DeliveryOptimizationCache](https://learn.microsoft.com/en-us/powershell/module/deliveryoptimization/delete-deliveryoptimizationcache),
      [Delivery Optimization FAQ](https://learn.microsoft.com/en-us/windows/deployment/do/waas-delivery-optimization-faq)
  - **Hibernation file:** `powercfg /hibernate /type reduced | full`, `powercfg /hibernate off | on`.
    - Microsoft: "A reduced hiberfile only supports hiberboot" (hiberboot is Fast Startup's
      mechanism).
    - To switch to reduced, Windows must manage the file's size: `powercfg /hibernate /size 0`
      first, then `/type reduced`.
    - The page states no administrator requirement for `/hibernate`; the helper runs it
      elevated anyway.
    - **Undo:** `powercfg /hibernate /type full` or `powercfg /hibernate on`. Both follow from the
      syntax; neither is shown as an example.
    - The page gives no size for "reduced". The plan's earlier "about 20% of RAM" is dropped
      as unverified; the window measures the file before and after.
    - **On the owner's PC** (`powercfg /a`): Hibernate and Hybrid Sleep are available, and
      **Fast Startup is "disabled in the current system policy"**. A reduced file would serve
      nothing here. Decision 4 was asked again: hibernation off.
    - [powercfg command-line options](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options)

  **Restore point (decision 5)**

  - **The call:** `SRSetRestorePointW`, loaded at run time from `SrClient.dll` (Microsoft:
    don't link it at load time).
    - It takes `BEGIN_SYSTEM_CHANGE` + `MODIFY_SETTINGS`, then `END_SYSTEM_CHANGE` with the
      returned sequence number.
    - COM security must let NetworkService, LocalService and System call back
      (`CoInitializeSecurity`). The "Using System Restore" page with the details is still to
      read in task 2.
  - **Results:**
    - it fails with `ERROR_SERVICE_DISABLED` when System Restore is off;
    - it fails with `ERROR_DISK_FULL` when System Restore is in standby for low disk space;
    - it can't be called in safe mode.
  - **The 24-hour limit:** "Windows skips creating this new restore point if any restore points
    have been created in the last 24 hours". It then returns success with the earlier point's
    sequence number.
    - So the helper reads the newest restore point's sequence number before calling. The same
      number back means "a recent restore point is reused", and the window says so with that
      point's date.
    - The window is the `SystemRestorePointCreationFrequency` value (minutes) under
      `HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore`. ByteBroom never
      changes it.
  - **Administrator rights:** not stated for the call itself; listing restore points
    (`Get-ComputerRestorePoint`) "Run as administrator". It runs in the helper.
  - **Not used:** `Checkpoint-Computer`, which reports the 24-hour skip as an error and needs a
    PowerShell process.
  - [SRSetRestorePointW](https://learn.microsoft.com/en-us/windows/win32/api/srrestoreptapi/nf-srrestoreptapi-srsetrestorepointw),
    [STATEMGRSTATUS](https://learn.microsoft.com/en-us/windows/win32/api/srrestoreptapi/ns-srrestoreptapi-statemgrstatus),
    [Checkpoint-Computer](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/checkpoint-computer?view=powershell-5.1),
    [Get-ComputerRestorePoint](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-computerrestorepoint?view=powershell-5.1)

  **Information only, with Windows' own page**

  - **Component store (WinSxS):**
    - Microsoft says never delete the folder by hand. The supported tools are the
      `StartComponentCleanup` task, `Dism.exe /online /Cleanup-Image /StartComponentCleanup`
      (elevated), and Disk Cleanup.
    - `/ResetBase` means "existing update packages can't be uninstalled", so ByteBroom never
      suggests it.
    - The window shows the size and names the Storage settings page.
    - [Clean up the WinSxS folder](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder)
  - **Windows.old and the Update store:**
    - Settings › System › Storage › Temporary files › "Previous version of Windows" (needs
      administrator rights). Windows deletes it itself 10 days after an upgrade.
    - Removing it can't be undone and ends going back to the previous Windows.
    - Button: `ms-settings:storagesense`.
    - [Delete your previous version of Windows](https://support.microsoft.com/en-us/windows/delete-your-previous-version-of-windows-f8b26680-e083-c710-b757-7567d69dbb74)
  - **Old restore points:**
    - Settings has no page for System Protection (no `ms-settings:` URI is listed for it).
    - The window shows the size and says how to reach it: System Properties › System Protection.
    - No button in V1.
  - **Page file:**
    - Microsoft doesn't advise removing it: it backs the commit limit and crash dumps.
    - Shown as information only, with no button. The Learn page doesn't name the
      Virtual-memory dialog, so ByteBroom doesn't either.
    - [Introduction to the page file](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/introduction-to-the-page-file)
  - **Settings pages used:** `ms-settings:storagesense` (Storage), `ms-settings:powersleep`
    (Power & sleep).
    - [Launch the Settings app](https://learn.microsoft.com/en-us/windows/apps/develop/launch/launch-settings-app)

  **Design consequence:** emptying the Recycle Bin needs no administrator rights, and a
  restore point can't bring those files back. So it needs no helper, no UAC prompt and no
  restore point (decision 8, owner: yes).
- [x] **1. The helper skeleton and the elevation path (no actions yet)**: built and tested
  2026-11-25; the real UAC round trip waits for the owner (steps under "Owner check for task 1").
  - **Security review** (2026-11-25): no must-fix. Should-fixes, all fixed with tests:
    - **S1:** the install script runs no copied program elevated. It always starts from a fresh
      folder, and checks the folder's and the file's permissions with a PowerShell copy of the
      helper's rule (`tools/helper-acl.ps1`), which a test cross-checks against the Rust rule
      on real files. Remaining trust: the helper is copied from `target\release`, which the
      owner's account can change (stated in the script and the README).
    - **S2:** UAC's `runas` verb is looked up in `HKLM\SOFTWARE\Classes\exefile`
      (`SEE_MASK_CLASSKEY`), never the per-user class, which the user's account could
      override. The owner checks the prompt names `bytebroom-admin.exe` in
      `C:\Program Files\ByteBroom`.
    - **S3:** the helper is linked with `/DEPENDENTLOADFLAG:0x800`, so even its start-up DLLs
      come only from System32. A test reads the flag from the built program's PE header, and
      fails without it.
    - **S4:** the helper starts in System32 (`lpDirectory`) and makes it its current folder
      first thing.
    - **N4:** a path that isn't exactly the expected one is reported as such, not as "a link".
  - **Rules from the review for tasks 2 and 4:**
    - **N1:** the restore point is made or verified *inside* the helper, in the same run as
      each action, which refuses without it. The app never sequences a separate restore-point
      call: the unelevated app can be tampered with.
    - **N2:** the helper starts Windows tools by their full System32 path (from
      `GetSystemDirectoryW`), with a minimal explicit environment block (no inherited `PATH`,
      `PSModulePath`, `windir` or `SystemRoot`).
      - PowerShell gets `-NoProfile -NonInteractive`, and the Delivery Optimization module is
        imported by its full System32 path.
      - `powercfg` is started the same way.
  - **Still open (N3):** a test with a crafted access list that has an admin owner and a
    single bad entry. Setting an admin owner needs administrator rights, so it waits for a
    harness the owner runs; the pure rules cover these cases in tables.
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
   stays there, and nothing is cleaned while you wait. **Cancel** is the highlighted button. Try
   clicking the ByteBroom window behind it: it should not respond. Press **Enter**: the page says
   nothing was cleaned.
5. Repeat and press **Clean them** after reading: the installer is in the Recycle Bin.
6. Also run the opt-in Recycle Bin test (it recycles one 4 KB dummy file,
   `bytebroom-test-….txt`, that you can delete from the bin afterwards):
   `$env:BYTEBROOM_REAL_RECYCLE_BIN_TESTS = "1"; cargo test -p bytebroom-core --test recycle real_bin_recycles_one_dummy_file -- --ignored --nocapture`
7. Tell Claude. Claude reads `ByteBroom\bytebroom.log` in your local app data (two lines,
   `Cancelled` and `Clean`, with how long the dialog was open).

## Owner check for task 1 (the UAC round trip)

In your project folder:

1. In an ordinary PowerShell, run `./build.ps1`.
2. In an **administrator** PowerShell, run `./tools/install-helper.ps1`.

   Expected: "Installed: C:\Program Files\ByteBroom\bytebroom-admin.exe … Only administrators can
   change it." Any other answer stops the script; tell Claude what it said.
3. Back in the **ordinary** PowerShell, run
   `cargo run --release -p bytebroom-admin --example elevate_noop`.
   - A UAC prompt appears. Click **Show more details**: the program location must be
     `"C:\Program Files\ByteBroom\bytebroom-admin.exe" noop`. If it names anything else,
     click **No** and tell Claude.
   - If it matches, click **Yes**. Expected: `Answer: Done (done)`.
   - Run it again and click **No**. Expected: `Not run: Cancelled`.
4. Tell Claude. Claude checks read-only that only `Program Files\ByteBroom\bytebroom-admin.exe`
   was added.

To remove the helper: run `./tools/uninstall-helper.ps1` in an administrator PowerShell.

**Result (2026-11-25), passed:**
- **Install:** `C:\Program Files\ByteBroom` holds only `bytebroom-admin.exe`. Its SHA-256 matches the
  build, and both the folder and the file pass the admin-owned rule. Run unelevated, the
  installed helper passes its own location check and stops with exit 4 ("not elevated").
- **UAC round trip,** from an ordinary console: Yes gave `Answer: Done (done)`, No gave
  `Not run: Cancelled`. So the machine-wide (HKLM) `runas` lookup works.
- **Lesson:** a first try ran the harness from the administrator console used for the install.
  An already-elevated program starts the helper with no prompt, so both runs said `Done`. Every
  later owner step names which console to use.

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
