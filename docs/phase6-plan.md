# Phase 6 plan: release

Status: **decided, 2026-11-25.** The owner chose the recommended option for all eight decisions
(see "Owner decisions"). Task 0 is the Windows dialog check below, then the plan's tasks.
Branch: `phase-6-release`, cut from `main` at `1b05dcd` (phase 5 merged). In a new worktree,
fast-forward to `main` first.

## What this phase proves (from `docs/spec.md`)

- A stranger can install ByteBroom from GitHub Releases.
- Updates install only when their signature checks out, against a key only the owner holds.
- The repo passes the publishing checklist, and every workflow is green on GitHub.

## Before starting (carried over)

1. **Phase 4's last owner check**, if not done yet: after 19:23 on 2026-11-26, run
   `cargo run --release -p bytebroom-admin --example elevate_restore_point`. Expected `Done`, and
   `rstrui.exe` lists a fresh "ByteBroom: restore point on request" (`docs/phase4-plan.md`).
2. **Phase 3's open item: still open, and now a possible safety bug.** Asked on 2026-11-25, the
   owner said a dialog appeared during the phase 5 check and they closed it with **Esc** ("a random
   guess, but it did close"). `src-tauri/src/confirm.rs` treats Esc as Cancel, so if that was
   ByteBroom's "clean your own files?" dialog, the clean should have stopped, yet the phase 5
   recycle went ahead. Either the dialog was a different one, or Esc let a clean through.
   **Task 0 (before the installer):**
   - log the native confirm's result (Confirmed / Cancelled, never file names) and show the dialog
     with the main window as its parent;
   - a test that every outcome other than the confirming button stops the clean, including Esc;
   - owner check with exact steps: one amber test file to the Recycle Bin, press Esc on the
     dialog, and expect "nothing cleaned"; then repeat with "Clean them" and expect it recycled.
     Claude reads the log line and the Recycle Bin read-only.
   Close the item in `docs/spec.md` only after that check passes.

   **Task 0 results (2026-11-25, branch `claude/phase-6-esc-dialog-efd777`): Esc cancels. The
   dialog the owner closed with Esc was not the clean's Windows dialog.**
   - **Evidence, from `bytebroom.log`** (read-only; it holds counts and answers, no file names).
     The phase 5 clean of the two test files is the line at 23:22 (+0700):
     `amber-confirm items=2 parent=main window answer=Confirm open_ms=5851 Clean`. Windows'
     dialog was shown once for that clean, over the main window, and answered with
     **Clean them** after 5.9 s. No line between 22:02 and 23:22 shows another answer to it. The
     log also shows the cancel path working in the real build: 18:06,
     `items=1 ... answer=Cancel open_ms=4615 Cancelled`.
   - **Why Esc can't confirm.** The dialog is Windows' task dialog
     (`crates/core/src/win/taskdialog.rs`): Cancel is the default button, and Esc, Cancel, Alt+F4
     and the close box all end it with `IDCANCEL` (Microsoft's documentation). Only the
     "Clean them" button's ID (`ID_CONFIRM`) counts as Confirm. A press under a second, no main
     window, or a dialog Windows can't show also stop the clean. While it is open, the dialog
     disables the main window it belongs to, so a key can't reach the page behind it.
   - **The phase 3 story is different.** Phase 3 used the dialog plugin (`rfd`), whose default
     button confirmed and which had no parent window. Phase 4 (security review S1) replaced it with
     the task dialog above. Phase 5 is the first owner check with the new dialog, and the log
     shows it working.
   - **Which dialog took the Esc** can't be told from the log; none of the others clean
     anything. Candidates: the page's Preview dialog (Esc means "Back", nothing is cleaned, and
     the owner previews again), the "Move to which folder?" folder picker (Esc picks nothing),
     or a History question (Esc answers no).
   - **What changed in code.** No root-cause bug was found. The gate in `clean` is now its own
     function, `amber_refusal` (`src-tauri/src/lib.rs`), so a test drives it directly:
     `only_clean_them_lets_an_amber_move_or_recycle_through`. It runs an amber **recycle** and an
     amber **move** through every outcome (Clean them read, Esc, Cancel, close box, button 0, a
     press under a second, dialog unavailable, no window) and checks that the dialog is shown
     once and that only "Clean them", read, goes ahead. The boundary test now pins that `clean`
     goes through this gate before `carry_out`. The log line and the parent window were already
     in place (phase 4, S1): the answer is `Confirm`/`Cancel`, the verdict is `Clean`/`Cancelled`
     (or `TooFast`, `NoWindow`, `Unavailable`), and there are no file names.

   **Owner's check for task 0** (on your PC, with one test file you make for it and nothing
   else). Claude only reads the log and the Recycle Bin afterwards.
   1. In your project folder, on the branch Claude names, run `./check.ps1` (expected:
      `All checks passed.`), then `./build.ps1` (expected: `Built: ...\target\release\bytebroom.exe`).
   2. Make one 600 MB test file in a new `bytebroom-esc-test` folder in Downloads. ByteBroom lists
      files of 500 MB or more as "Large files", an amber category:
      ```powershell
      $t = Join-Path $env:USERPROFILE 'Downloads\bytebroom-esc-test'; New-Item -ItemType Directory -Force $t | Out-Null; $f = [IO.File]::Create((Join-Path $t 'esc-test.bin')); $f.SetLength(600MB); $f.WriteByte(7); $f.Close(); Get-ChildItem $t
      ```
   3. Start `target\release\bytebroom.exe` and press **Scan**. When it is done, untick everything,
      then under "Large files" tick only `esc-test.bin` and leave its action **Recycle Bin**.
   4. Press **Preview…**, tick the confirm that lists the file, and press **Clean now**. Windows'
      dialog "ByteBroom: clean your own files?" opens, with a warning icon, the buttons
      **Clean them** and **Cancel**, and the path of the file in its text.
      Wait 2 seconds, then press **Esc** once.
      Expected: the dialog closes, the status line says "cancelled: nothing was cleaned. Preview
      again to choose.", and `esc-test.bin` is still in `Downloads\bytebroom-esc-test`.
   5. Press **Preview…** again, tick the confirm, and press **Clean now**. In Windows' dialog wait
      2 seconds, then press **Clean them**.
      Expected: the result screen says "Recycle Bin: 1 item done", `esc-test.bin` is gone from the
      folder, and Windows' Recycle Bin lists it.
   6. Tell Claude whether 4 and 5 held (yes/no, and what differed). Claude then reads, read-only:
      - the last two lines of `%LOCALAPPDATA%\ByteBroom\bytebroom.log`. Expected: first
        `amber-confirm items=1 parent=main window answer=Cancel ... Cancelled`, then
        `amber-confirm items=1 parent=main window answer=Confirm ... Clean`;
      - the Recycle Bin, which should list `esc-test.bin`.
   7. Tidy up: in Explorer, delete `esc-test.bin` from the Recycle Bin and delete the
      `bytebroom-esc-test` folder.

   If step 4 cleans anything, stop: that is a safety bug, and Claude fixes it with a test before
   anything else in this phase.
3. `main` is 79 commits ahead of `origin/main`. **Nothing is pushed until the owner asks**, and
   only after the publishing checklist (task 7).

## What already exists

- **`./build.ps1`:** `cargo tauri build --no-bundle` (no installer: `bundle.active` is `false` in
  `src-tauri/tauri.conf.json`), plus `bytebroom-admin.exe`.
- **The elevated helper** must live at `<Program Files>\ByteBroom\bytebroom-admin.exe`, which
  only administrators can change (`crates/core/src/win/admin.rs`, `helper_path`). The window
  refuses to start it from anywhere else. Today the owner installs it with
  `tools/install-helper.ps1` (as administrator); `tools/uninstall-helper.ps1` removes it.
- **App data:** `%LOCALAPPDATA%\ByteBroom` holds `moves.journal`, `recycled.journal` and
  `bytebroom.log`. These are the owner's records, not part of the install.
- **Workflows:**
  - `ci.yml` (Windows: fmt, clippy, tests);
  - `security.yml` (cargo deny, gitleaks on the full history, zizmor);
  - `codeql.yml`;
  - `dependabot.yml`.
  All actions are pinned to SHAs, with harden-runner.
- **Repo:**
  - `origin` is `github.com/SocheatSorng/ByteBroom`; only the foundation commit is pushed;
  - LICENSE is MIT;
  - every commit uses the noreply email.
- **Version:** `0.3.0` in the workspace `Cargo.toml`.
- **The page boundary** (`src-tauri/tests/boundary.rs`) pins the app's dependencies to
  `bytebroom-core`, `serde`, `tauri` and `tauri-plugin-dialog`. Adding the updater plugin changes
  that pin on purpose (spec: "ask first: adding a crate dependency; changing the release and
  updater setup").

## Gaps to close

- No installer, so the helper still needs a hand-run admin script.
- No updater: no signing key, no update check, no `latest.json`.
- No one-command release script, and no docs for installing as a stranger (SmartScreen warning,
  where the files go, how to uninstall).
- The publishing checklist hasn't been run on the full history, and the workflows have never run
  on the real code.

## Design (proposed)

- **Installer:** Tauri's NSIS bundle, per-machine, into `<Program Files>\ByteBroom`. It installs
  `ByteBroom.exe` and `bytebroom-admin.exe` side by side, so the helper lands where the window
  expects it, in a folder only administrators can change. It replaces `install-helper.ps1`.
- **Uninstall** removes the program folder only. `%LOCALAPPDATA%\ByteBroom` (history and log)
  stays, and the README says where it is and how to remove it.
- **Updates:** the Tauri updater plugin, with the owner's minisign key.
  - The public key is in `tauri.conf.json`, and the private key stays outside the repo.
  - The endpoint is fixed: `latest.json` on this repo's GitHub Releases.
  - The plugin refuses any update whose signature doesn't match. Rust checks, the page only shows
    "Update available: install?" and sends no URL or path.
  - A per-machine install means an update asks for UAC, which the owner clicks.
- **Release script:** `./release.ps1` runs the checks, builds the signed installer, and writes
  `latest.json`. The owner types the key's password and uploads the files in the browser (the
  owner doesn't use `gh`).
- **Tests:**
  - the boundary test pins the updater endpoint (https, this repo only), the public key's
    presence, and no private key anywhere in the repo;
  - a test checks the installer config: per-machine, Program Files, and the helper included;
  - the docs-drift test covers the install, update and uninstall steps in the README;
  - an update test against a local, test-build-only endpoint (a test checks the real build lacks it).

## Owner decisions (recommended option first)

**Answered by the owner, 2026-11-25: the recommended option for every decision.**

| # | Decision | Owner's choice |
|---|---|---|
| 1 | Installer | (a) per-machine NSIS into Program Files, helper inside |
| 2 | Updates in V1 | (a) yes, the Tauri updater with the owner's signing key (new crate dependency approved) |
| 3 | Where releases are built and signed | (a) on the owner's PC with `./release.ps1`; no key in GitHub or CI |
| 4 | Where the private key lives | `%LOCALAPPDATA%\ByteBroom-signing\`, password-protected, plus an offline backup |
| 5 | When the app checks | (a) at start, and it asks before installing |
| 6 | The repo | (a) public, after the publishing checklist passes |
| 7 | First version | (a) `1.0.0` |
| 8 | On uninstall | (a) keep `%LOCALAPPDATA%\ByteBroom` |

The options as they were offered:

1. **Installer:**
   - (a) **per-machine NSIS into Program Files, with the helper inside (recommended):** one UAC
     prompt at install, and the helper is admin-owned by the installer;
   - (b) per-user install, with the helper still added by `install-helper.ps1`.
2. **Updates in V1:**
   - (a) **yes, the Tauri updater with your signing key (recommended);**
   - (b) none in V1: strangers download each new version by hand.
3. **Where releases are built and signed:**
   - (a) **on your PC with `./release.ps1` (recommended):** the private key never leaves your PC
     and never goes into GitHub; you upload the files in the browser;
   - (b) a GitHub Actions release workflow on a tag, with the key as a repo secret.
4. **Where the private key lives:** in a folder outside every repo (e.g.
   `%LOCALAPPDATA%\ByteBroom-signing\`), with a password you type at each release, plus a backup
   you keep offline. If the key is lost, installed copies can't update any more; if it leaks, a
   bad update could be signed. Any other place?
5. **When the app checks for updates:**
   - (a) **at start, and it asks before installing (recommended);**
   - (b) only from a "Check for updates" button.
6. **The repo:**
   - (a) **public (recommended):** strangers need public Releases;
   - (b) private for now: Releases only for you.
7. **First version number:**
   - (a) **`1.0.0` (recommended);**
   - (b) `0.6.0`, keeping 1.0 for later.
8. **On uninstall:**
   - (a) **keep `%LOCALAPPDATA%\ByteBroom` (recommended):** your move history stays, so moved files
     can still be put back after a reinstall;
   - (b) remove it too.

## Tasks (riskiest first)

Each task: code → tests → fmt + clippy → full tests → build → commit with a "why" message.

0. **Check the facts** against official docs, with links in this plan:
   - Tauri 2's NSIS bundler: per-machine `installMode`, bundling a second exe (resources, or
     `externalBin` sidecar naming), the install folder and its ACLs;
   - the updater plugin: `createUpdaterArtifacts`, the `pubkey` and `endpoints` config, the signing
     environment variables, how it handles a per-machine install (UAC, `installMode` passive), and
     what it does with a bad signature;
   - the permissions the updater needs in the capability file, if any page call is used.
1. **Installer with the helper** (riskiest: the helper's trust):
   - turn bundling on, with NSIS per-machine and the helper included;
   - a read-only checker, `tools/verify-install.ps1`, confirms the installed folder: owner
     Administrators/SYSTEM, no write for Users, both exes there, and the helper's own self-check
     passes (`elevate_noop`);
   - migration: the owner removes the hand-installed helper with `uninstall-helper.ps1` first;
     document it, and retire `install-helper.ps1` (or keep it for dev builds).
2. **Updater:**
   - the plugin (new dependency, pinned in the boundary test) and the public key;
   - the start-up check and an "Update available" prompt on the page, with an ID-only command;
   - a test-build-only local endpoint, tested both ways: a good signature installs, a tampered
     file is refused.
3. **`./release.ps1`:** checks, a signed installer, `latest.json` with the GitHub download URL,
   and SHA-256 sums printed for the release notes. Docs-drift tested.
4. **Version:** set the decided version everywhere it appears (Cargo, `tauri.conf.json`, README);
   a test keeps them equal.
5. **Docs:**
   - the README's install section for strangers: download, SmartScreen "More info → Run anyway"
     (no paid certificate in V1), what UAC asks, updates, uninstall, and where the history stays;
   - the spec's phase 6 row;
   - `docs/recovery.md`: how to roll back an update (install the previous installer).
6. **Reviews:**
   - a security review (`agent-skills:security-auditor`) of the installer, the helper placement,
     the updater and the release script; every must-fix fixed with a test;
   - a UI pass (`bytebroom-ui-designer`) of the update prompt.
7. **Publishing checklist** (before any push):
   - scan every tracked file and the whole history for personal paths, names, emails and
     machine names; a hit in history means a history rewrite, decided with the owner;
   - check every commit's author is the noreply email;
   - gitleaks on the full history;
   - confirm public or private (decision 6).
8. **Push and make every workflow green** on the owner's ask:
   - read the results through the public GitHub API (`curl`) or the built-in browser, never `gh`;
   - fix root causes, never turn a check off;
   - add a release build to `ci.yml` (unsigned installer only: no key in CI under decision 3a).
9. **Owner check:**
   - uninstall the hand-installed helper;
   - install from a draft GitHub release as a stranger would, then scan and do a small clean;
   - install a second, newer test release through the updater;
   - see a tampered `latest.json` signature refused;
   - uninstall, and check the history in local app data stays.
   Then the merge with `--ff-only` on the owner's yes, the tag, and publishing the release.

## Risks

- **A leaked signing key** would let anyone sign a "ByteBroom update". It stays outside the repo
  and CI, has a password, gitleaks scans every commit, and a test forbids private-key markers in
  tracked files.
- **A lost signing key** means installed copies can never update again. Keep an offline backup.
- **The helper's trust:** it must only ever run from the admin-owned install folder. The installer
  test and `verify-install.ps1` check the ACL, and the security review covers it.
- **Personal details in history** (the ShelfDrop lesson): a hit means a history rewrite before the
  first public push, never after.
- **SmartScreen** warns until a paid certificate (out of scope for V1); the README shows the steps.
- **The updater on a per-machine install** needs UAC at each update; the owner clicks it, never
  Claude.

## Results

(to be filled in)
