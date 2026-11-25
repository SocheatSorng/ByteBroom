# Phase 6 plan: release

Status: **draft, 2026-11-25.** The owner answers the decisions below before any code is written.
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
2. **Phase 3's open item:** Windows' own amber dialog. The phase 5 owner check went through it
   (step 3, "Clean them"); confirm with the owner that it was seen, then close the item in the spec.
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
