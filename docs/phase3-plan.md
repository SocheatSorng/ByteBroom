# Phase 3 plan: the window (unelevated)

Status: decisions made; ready to build. Spec: `docs/spec.md`. Branch: `phase-3-window`.
Version after this phase: 0.3.0.

## What this phase proves

That the owner can scan, see what was found, choose an action for each item, preview exactly what
will happen, confirm, and get an honest report, all in a Tauri 2 window. And that the window can
only ever act on what the scan found and the owner confirmed.

The window is a web page (WebView2), so the riskiest part is the boundary between the page and the
Rust code that deletes. The page never sends a path. It refers to findings by IDs the scan handed out,
and the Rust side rebuilds every plan from its own copy of the scan, so even a compromised page can
only choose among items the scan already offered. It still runs unelevated; administrator rights and
the red tier's actions are phase 4.

## Carried over from phase 2

- **Duplicates in the background** (phase 2 speed result): the window shows everything else in about
  35 s and duplicates arrive when hashing finishes.
- **F1, a check right before acting:** a finding records the file's identity (volume serial, file ID,
  length, last-write time). Right before acting, the engine checks it is still the same file, hashes
  both copies of a duplicate again, and re-applies the 24-hour temp rule. Anything that changed is
  skipped and reported.
- **F5:** items whose rule folder can't be a clean root (directly in the profile or at a drive root,
  like `D:\Video.vkl`) are shown as "can't be cleaned here", not offered.
- **Cloud files:** shown as "cloud file (OneDrive)", not as links, and not offered (the engine never
  acts on placeholders).
- **The spec's warnings:** recycling on the same drive frees no space until the Recycle Bin is emptied,
  and "space freed" counts only bytes that really come back.

## Design

- **Workspace:**
  - `src-tauri/`: the app crate. Tauri commands only; no file logic beyond calling `bytebroom-core`.
  - `ui/`: plain HTML, CSS and JavaScript, no framework and no npm packages, so nothing is fetched at
    build time or run time.
- **The command surface (the boundary):**
  - `start_scan`, `cancel_scan`;
  - `scan_state`: progress, findings with their IDs, red-tier sizes;
  - `preview(choices)`: each choice is a finding ID and an action;
  - `clean(preview_id)`: acts on exactly the confirmed preview;
  - `pick_move_destination`: a native folder dialog run by Rust;
  - `open_recycle_bin`.

  No command takes a path or a free-form string that becomes one.
- **Lockdown:**
  - no file-system, shell, HTTP or process plugins;
  - a strict content security policy (`default-src 'self'`, no inline scripts, no remote content);
  - one window, no navigation away from the app;
  - Tauri capabilities listing only the commands above.
- **Scan session:** runs on a background thread with progress events and cancel. The results stay in
  Rust; the page gets display data (label, tier, size, date, path text to show) plus an ID.
- **Preview and confirm:**
  - **Green:** one confirm for the batch.
  - **Amber:** a second confirm listing every amber item.
  - **Red:** sizes only, with "freed in a later version through Windows' own tools".
  - **Space shown:** the preview shows the space that will really come back per action: permanent and
    move-to-another-drive free it, and the Recycle Bin on the same drive frees nothing until emptied.
- **Acting:** the phase 1 engine (Recycle Bin, permanent delete, move with journal), run through
  `clean::prepare` and the F1 check, with every item re-checked at the moment of action as always. The
  result screen lists what was freed, what was skipped and why.

## Owner decisions

Decided by the owner on 2026-11-25:

1. **Default action per tier:**
   - **Green:** permanent delete. Windows or the app rebuilds these, and recycling them on the same
     drive would free nothing until the Recycle Bin is emptied.
   - **Amber:** Recycle Bin.

   The owner can change the action per item either way. This is the spec's exception to "the
   default is the Recycle Bin" (recorded in `docs/spec.md`).
2. **Virtual machine disks** (`.vmdk`, `.vdi`, `.vhd`, `.vhdx`, `.qcow2`, `.ova`): kept in large files
   (amber, never ticked), with the label "virtual machine disk: deleting it removes the VM" and a
   suggestion to move it instead.
3. **Growing the "never listed" list** (security review F3): add all of these:
   - Firefox: `logins.json`, `key4.db`, `cert9.db`, `cookies.sqlite`, `places.sqlite`;
   - SSH keys outside `.ssh`: `*.ppk`, `id_rsa`, `id_ed25519`;
   - other vaults: `*.kdb`, `*.psafe3`, `*.gpg`.
4. **New dependencies, approved:**
   - the `tauri` crate and `tauri-build`;
   - the dialog plugin (Rust side only);
   - the `tauri-cli` tool, installed with `cargo install --locked tauri-cli`.

   No npm packages and no other plugins.

Defaults this plan uses unless the owner says otherwise:

- **Moves:** only to a folder on another fixed drive. Moving within the same drive frees nothing, and
  the engine already refuses unsafe destinations.
- **Not remembered between runs:** the window remembers no choices. Every scan starts from the
  rules' defaults: green ticked, amber not.

## Tasks

Each task: code → tests → fmt + clippy → full tests → commit with a "why" message.

- [x] **0. Never-listed additions (decision 3)**
  - Acceptance: the new names and extensions are in `rules.rs` and in the README list (docs-drift);
    the walker never lists them and the engine never acts on them.
  - Tests: the existing never-listed tests (rules, walker, engine) cover every new entry.
- [x] **1. App skeleton and the boundary**
  - Acceptance:
    - `cargo tauri dev` opens an empty ByteBroom window;
    - `./check.ps1` still covers the whole workspace, and `./build.ps1` builds the app.
  - Tests:
    - every registered command is in an allow-list, and none takes a path or a string that could
      become one;
    - the capability file grants nothing beyond those commands;
    - the CSP forbids remote and inline code;
    - the UI folder contains no `http(s)://` resource.
- [x] **2. Scan session**
  - Acceptance:
    - background scan with progress and cancel;
    - duplicates arrive as a second step;
    - each finding gets an opaque ID and its file identity (F1);
    - the walker exposes file IDs.
  - Tests: IDs from one scan are never accepted after a new scan; cancel stops both steps.
- [x] **3. Preview**
  - Acceptance: choices (ID + action) become a preview with:
    - the targets;
    - the bytes that will really come back per action;
    - the confirmations each tier needs (green batch, amber list);
    - the items that can't be cleaned (F5, cloud files, last copy).

    Unknown or stale IDs are refused, and red can't be chosen.
  - Tests: pure, table-driven, every action × tier × drive case.
- [x] **4. Clean, with the check right before acting**
  - Acceptance:
    - `clean(preview_id)` acts only on that preview, once;
    - the F1 identity check, the duplicate re-hash and the 24-hour rule run right before acting;
    - Recycle Bin, permanent delete and move work, and the report is honest.
  - Verify: end-to-end on a fake profile, with:
    - permanent delete, checked by `verify-tree.ps1`;
    - move, also checked by `verify-tree.ps1`;
    - a swapped file, refused;
    - a duplicate edited after the scan, refused.

    The real Recycle Bin stays CI-only, as in phase 1.
- [x] **5. The window**
  - Acceptance:
    - lists grouped by tier and category, with ticks and an action per item;
    - totals, a filter, and the largest items;
    - labels for cloud files, "can't be cleaned here" and VM disks (decision 2);
    - the red tier as sizes only;
    - progress, cancel, preview, confirmations and the result screen;
    - keyboard use and screen-reader labels.
- [ ] **6. UI designer agent and harness**
  - Acceptance:
    - `.claude/agents/bytebroom-ui-designer.md` and `tools/ui-harness/` render the real window with
      fake data;
    - the agent screenshots it in light and dark mode, small and large sizes, fixes layout, spacing
      and colour, never changes behaviour and never commits;
    - a test proves the app can't include the fake data.
  - Changed while building (safer than the Cargo feature first planned): the harness is a small
    Node server that serves the real `ui/` files with a fake `window.__TAURI__`
    (`tools/ui-harness/mock-tauri.js`). The fake data never exists in Rust, so no build can switch
    it on; the browser pane can emulate dark mode and window sizes. The boundary test checks that
    the app has no Cargo features and that `ui/` never names the harness.
- [x] **7. Docs**
  - README: how to run and build the app, what each confirmation means, and the same-drive Recycle Bin
    warning. The docs-drift test covers the new commands.
- [x] **8. Security review**
  - `agent-skills:security-auditor` reviews the boundary (commands, capabilities, CSP), the preview
    and clean path, and the move destination. Every must-fix is fixed with a test.
  - Result (2026-11-25): no must-fix. Fixed with tests:
    - should-fix 1, confirmations only in the page: `clean` asks again in Windows' own dialog
      before acting on any amber item;
    - should-fix 2, two cleans at once could each keep "the other" copy of a duplicate: while a
      clean runs nothing else starts, and a cleaned scan is used up;
    - note 4: the 24-hour rule fails safe for an item nested below its root;
    - note 5: more choices than findings are refused;
    - note 6: pop-up windows are denied;
    - `insertAdjacentHTML` and `createContextualFragment` are banned in the page too.
  - **Before phase 4 (elevation)**, from the same review:
    - note 3: between the check right before acting and the engine re-opening the item, a file
      could be swapped. Pass each item's identity into the engine and compare it on the handle
      that deletes or copies (Recycle goes through the shell by path: document what is left).
    - note 7: the move journal's folder is opened following links; open it no-follow, or keep it
      in an admin-owned folder.
- [x] **9. Accessibility pass**
  - `agent-skills:accessibility-auditor` checks the window (keyboard, contrast, labels) through the
    harness; must-fixes are fixed.
- [ ] **10. Owner check**
  - The first real clean: the owner cleans a few green items (permanent delete, and the Recycle Bin)
    and moves one large file to another drive, with exact steps. Claude verifies read-only that only
    those items changed and that the moved file's journal and hash are right.
  - Merge with `--ff-only` on the owner's yes.

## Risks

- **A page that asks for more than it was shown.** Mitigations:
  - IDs only, no paths;
  - Rust rebuilds every plan from its own scan;
  - the engine re-checks everything at the moment of action;
  - tests pin the command list, the capabilities and the CSP.
- **Acting on a stale scan.** Mitigations:
  - IDs die with their scan;
  - F1 identity checks;
  - the 24-hour rule re-applied right before acting.
- **Recycling that frees nothing.** The preview shows 0 bytes for same-drive recycling and says why;
  the default action is decision 1.
- **Tauri on this PC.** WebView2 158 and the Visual Studio build tools are already installed; only the
  Tauri CLI is missing (decision 4).
- **Long duplicate hashing.** It runs in the background and can be cancelled; the rest of the list is
  usable while it runs.

## Results

(filled in at the end of the phase)
