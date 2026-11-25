# Phase 2 plan: scanner and tier rules

Status: decisions made; ready to build. Spec: `docs/spec.md`. Branch: `phase-2-scanner`.
Version after this phase: 0.2.0.

## What this phase proves

That ByteBroom can **find** what is worth cleaning, sort it into the three tiers with honest sizes,
and do it fast enough for a whole drive, without following links and without ever listing keys,
passwords or browser logins. Phase 2 still has no window: it adds the scanner to the core crate,
plus a small **read-only** command-line tool so the owner can see what a scan of their real PC finds.
The scanner never deletes anything; it hands findings to the phase 1 engine, which checks every item
again at the moment of action.

## Categories

Every rule is data (a table in `crates/core/src/rules.rs`), so the list below is tested against
the code by the docs-drift test.

**Green (pre-ticked; Windows or the app rebuilds them):**

| Rule | Where (under the user's own folders) |
|---|---|
| User temp files | `%LOCALAPPDATA%\Temp` (contents, not the folder) |
| Crash dumps | `%LOCALAPPDATA%\CrashDumps` |
| Windows error reports | `%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive`, `ReportQueue` |
| Thumbnail and icon cache | `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db`, `iconcache_*.db` |
| Internet cache | `%LOCALAPPDATA%\Microsoft\Windows\INetCache` |
| DirectX shader cache | `%LOCALAPPDATA%\D3DSCache` |
| Browser caches (Brave, Chrome, Edge, Firefox) | each profile's `Cache`, `Code Cache`, `GPUCache` (Firefox: `cache2`). Never cookies, history, logins or settings. |

**Amber (never pre-ticked; the owner picks):**

| Rule | What |
|---|---|
| Large files | files at or above the size threshold (decision 1), anywhere the scan can read |
| Duplicates | files with identical content (same size, then SHA-256), all but one copy offered |
| Old installers | `.exe`, `.msi`, `.msix`, `.zip`, `.iso` in Downloads older than N days (decision 2) |
| Developer caches | npm, pip, uv, Cargo registry, NuGet, Gradle caches (tier: decision 3) |
| Build folders in code projects | `node_modules`, `target`, `bin`/`obj`, `dist` inside a folder with `.git` |

**Red (shown with sizes only; freed in phase 4 through Windows' own tools):** the Recycle Bin's
contents, `hiberfil.sys`, `pagefile.sys`, `Windows.old`, the Windows Update store, Delivery
Optimization files and restore points. Each one whose size can't be read without administrator
rights says "needs admin".

**Never listed at all:**

- `.ssh` and `.gnupg`;
- password vaults (`*.kdbx`, `*.1pif`, `*.agilekeychain`) and wallets (`wallet.dat`);
- the browser files `Cookies`, `Login Data`, `Web Data`, `History`, `Bookmarks` and `Local State`;
- certificates and keys (`*.pfx`, `*.p12`, `*.pem`, `*.key`);
- every link and junction, and the hard floor from phase 1.

A test sweeps a fake profile full of these files and proves none ever appears in any finding.

**Deferred (not in V1 phase 2):** leftovers of removed apps (needs reliable installed-app data and
is the riskiest guess; revisit after phase 3).

## Owner decisions

Decided by the owner on 2026-11-25:

1. **Large-file threshold:** 500 MB.
2. **Old installers:** offered once they are 30 days old.
3. **Developer caches:** amber, never pre-ticked (cleaning them slows the next builds).
4. **Fresh temp files:** temp files changed in the last 24 hours are not offered.

## Tasks

Each task: code → tests → fmt + clippy → full tests → commit with a "why" message.

- [x] **1. Locations**
  - Acceptance: a `Locations` struct holds the folders the rules use (LocalAppData, the profile,
    Downloads, and the other drives). The real one is built from `SHGetKnownFolderPath`; tests
    build it from a fake profile in a temp folder. Values that disagree with the environment are
    not trusted (the same rule as phase 1's layout).
  - Files: `crates/core/src/win/locations.rs`, `crates/core/src/locations.rs`.
- [x] **2. Rule catalogue (pure)**
  - Acceptance:
    - every rule names a tier, a plain-English label and where it looks;
    - no rule can point into the hard floor or at a "never listed" name (tests);
    - the README's category list matches the table (docs-drift).
  - Files: `crates/core/src/rules.rs`, tests.
- [x] **3. Walker**
  - Acceptance:
    - an iterative walk that never enters links or junctions and counts the folders it can't read
      ("access denied") instead of failing;
    - stops at a depth limit;
    - can be cancelled (for the window in phase 3);
    - sizes are file lengths, and a file with several hard links is counted once.
  - Verify: tests on fake trees; `verify-tree.ps1` proves the walk changed nothing (it only reads).
- [x] **4. Green and amber findings**
  - Acceptance: rules turn walk results into findings with:
    - the rule;
    - the tier;
    - the path;
    - bytes and file count;
    - the newest change date;
    - pre-ticked or not.

    The rules for fresh temp files (decision 4) and old installers (decision 2) are applied.
  - Verify: a fake profile with every category, plus decoys that must not match.
- [x] **5. Large files and duplicates**
  - Acceptance:
    - large files use the threshold from decision 1;
    - duplicates are grouped by size, then by a hash of the first 64 KB, then by full SHA-256
      (Windows CNG, as in phase 1);
    - in each group the oldest copy is kept, and the others are offered unticked;
    - "never listed" files are excluded.
  - Built with these defaults (not owner decisions; say if you want them changed):
    - duplicates under 1 MiB are not offered (`DUPLICATE_MIN_BYTES`);
    - duplicates are not searched in AppData, `.git` or build folders (`node_modules`, `target`,
      `bin`, `obj`, `dist`), where identical files are normal and other rules cover them;
    - cloud placeholders are never hashed (a read would download them), so they are never
      duplicates; they can still be large files;
    - "oldest" means the oldest change date; on a tie the shortest path is kept.
  - Verify: tests with planted duplicates, near-duplicates (same size, different content) and
    hard-linked copies (not duplicates: one file, two names).
- [x] **6. Red-tier sizes (read-only)**
  - Acceptance: the Recycle Bin size (`SHQueryRecycleBinW`), the sizes of `hiberfil.sys` and
    `pagefile.sys` (read from the folder listing, without opening them), and the size of
    `Windows.old` if it is readable; everything else says "needs admin". Nothing in this task can
    act; it only reports.
- [x] **7. From findings to a safe clean**
  - Acceptance: a confirmed selection becomes a phase 1 `Policy` whose roots are the rules' own
    folders.
  - Closes the phase 1 review follow-up: `Policy::new` also refuses roots in sensitive places, such
    as `ProgramData\Microsoft` and every Startup folder, now that the scanner, not the owner,
    proposes roots.
  - Verify: the end-to-end test is fake profile → scan → select → delete → `verify-tree.ps1`, with
    only the selected items gone.
  - Done as: the protected areas now also cover, under every profile, the Startup folder and
    Windows' key and credential stores (`Protect`, `Credentials`, `Crypto`, `SystemCertificates`,
    `Vault`, plus `.ssh` and `.gnupg`), and all of `ProgramData\Microsoft`. They are refused as
    roots, as targets and as places to restore a moved file. A refused root leaves out only its
    own items.
  - Bug found by the end-to-end test: the large-file, duplicate and build-folder searches skipped
    the whole profile on a real PC, because the profile root is protected as a delete target. The
    task 4 and 5 tests missed it because their fake profile was not listed as a Windows profile;
    they now list it, and fail with the old code.
  - Follow-up for phase 3: a clean happens some time after its scan, so the window should scan
    again (or at least re-check the 24-hour temp rule) right before acting.
- [ ] **8. Speed**
  - Acceptance: a generated fake tree of 200,000 files in 20,000 folders is scanned in under 30
    seconds in a release build on the owner's PC; the result goes into this plan. The test lives
    behind `#[ignore]`, so normal test runs stay quick.
- [ ] **9. Read-only scan tool**
  - Acceptance: `cargo run --release -p bytebroom-scan` prints the totals for each category and
    tier, the 20 largest findings and how many folders it could not read.
  - It has no delete, move or recycle option at all. A test checks that the binary links no engine
    functions that act.
  - Its output stays in the owner's terminal and is never written to a file.
- [ ] **10. Security review**
  - `agent-skills:security-auditor` reviews the scanner read-only, with a focus on:
    - a rule that could match something it shouldn't;
    - the "never listed" exclusions;
    - the hand-off to the engine.

  Every must-fix is fixed with a test.
- [ ] **11. Owner check**
  - The owner runs the read-only scan tool on their PC and compares a few totals with what Windows
    shows (for example the Recycle Bin, the Downloads folder, the temp folder).
  - Merge with `--ff-only` on the owner's yes.

## Risks

- **A rule that matches too much.** Mitigations:
  - rules are data and every one is tested against decoys;
  - the engine still refuses anything outside the rule's folder;
  - amber is never pre-ticked.
- **Browser caches while the browser runs.** Files in use are skipped and reported by the engine.
  The UI (phase 3) can suggest closing the browser first.
- **Speed on a 220 GB drive.** `std::fs::read_dir` on Windows already returns sizes and attributes
  from the folder listing (no extra call per file). If the 200,000-file target is missed, the
  fallback is `FindFirstFileExW` with the large-fetch flag, not reading the MFT (which needs
  administrator rights).
- **Sizes vs space on disk.** Compressed, sparse and cloud-only (OneDrive) files take less space
  than their length. Phase 2 reports length and marks cloud placeholders. Exact "space on disk"
  numbers wait for phase 3, if the owner wants them.

## Results

(filled in at the end of the phase)
