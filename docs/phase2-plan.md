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
- [x] **8. Speed**
  - Acceptance: a generated fake tree of 200,000 files in 20,000 folders is scanned in under 30
    seconds in a release build on the owner's PC; the result goes into this plan. The test lives
    behind `#[ignore]`, so normal test runs stay quick.
  - Run with `cargo test --release -p bytebroom-core --test speed -- --ignored --nocapture`.
  - Result (2026-11-25, owner's PC, release build, 200,000 files in 20,204 folders):
    - **full scan, every rule: 18.9 s** (target met). It walks the profile twice (the large-file
      and duplicate search, then the build-folder search), 400,000 files in all;
    - the walker alone, once over the profile: 12.4 s;
    - generating the tree took 389 s and removing it 44 s (not part of the measurement).
  - Caveat: the files had just been written, so Windows' cache was warm. A first scan after a
    restart will be slower; the owner's check (task 11) gives the real-drive number.
  - Not needed now; if a real drive is too slow, merge the scan's two passes over the profile (the
    large-file and duplicate search, then the build-folder search) into one, before anything
    lower-level.
  - **Owner's real scan (task 11): 780 s** for the profile plus D: and E: (VM disks and ISOs, 14.5 GB
    of duplicate copies). Changes made:
    - one walk for large files, duplicates and build folders, instead of two;
    - duplicate hashing in parallel, one thread per drive, with 1 MiB reads;
    - the tool prints the time of each step.
  - Re-run of the speed test after the change: the full scan walked 200,000 files instead of
    400,000. Its time (19.8 s) can't be compared with the first run, because the PC was much slower
    that hour: generating the tree took 617 s against 389 s, and the walk alone 25.3 s against
    12.4 s. The fake tree has no duplicates, so the parallel hashing shows only on a real drive.
    The owner's re-run gives the real number.
- [x] **9. Read-only scan tool**
  - Acceptance: `cargo run --release -p bytebroom-scan` prints the totals for each category and
    tier, the 20 largest findings and how many folders it could not read.
  - It has no delete, move or recycle option at all. A test checks that the binary links no engine
    functions that act.
  - Its output stays in the owner's terminal and is never written to a file.
- [x] **10. Security review**
  - `agent-skills:security-auditor` reviews the scanner read-only, with a focus on:
    - a rule that could match something it shouldn't;
    - the "never listed" exclusions;
    - the hand-off to the engine.

  Every must-fix is fixed with a test.
  - Done: 1 must-fix and 7 should-fix items, each checked against the code, fixed with a test,
    and each test shown to fail with its fix switched off. See "Security review" below.
- [ ] **11. Owner check**
  - The owner runs the read-only scan tool on their PC and compares a few totals with what Windows
    shows (for example the Recycle Bin, the Downloads folder, the temp folder).
  - Merge with `--ff-only` on the owner's yes.
  - Exact steps: `docs/phase2-owner-check.md`.

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

## Security review

Reviewed read-only by `agent-skills:security-auditor` on 2026-11-25.

**Must-fix (fixed):**

- **M1. A vault, key or browser login inside an offered folder would have been deleted.** The
  walker left "never listed" items out of a finding's size, but the engine emptied the whole folder.
  `Policy::check_target` and `check_container` now refuse any path with a never-listed part
  (`Refusal::NeverListed`); every delete, recycle and move passes there. Test: a pre-ticked temp
  folder holding a `.kdbx`, `Login Data`, a `.ssh` key and a `.pem` keeps those four.

**Should-fix (fixed):**

- **S1.** A duplicate and its kept copy could both be chosen (the kept copy can also be an old
  installer or large file). `plan_clean` refuses that selection (`SelectError::LastCopy`).
- **S2.** `bin` and `dist` beside a `.git` are often tracked source. Each build-folder name now needs
  its project file beside it (`package.json`, `Cargo.toml`/`pom.xml`, a .NET project file).
- **S3.** Another Windows on another drive (`D:\Windows`, `D:\Program Files`, `D:\ProgramData`) is now
  on the hard floor.
- **S4.** Temp freshness used only last-write dates. It now uses creation and change dates too, over
  files and folders, and a temp item with any part not seen is never offered.
- **S5.** The large-file search entered AppData (WSL and Docker disk images). It now skips every
  AppData folder, and never offers a cloud placeholder.
- **S6.** Downloads could point at another user's files. It is used only inside the owner's profile or
  on another drive outside every profile.
- **S7.** The "acts on nothing" test now also reads every core module the scan runs for file writes
  and acting calls, and bans five more Windows calls.

**Follow-ups (later phases):**

- **F1 (phase 3).** A finding carries no file identity. Record volume serial, file id, length and date
  at scan time and re-check them right before acting; re-hash duplicates before removing one; re-run
  the 24-hour rule.
- **F2.** Protected key and credential folders assume `AppData\Roaming` under the profile; also derive
  them from `FOLDERID_RoamingAppData` for redirected AppData.
- **F3.** Grow the "never listed" list: Firefox `logins.json`, `key4.db`, `cert9.db`,
  `cookies.sqlite`, `places.sqlite`; `*.ppk`, `id_rsa`, `id_ed25519`; `*.kdb`, `*.psafe3`, `*.gpg`;
  other wallets. Needs the owner's yes (it changes what is never shown).
- **F4 (phase 4).** Elevated as a different admin account, the profile, environment and Recycle Bin
  are that account's. Detect it or warn.
- **F5 (phase 3).** Large files directly in the profile or at a drive root get a root `Policy::new`
  refuses; show them as "can't be cleaned here" or hide them.
- **F6.** Hashing may update last-access times where NTFS keeps them (harmless). The walk's name-bound
  sum has no overflow check; fine on 64-bit.

Checked and found sound by the reviewer: the walk's buffer parsing; name tricks (alternate data
streams, DOS wildcards, trailing dots, device names, 8.3 names); the red-tier listing and Recycle Bin
query; hashing never downloading cloud files; root checks against swapped junctions; search areas
never yielding a sensitive root; protected-area matching; links in Temp; wildcard expansion; the
name matcher; privacy (nothing writes or sends names).

## Results

- **Built:**
  - trusted locations;
  - the rule catalogue as data, with the owner's decisions;
  - a no-follow, handle-based walker;
  - green and amber findings, large files and duplicates;
  - read-only red-tier sizes;
  - the selection-to-engine hand-off with new protected areas;
  - totals counting each file once;
  - the read-only scan tool, proven to contain no acting code.

  Version 0.2.0.
- **Speed:** 200,000 files in 20,204 folders scanned in 18.9 s (release, warm cache).
- **Bugs found by tests:**
  - the profile-wide searches skipped the whole profile on a real PC (the profile root is on the
    floor as a delete target);
  - a test's two "same-date" files differed by microseconds;
  - a decoy check missed a kept copy that came from AppData;
  - a Downloads value in a different letter case was refused before being respelled.

  Each has a regression test.
- **Owner check:** pending (`docs/phase2-owner-check.md`).
