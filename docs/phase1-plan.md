# Phase 1 plan: safe delete engine

Status: draft, waiting for the owner's decisions. Spec: `docs/spec.md`. Branch: `phase-1-delete-engine`.
Version after this phase: 0.1.0.

## What this phase proves

The riskiest bet: a Rust engine that can delete or move files for real, yet **cannot** act outside the
folder it was given, never follows a link, and never turns "recycle" into a silent permanent delete. This
phase has no UI and no scanner. Tests call the engine directly, on fake trees in temp folders, and a
separate PowerShell checker confirms that nothing else changed.

## Before building (the owner)

1. Install Rust once, in your own terminal:

   ```powershell
   winget install Rustlang.Rustup
   ```

   Then open a new terminal and accept the default (MSVC) toolchain if rustup asks. I check it with
   `rustc -V` and pin that version in `rust-toolchain.toml`.
2. Optional, for the commit hooks: `uv tool install pre-commit`, then `pre-commit install` in your project
   folder. `uv` isn't on PATH on this PC yet, so this can wait.

## Tasks

Each task: code → tests → fmt + clippy → full tests → commit with a "why" message.

- [ ] **1. Workspace and checks**
  - Acceptance: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` and `cargo deny check` pass
    on an empty `bytebroom-core`. Also in place:
    - `check.ps1` runs all four;
    - README commands and a docs-drift test;
    - pre-commit local hooks (fmt, clippy, tests, deny);
    - `ci.yml` and `codeql.yml` (Rust) on `windows-latest`, plus a cargo-deny job in `security.yml`;
    - Dependabot for cargo.
  - Files: `Cargo.toml`, `rust-toolchain.toml`, `deny.toml`, `crates/core/*`, `check.ps1`, `.github/*`,
    `.pre-commit-config.yaml`, README.
- [ ] **2. Path policy (pure)**
  - Acceptance: `check_target` refuses:
    - reparse points;
    - paths outside the allowed roots, including the root itself;
    - every deny-list area;
    - a drive root or profile root given as an allowed root.

    Normalisation covers `\\?\`, UNC, device paths, 8.3 names (resolved in step 4), trailing dots and
    spaces, alternate data streams and case.
  - Verify: unit tests, plus `proptest` escape attempts that must all be refused.
  - Files: `crates/core/src/policy.rs`, `paths.rs`.
- [ ] **3. Fake-tree fixture and independent checker**
  - Acceptance: a test helper builds, in a fresh temp folder:
    - an allowed root;
    - a sentinel folder outside the root;
    - a junction inside the root that points at the sentinel;
    - a hard-linked file;
    - a file held open.

    `tools/verify-tree.ps1` snapshots a tree (path, size, SHA-256) and diffs two snapshots. A test proves
    that the checker notices a single changed byte.
  - Files: `crates/core/tests/common/*`, `tools/verify-tree.ps1`.
- [ ] **4. Windows adapter: resolve without following**
  - Acceptance: opening with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS` gives the real
    final path, the attributes and the link count. A path through a junction that leads outside the root
    is refused.
  - Verify: integration tests on the fixture.
  - Files: `crates/core/src/win/*`.
- [ ] **5. Permanent delete through the checked handle**
  - Acceptance:
    - files are deleted with `FileDispositionInfoEx` (POSIX semantics) on the handle that passed the
      check, and folders bottom-up;
    - junctions are skipped, not entered;
    - files in use are skipped and reported;
    - "space freed" counts only bytes that really come back.
  - Verify: integration tests, the sentinel unchanged according to `verify-tree.ps1`.
- [ ] **6. Recycle Bin**
  - Acceptance:
    - the engine checks that the drive has a Recycle Bin and refuses to recycle when it doesn't;
    - it re-checks the target just before recycling through `IFileOperation` with `FOFX_RECYCLEONDELETE`
      and no UI, and confirms afterwards that the file is gone from its place;
    - recycling on the same drive is reported as freeing 0 bytes.
  - Verify: the decision logic is unit-tested with a fake bin. Tests that use the real Recycle Bin are
    gated (see decision 1).
- [ ] **7. Move with verify and journal**
  - Acceptance:
    - each file is copied, then checked (decision 2), then written to a journal line in a JSONL file
      before the source is deleted;
    - an interrupted move leaves the source in place;
    - a minimal `undo_move` puts a file back from its journal entry.
  - Verify: integration tests, including a simulated failure in the middle of a move; the journal lives
    in a temp folder in tests.
- [ ] **8. Safety sweep and security review**
  - Acceptance: every action × every refusal case is tested in one table-driven test. The
    `security-auditor` reviews the engine read-only, and every must-fix item is fixed with its own test.
    Follow-ups go into this file.
- [ ] **9. Owner check**
  - You run `./check.ps1` and the opt-in real-Recycle-Bin test with the exact steps I give you, then
    confirm that the test file shows up in your Recycle Bin and can be restored.
  - Merge with `--ff-only` on your yes, then re-run the checks on main.

## Risks

- **Time-of-check gap when recycling:** `IFileOperation` takes a path, not a handle. Mitigation: check,
  recycle, then confirm the result; recycle only inside allowed roots. This goes to the security review.
- **Creating junctions in tests:** creating a junction needs no administrator rights, but a symlink does
  (or Developer Mode). Tests use junctions, and symlink cases run on CI, whose runner is an administrator.
- **CI runners run as administrator,** so tests that expect "refused without admin" are skipped there.

## Owner decisions

1. Real Recycle Bin tests: ?
2. How moves are verified: ?
3. A folder with a file that can't be deleted: ?
4. Dependency and code security checks: ?

## Results

(filled in at the end of the phase)
