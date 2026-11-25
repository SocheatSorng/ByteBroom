# ByteBroom: project instructions

A Windows disk-space cleaner: with the owner's explicit permission (UAC elevation) it scans the drive,
previews what can be cleaned, and removes only what the owner confirms. Intent: `docs/intent/` (being
written). Spec and phases: `docs/spec.md`. One plan per phase: `docs/phaseN-plan.md`.

This is **high-risk work** (file deletion, administrator rights). The owner's safety procedure applies
in full to every change.

## Run, test, lint, build

Rust workspace: `crates/core` (safety core, delete engine, scanner, preview, act), `crates/scan`
(read-only scan tool) and `src-tauri` (the window's Tauri commands; its page is `ui/`). Keep the
README's commands in step (a docs-drift test checks them).

- All checks: `./check.ps1` (format check, clippy with `-D warnings`, `cargo test --workspace`,
  `cargo deny check`).
- Read-only scan tool: `cargo run --release -p bytebroom-scan` (only the owner runs it on the real PC).
- The window: `cargo tauri dev`; build with `./build.ps1` (makes `target\release\bytebroom.exe`).
  Both scan and clean the real PC, so only the owner runs them. Claude checks the window's look
  through the fake-data harness instead: `node tools/ui-harness/serve.mjs` (or `preview_start`
  `ui-harness`), and the `bytebroom-ui-designer` agent.
- The page↔Rust boundary is pinned by `src-tauri/tests/boundary.rs`; a new command, parameter type,
  permission or dependency means changing that test on purpose and a security review.
- Speed test (ignored by default, writes 200,000 files to temp):
  `cargo test --release -p bytebroom-core --test speed -- --ignored --nocapture`.

## Safety rules (write these as tests early)

- **Tests and harnesses never touch the owner's real files, folders, drives, Recycle Bin or registry.**
  They build fake trees in a fresh temp folder and delete only inside it. A guard refuses any delete
  target outside the allowed roots, and a test proves the guard.
- **No delete without preview and confirmation.** The default is the Recycle Bin, unless the owner's
  decisions in `docs/spec.md` say otherwise for a specific category.
- **Never follow links:** refuse symlinks, junctions and other reparse points as delete targets and
  never descend into them while scanning.
- **Never-touch list** (to be finalised in the spec): Windows system files, Program Files, user documents,
  anything outside the chosen categories. A test sweeps it.
- **Elevation:** only the owner clicks UAC prompts. Elevate only an admin-owned binary. Test-only hooks
  exist only in a test build, and a test checks the real build lacks them.
- **Scan results and logs** list the owner's file names: never commit them, never send them anywhere.
- Security review (`agent-skills:security-auditor`) for anything that deletes, elevates or touches the
  registry; system-level changes only after a harness, a review, a restore point and a written recovery
  recipe in `docs/`, and the owner turns them on.

## Never

- Never run ByteBroom (or any delete code) against the owner's real drive yourself. The owner does
  real-world tests with exact steps from Claude; Claude verifies with read-only checks.
- Never type or ask for the owner's passwords, and never approve a UAC prompt.
- Never write absolute personal paths or other personal details into tracked files; say "in your project
  folder".
- Never push to GitHub unless the owner asks; before the first push follow the publishing checklist
  (personal-details scan, public/private question, noreply email). The owner does not use `gh`.

## Workflow

Interview → spec with phases (riskiest first) → `docs/phaseN-plan.md` with the owner's decisions →
branch per phase (`phase-N-...`), small tested commits whose messages say why → reviews → owner's real
test → merge to `main` with `--ff-only` only on the owner's yes, then re-run lint, build and tests on main.
After every code change: run lint, build and tests without being asked and report the result.

Git identity for this repo: `SocheatSorng <55123731+SocheatSorng@users.noreply.github.com>`.
On Windows, write multi-line commit messages with Git Bash `git commit -F - <<'EOF'`, never run the bare
`python` (Windows Store stub), and use `node` or `uv run` for scripting.
