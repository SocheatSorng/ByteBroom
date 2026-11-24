# ByteBroom

A Windows disk-space cleaner. With your explicit permission (a Windows administrator prompt), ByteBroom
scans the drive, shows you what it can clean and how much space each item frees, and removes only what
you confirm.

> **Status: planning.** No cleaning code exists yet. What ByteBroom cleans, how deletion works and what it
> never touches are being decided in `docs/intent/`; the phases are in `docs/spec.md`.

## Safety promises

- Nothing is deleted without a preview and your confirmation.
- Tests and harnesses only ever use fake folders in a temp directory, never your real files or drives.
- ByteBroom never touches the rules listed under "Never touched" in `docs/spec.md` (once written).

## Install, run, test, build

ByteBroom is written in Rust (the core) with a Tauri 2 window (from phase 3). Phase 1 builds only the
safety core in `crates/core`; there is no app to run yet.

1. Install Rust once: `winget install Rustlang.Rustup`, then open a new terminal. The exact Rust version
   is pinned in `rust-toolchain.toml`, and rustup installs it on first use.
2. Install the dependency checker once: `cargo install --locked cargo-deny`.
3. In your project folder, run every check with `./check.ps1`, or one at a time:

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

Tests build fake folder trees in a fresh temp folder and never touch your own files, drives or Recycle
Bin. A docs-drift test checks that the commands above are the ones `check.ps1` and CI really run.

## Development checks

- Secret scan before every commit: `pre-commit install` once (needs `pre-commit`, e.g.
  `uv tool install pre-commit`), then hooks run on each commit. Hooks: gitleaks, private-key detection,
  large-file check, JSON/YAML checks, zizmor for GitHub Actions workflows.
- GitHub Actions: `security.yml` (gitleaks over the full history, zizmor), Dependabot weekly.

## License

MIT, see `LICENSE`.
