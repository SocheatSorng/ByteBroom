# ByteBroom

A Windows disk-space cleaner. With your explicit permission (a Windows administrator prompt), ByteBroom
scans the drive, shows you what it can clean and how much space each item frees, and removes only what
you confirm.

> **Status: phase 2 (scanner).** The safety core and delete engine (phase 1) are done; the scanner is
> being built. There is no app to run yet. The phases are in `docs/spec.md`.

## Safety promises

- Nothing is deleted without a preview and your confirmation.
- Tests and harnesses only ever use fake folders in a temp directory, never your real files or drives.
- ByteBroom never touches the rules listed under "Never touched" in `docs/spec.md` (once written).

## What ByteBroom cleans

Green items start ticked, because Windows or the app rebuilds them. Amber items are never ticked for
you. Red items are shown with their sizes only; ByteBroom never deletes them as files.

| Tier | Category |
|---|---|
| Green | User temp files |
| Green | Crash dumps |
| Green | Windows error reports |
| Green | Thumbnail and icon cache |
| Green | Internet cache |
| Green | DirectX shader cache |
| Green | Browser caches |
| Amber | Large files |
| Amber | Duplicates |
| Amber | Old installers |
| Amber | Developer caches |
| Amber | Build folders in code projects |
| Red | Recycle Bin |
| Red | Hibernation file |
| Red | Page file |
| Red | Previous Windows installation |
| Red | Windows Update store |
| Red | Delivery Optimization files |
| Red | Restore points |

Never listed at all, wherever they are: `.ssh`, `.gnupg`, `wallet.dat`, `Cookies`, `Login Data`,
`Login Data For Account`, `Web Data`, `History`, `Bookmarks`, `Local State`, and files ending in
`.kdbx`, `.1pif`, `.agilekeychain`, `.pfx`, `.p12`, `.pem` or `.key`. Links and junctions are never
followed.

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
