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

To be filled in once the toolchain is chosen (phase 1). Each command listed here will be checked by a
docs-drift test.

## Development checks

- Secret scan before every commit: `pre-commit install` once (needs `pre-commit`, e.g.
  `uv tool install pre-commit`), then hooks run on each commit. Hooks: gitleaks, private-key detection,
  large-file check, JSON/YAML checks, zizmor for GitHub Actions workflows.
- GitHub Actions: `security.yml` (gitleaks over the full history, zizmor), Dependabot weekly.

## License

MIT, see `LICENSE`.
