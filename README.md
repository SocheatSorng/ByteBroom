# ByteBroom

A Windows disk-space cleaner. With your explicit permission (a Windows administrator prompt), ByteBroom
scans the drive, shows you what it can clean and how much space each item frees, and removes only what
you confirm.

> **Status: phase 4 (elevation and the red tier) built, awaiting the owner's check; version 0.3.0.**
> The safety core and delete engine (phase 1), the scanner (phase 2) and the window (phase 3) are
> done. The window now also frees three of Windows' own areas through Windows' own tools. The
> phases are in `docs/spec.md`.

## Safety promises

- Nothing is deleted without a preview and your confirmation.
- Tests and harnesses only ever use fake folders in a temp directory, never your real files or drives.
- ByteBroom never touches the rules listed under "Never touched" in `docs/spec.md` (once written).

## What ByteBroom cleans

Green items start ticked, because Windows or the app rebuilds them. Amber items are never ticked for
you. Red items are Windows' own areas: ByteBroom never deletes them as files. Three of them have a
button in the window's red tier (below); the rest are shown with their sizes only.

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
`Login Data For Account`, `Web Data`, `History`, `Bookmarks`, `Local State`, Firefox's `logins.json`,
`key4.db`, `cert9.db`, `cookies.sqlite` and `places.sqlite`, SSH keys named `id_rsa` or `id_ed25519`,
and files ending in `.kdbx`, `.kdb`, `.psafe3`, `.1pif`, `.agilekeychain`, `.gpg`, `.pfx`, `.p12`,
`.pem`, `.key` or `.ppk`. Their SQLite companions (the same name ending in -journal, -wal or
-shm) are never listed either. Links and junctions are never followed.

## Using the window

1. **Scan.** ByteBroom only reads while it scans. Everything but duplicates is listed first;
   duplicates follow when hashing ends. You can stop a scan at any time.
2. **Choose.** Tick items and pick an action for each: **Delete for good**, **Recycle Bin**, or
   **Move to folder**. Green items start ticked with "Delete for good"; amber items are never
   ticked for you and start with "Recycle Bin". Cloud files (OneDrive) and items that can't be
   cleaned where they are are shown but can't be ticked. Virtual machine disks are labelled:
   deleting one removes the VM, so moving it is safer.
3. **Preview.** The preview shows, per action, how many items and how much space really comes back
   now. Items it leaves out are listed with the reason (for example a duplicate whose kept copy is
   also chosen).
4. **Confirm.** Green items need one confirm. Amber items need a second confirm that lists every
   one of them. "Clean now" stays off until both are ticked. When amber items are chosen, Windows'
   own dialog "ByteBroom: clean your own files?" then opens over the window. Cancel is its
   default button, so Enter cancels. Only **Clean them** goes ahead, and an answer given in under
   a second counts as a stray click, so nothing is cleaned. Each answer is logged (counts only, no file names) in `ByteBroom\bytebroom.log` in your
   local app data folder.
5. **Clean.** Right before acting, each item is checked again: it must still be the same file,
   unchanged since the scan; a duplicate must still match its kept copy; and a temp item must not
   have been used in the last 24 hours. The file's identity is checked once more on the very
   handle that deletes, copies or recycles it. Anything that changed stays, and the result says why.

Where the space comes back:

- **Delete for good:** at once.
- **Move to folder:** at once, on the drive the files leave. Moves go only to a folder on another
  fixed drive, because a move within one drive frees nothing. Every moved file is recorded with its
  SHA-256 in `ByteBroom\moves.journal` in your local app data folder.
- **Recycle Bin:** not until you empty the bin. Each drive's Recycle Bin is on that same drive, so
  recycling frees nothing by itself; the result screen offers to open the bin.

### History: putting moves back

**History…** (top right) lists what ByteBroom moved, one clean at a time with the newest first,
and what it sent to the Recycle Bin.

- **Put back…** puts a moved file back where it was. **Put back all…** does the same for every
  file of one clean that is still moved. The page asks first. Each file is copied back into its
  original folder and checked against the SHA-256 recorded when it was moved; the moved copy is
  removed only after the copy matches. Nothing already at the original place is ever replaced. If
  the original folder is gone (a moved folder), it is made again, but only inside a place
  ByteBroom scans. A file can't be put back directly into your profile folder or a drive root:
  move those back by hand. Putting back never runs as administrator.
- A file shows why it can't be put back now, for example when the drive it was moved to is not
  plugged in. A file that was already put back says so, and a second try changes nothing.
- **Recycled items** are listed with where they came from. ByteBroom never restores them itself:
  **Open the Recycle Bin**, select them, and use Windows' own Restore.
- **Deleted items** are gone for good and are not listed.
- **Clear history…** forgets everything listed. The files stay exactly where they are, but moved
  files can then no longer be put back from ByteBroom.

The history lives in your local app data folder: `ByteBroom\moves.journal` (moves, and which were
put back) and `ByteBroom\recycled.journal` (what was recycled). Both list your file names, so they
are never committed, logged or sent anywhere; `bytebroom.log` keeps counts only.

## Install, run, test, build

ByteBroom is written in Rust: the safety core and scanner in `crates/core`, the read-only scan tool
in `crates/scan`, and the Tauri 2 window in `src-tauri` (with its page in `ui/`, plain HTML, CSS and
JavaScript with no packages).

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

### The red tier: Windows' own areas

Three buttons free space in Windows' own areas, each only after you type its word:

| Button | Type | What happens | Undo |
| --- | --- | --- | --- |
| **Empty the Recycle Bin** | `recycle bin` | Windows' own dialog "ByteBroom: empty the Recycle Bin?" opens; only **Empty it** goes ahead. No administrator rights. | Can't be undone. |
| **Clear the Delivery Optimization cache** | `delivery optimization` | The UAC prompt, then the helper makes a restore point and runs `Delete-DeliveryOptimizationCache -Force` (pinned files kept). | Can't be undone; Windows downloads again what it needs. |
| **Turn hibernation off** | `hibernation` | The UAC prompt, then the helper makes a restore point and runs `powercfg /hibernate off`. Hibernate and Hybrid Sleep stop working. | `powercfg /hibernate on` in an administrator PowerShell. |

Before a helper action, a restore point is made (a point from the last 24 hours counts, as Windows
makes at most one a day). If System Restore is off, paused for low disk space, or the point can't
be confirmed, nothing is changed and the window says why. Afterwards the red sizes are measured
again. How to undo each action and how to roll Windows back, even when it won't start, is in
`docs/recovery.md`: keep it at hand.

To run the window, install the Tauri CLI once with `cargo install --locked tauri-cli`, then run
`cargo tauri dev` in your project folder. To build it, run `./build.ps1`: it makes
`target\release\bytebroom.exe` (the installer comes in phase 6).

`./build.ps1` also builds the elevated helper, `target\release\bytebroom-admin.exe` (phase 4).
The window never runs as administrator; for a red-tier action it starts this helper
through Windows' UAC prompt, which only you click. The helper has no window and does one fixed
action per run. It runs only from an admin-owned folder, `Program Files\ByteBroom`, and refuses
anywhere else, so ordinary programs can't swap it. To put it there, run
`./tools/install-helper.ps1` in an administrator PowerShell in your project folder; to remove
it, run `./tools/uninstall-helper.ps1` the same way. The script copies the helper from your build
folder, which your own account can change, so run `./build.ps1` and the install one after the
other on a PC you trust. When the UAC prompt appears, **Show more details** must name
`C:\Program Files\ByteBroom\bytebroom-admin.exe`; if it names anything else, click No.

To check the window's look without scanning anything, run `node tools/ui-harness/serve.mjs` and open
the address it prints. It serves the real page with made-up findings and never runs ByteBroom.

To see what ByteBroom would offer to clean on your PC, run `cargo run --release -p bytebroom-scan` in
your project folder. It only reads: it has no option that deletes, moves or recycles anything, and a
test checks that its program contains none of the code that does. It prints the totals for each
category and tier, the 20 largest items and what it could not read. The list names your files, so it
is only printed in your terminal and never saved.

## Development checks

- Secret scan before every commit: `pre-commit install` once (needs `pre-commit`, e.g.
  `uv tool install pre-commit`), then hooks run on each commit. Hooks: gitleaks, private-key detection,
  large-file check, JSON/YAML checks, zizmor for GitHub Actions workflows.
- GitHub Actions: `security.yml` (gitleaks over the full history, zizmor), Dependabot weekly.
- The window's boundary is pinned by `src-tauri/tests/boundary.rs`: the seven commands, the one
  capability file, the content security policy, the approved dependencies, and a page that loads
  nothing remote and runs no inline code.

## License

MIT, see `LICENSE`.
