# ByteBroom: statement of intent

Confirmed by the owner on 2026-11-24 after a nine-question interview.

## Intent

- **Outcome:** ByteBroom, a Windows desktop app (Rust + Tauri 2) that scans a drive, groups what it finds
  into three tiers with sizes, and frees space only after the user previews and confirms. Per item, the
  user chooses Recycle Bin, permanent delete, or move to another drive.
  - **Green:** temp files and caches, pre-ticked.
  - **Amber:** personal files, code projects, keys and vaults, never pre-ticked, with an extra confirm.
  - **Red:** Windows, Program Files, pagefile/hiberfil, restore points. Freed only through Windows' own
    tools (DISM, `powercfg`, Disk Cleanup handlers), never by deleting files, after administrator rights
    and a typed confirm.
- **User:** the owner first, on their own PC (whose system drive was nearly full); also other people who
  download it.
- **Why now:** the system drive is nearly full, and the previous project is finished.
- **Success:**
  - One session frees a lot of space on the system drive.
  - Windows and every app still work afterwards.
  - Everything sent to the Recycle Bin or moved can be brought back.
  - It is safe enough to run on strangers' PCs.
- **Constraints:**
  - Starts unelevated; a "Scan whole drive (admin)" button relaunches it through UAC, which the user
    clicks themselves.
  - Released as an installer on GitHub Releases, with in-app updates verified by a signature key only
    the owner holds. No paid code-signing certificate at first (Windows SmartScreen will warn about an
    unknown publisher).
  - Tests and harnesses only ever use fake folders in a temp directory.
  - Every change to deleting, elevation or updates gets a security review.
- **Out of scope:**
  - Registry "cleaning".
  - Scheduled automatic cleaning.
  - Deleting system files directly.
  - Microsoft Store or winget.
  - Translations.
  - Other PCs on a network.

## Interview answers

1. **What to clean:** all kinds: temp files and caches, Windows Update leftovers, the Recycle Bin, large
   and duplicate files, and more (developer caches, old installers, leftovers of removed apps).
2. **Big files you still want:** the user chooses delete or move to another drive.
3. **How final deleting is:** chosen per item: Recycle Bin, permanent, or move. (The Recycle Bin on the
   same drive frees no space until emptied; the UI must say so.)
4. **Form:** a desktop window.
5. **Toolchain:** Rust + Tauri 2. The scanning and deleting core is pure Rust (`windows-rs`), tested with
   `cargo test`; the window is HTML/CSS in WebView2.
6. **Administrator rights:** elevate on demand through UAC, never at every launch.
7. **What must never be touched:** everything may be touched, each area with its own level of permission
   (the three tiers above). Links, junctions and files in use are never followed or deleted.
8. **Who uses it:** the owner and other people.
9. **Distribution:** GitHub Releases with signed in-app updates; code signing may be added later.
