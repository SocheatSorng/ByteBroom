# Phase 3: the owner's check

The first real clean. You run the window on your PC, clean a **few** green items (one action
"Delete for good", one "Recycle Bin"), and move **one** large file to another drive. Claude then
checks, read-only, that exactly those items changed and that the moved file arrived whole.

Choose small, low-stakes items: green items are rebuilt by Windows or their app, and the large file
should be one you would be fine to keep on the other drive. You can stop at any step: nothing is
changed until you press **Clean now** in the preview.

The window and the commands below show your file names. They stay on your PC; for the report back,
"yes/no" answers and counts are enough.

## 1. Open the branch and build

In PowerShell, in the folder Claude names for the `phase-3-window` branch:

```powershell
./check.ps1
```

Expected: the last line says `All checks passed.`

```powershell
./build.ps1
```

Expected: `Built: ...\target\release\bytebroom.exe`.

## 2. Scan

Start `target\release\bytebroom.exe` (double-click it, or run it from PowerShell). No Windows
administrator prompt should appear (phase 3 runs without admin rights). Press **Scan**.

Expected:

- the status line counts up, the green and amber lists fill in, then "Looking for duplicates";
- the red section shows sizes only, with "freed in a later version, through Windows' own tools";
- any OneDrive file shows "cloud file (OneDrive)" and can't be ticked.

## 3. Choose three things, and note them

1. **Delete for good:** untick everything (the category ticks), then tick **one** green item, for
   example one crash dump or one item in "User temp files". Leave its action "Delete for good".
2. **Recycle Bin:** tick **one other** green item and set its action to "Recycle Bin".
3. **Move:** press **Choose folder…** and pick a folder on **another drive** (for example
   `D:\ByteBroom-moved`, made first in Explorer). Tick **one** large file and set its action to
   "Move to folder".

Before you go on, copy the three full paths (shown under each name) into a text file on your PC.

## 4. Snapshot, read-only

For each of the three items, run this with the item's **folder** (the path without its last part),
and a snapshot name of your choice. It only reads, and it saves the snapshot as a file in your
temp folder, not in the repo:

```powershell
./tools/verify-tree.ps1 -Snapshot -Path "<the item's folder>" -Out "$env:TEMP\bb-before-1.json"
```

Use `bb-before-2.json` and `bb-before-3.json` for the other two. Also snapshot the move destination
folder as `bb-before-dest.json`. The script reads every file to hash it, so a big folder (your temp
folder can be several GB) takes a minute or two. It was written for test folders, but it only
reads: it opens files for reading and writes nothing but the snapshot file.

## 5. Preview and clean

Press **Preview…**. Expected:

- three rows: Delete for good, Move, Recycle Bin, each with one item;
- "Space back now" counts the delete and the move, and the Recycle Bin row shows 0 B with the note
  that its space comes back only when the bin is emptied;
- the green confirm is there; an amber confirm is there too if the large file is amber (it is),
  listing just that one file;
- **Clean now** stays greyed until both confirms are ticked.

Tick the confirms and press **Clean now**. Expected: because the large file is one of your own
(amber), Windows' own dialog "ByteBroom: clean your own files?" asks once more, naming 1 file, its
size, "1 moved" and its path. This one comes from ByteBroom's Rust side, so a page can't skip it.
Press **Clean them**. (To test the brakes first, you can press **Cancel** once: the status line
says nothing was cleaned; preview again and continue.)

Expected after cleaning: the result screen shows the space back now,
one item done per action, and "Open Recycle Bin" (the recycled item should be in the bin).

## 6. Snapshot again and compare, read-only

Repeat step 4 with `bb-after-*.json`, then compare each pair:

```powershell
./tools/verify-tree.ps1 -Compare -Before "$env:TEMP\bb-before-1.json" -After "$env:TEMP\bb-after-1.json"
```

Expected: for the three item folders, only `removed:` lines for the item you chose (and, for a
folder item, what was inside it). Other programs also write to temp folders, so an unrelated
`added:` line there is normal; note it. For the destination: one `added:` line, the moved file.

Then the moved file's hash and the journal, read-only:

```powershell
Get-FileHash "<the moved file in the destination>" -Algorithm SHA256
```

```powershell
Get-Content "$env:LOCALAPPDATA\ByteBroom\moves.journal" -Tail 3
```

Expected: the journal's last line names the old and new paths, with the same SHA-256 as
`Get-FileHash`.

## 7. Tell Claude

- whether each expectation in steps 2, 5 and 6 held (yes/no, and what differed);
- the `-Compare` output lines with your user name shortened if you like;
- whether the two SHA-256 values matched.

Claude checks them read-only. A mismatch is a bug to fix with a test before merging. You can move
the file back yourself whenever you like; undo from the journal comes in phase 5.

## 8. Merge

On your yes, Claude merges `phase-3-window` into `main` with `--ff-only`, then runs the checks and
the build again on `main`.
