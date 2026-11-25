# Phase 5: the owner's check

Undo and history, on your PC, with **two test files you make for this check** and nothing else. You
move one to another drive and put it back (twice, to see the second try refused), recycle the other
and find it in the History, then clear the history. Claude then checks, read-only, that the file
came back byte for byte.

You can stop at any step. Nothing is changed until you press **Clean now** in the preview, or the
yes button in a History question.

The window and the commands below show your file names. They stay on your PC; for the report back,
"yes/no" answers and the two hashes are enough.

## 1. Open the branch and build

In PowerShell, in the folder Claude names for the `phase-5-undo-history` branch:

```powershell
./check.ps1
```

Expected: the last line says `All checks passed.`

```powershell
./build.ps1
```

Expected: `Built: ...\target\release\bytebroom.exe`.

## 2. Make the two test files

ByteBroom lists files of 500 MB or more as "Large files", so each test file is 600 MB (zeros after
a different first byte, so they are not duplicates of each other). This makes a folder
`bytebroom-test` in your Downloads folder with two files:

```powershell
$t = Join-Path $env:USERPROFILE 'Downloads\bytebroom-test'; New-Item -ItemType Directory -Force $t | Out-Null; $i = 0; foreach ($n in 'move-me.bin','recycle-me.bin') { $i++; $f = [IO.File]::Create((Join-Path $t $n)); $f.SetLength(600MB); $f.WriteByte($i); $f.Close() }; Get-ChildItem $t
```

Then note the first file's SHA-256:

```powershell
Get-FileHash (Join-Path $env:USERPROFILE 'Downloads\bytebroom-test\move-me.bin') -Algorithm SHA256
```

Make a folder for the move on **another fixed drive** in Explorer, for example
`D:\ByteBroom-moved`.

## 3. Move one, recycle the other

Start `target\release\bytebroom.exe` and press **Scan**. When it is done:

1. Untick everything (the category ticks).
2. Press **Choose folder…** and pick the folder on the other drive.
3. Under "Large files", tick `move-me.bin` and set its action to **Move to folder**.
4. Tick `recycle-me.bin` and leave its action **Recycle Bin**.
5. **Preview…**, tick the confirm that lists both files, **Clean now**, then **Clean them** in
   Windows' dialog.

Expected: the result screen shows one item moved and one recycled, and says "Moved files can be put
back from History."

## 4. Look at the History

Close the result screen and press **History…** (top right). Expected:

- under "Moved files", today's clean with `move-me.bin`, its "From" path in your Downloads and its
  "Now in" path on the other drive, and a **Put back…** button;
- under "Sent to the Recycle Bin", `recycle-me.bin` with where it came from, and
  **Open the Recycle Bin**.

## 5. Put it back

Press **Put back…** next to `move-me.bin`. ByteBroom asks first, naming where it goes. Press
**Put back**. Expected: "move-me.bin is back where it was.", and the row now says "Put back" with
today's date. No Windows administrator prompt appears.

Read-only, check the file and its hash:

```powershell
Get-FileHash (Join-Path $env:USERPROFILE 'Downloads\bytebroom-test\move-me.bin') -Algorithm SHA256
```

Expected: the same SHA-256 as in step 2, and `move-me.bin` is gone from the folder on the other
drive.

## 6. Try to put it back again

The row has no button now. Close the History, open it again: still "Put back". (The refusal of a
second try is also tested on fake files: "it was already put back".)

## 7. The recycled file

In the History, press **Open the Recycle Bin**. Expected: Explorer shows the Recycle Bin with
`recycle-me.bin` in it. Restore it there with Windows' own **Restore** if you like, or leave it.
ByteBroom never restores it itself.

## 8. Clear the history

Press **Clear history…**. ByteBroom asks first and says the files stay where they are. Press
**Clear history**. Expected: "History cleared. No file was touched.", both lists empty, and
`move-me.bin` still in `Downloads\bytebroom-test`.

## 9. Tidy up

Delete the `bytebroom-test` folder (and `recycle-me.bin` from the Recycle Bin, if you restored it,
delete that too) and the folder on the other drive, in Explorer.

## 10. Tell Claude

- whether each expectation in steps 3 to 8 held (yes/no, and what differed);
- whether the two SHA-256 values in steps 2 and 5 matched;
- whether any Windows administrator prompt appeared (none should).

Claude checks them read-only. A mismatch is a bug to fix with a test before merging.

## 11. Merge

On your yes, Claude merges `phase-5-undo-history` into `main` with `--ff-only`, then runs the checks
and the build again on `main`.
