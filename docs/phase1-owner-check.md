# Phase 1: the owner's check

Phase 1 has no app window yet; this check runs the engine's own tests on your PC. They only use fake
folders in your temp folder, except step 3, which puts **one** small dummy file in your real Recycle
Bin (your decision 1).

## 1. Get the branch

In PowerShell, in your project folder:

```powershell
git switch phase-1-delete-engine
```

## 2. Run every check

```powershell
./check.ps1
```

Expected: the last line says `All checks passed.` It takes a minute or two the first time.

## 3. The opt-in Recycle Bin test (one dummy file)

```powershell
$env:BYTEBROOM_REAL_RECYCLE_BIN_TESTS = "1"
cargo test --test recycle real_bin_recycles_one_dummy_file -- --ignored --nocapture
Remove-Item Env:\BYTEBROOM_REAL_RECYCLE_BIN_TESTS
```

Expected: `test result: ok. 1 passed`, and a line `Recycled bytebroom-test-....txt: find it in the
Recycle Bin.`

## 4. Look in the Recycle Bin

1. Open the Recycle Bin on the desktop.
2. Find the file whose name starts with `bytebroom-test-` (about 4 KB).
3. Right-click it → **Restore**. It goes back to a `bytebroom-tests` folder inside your temp folder.
4. Tell Claude it restored. Claude checks it with a read-only look, then you can delete that
   `bytebroom-tests` folder (or leave it; it is only test data).

## 5. Tell Claude

- Did step 2 end with `All checks passed.`?
- Did step 3 pass, and did step 4 find and restore the file?

Then, if you say so, Claude merges the branch into `main` with `--ff-only` and runs the checks again.
