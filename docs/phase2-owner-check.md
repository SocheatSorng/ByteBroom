# Phase 2: the owner's check

Phase 2 still has no window. This check runs the **read-only** scan tool on your real PC and compares
a few of its numbers with what Windows shows. Nothing in it deletes, moves or recycles anything: the
tool has no such option, and a test proves its program contains none of that code.

The tool's output names your files. It is only printed in your terminal; don't paste file names
anywhere you don't want them. For the report back, the totals and counts are enough.

## 1. Open the branch

In PowerShell, in the folder Claude names for the `phase-2-scanner` branch (or, in your project
folder, `git switch phase-2-scanner`).

## 2. Run every check

```powershell
./check.ps1
```

Expected: the last line says `All checks passed.`

## 3. Run the scan

```powershell
cargo run --release -p bytebroom-scan
```

Expected:

- It starts with `Nothing on this PC is changed by this scan.`
- "Looking in" lists your profile, AppData\Local and Downloads, and any other fixed drives. Any
  "Not scanned" line gives its reason.
- It prints `Scanned in ... s.` Note the time: this is the real-drive speed (task 8 measured 18.9 s
  for 200,000 files with a warm cache).
- It ends with `This list names your files. It was only printed here; ByteBroom saved it nowhere.`

## 4. Compare with Windows (read-only commands)

Each command below only reads. Compare its number with the matching line of the scan.

**Recycle Bin** (scan: Red, "Recycle Bin"):

```powershell
(New-Object -ComObject Shell.Application).NameSpace(10).Items() | Measure-Object -Property Size -Sum | Select-Object Count, Sum
```

The sum is in bytes; the scan rounds to MB or GB. They should match closely. The scan covers every
drive's Recycle Bin for your account.

**Page file and hibernation file** (scan: Red, "Page file", "Hibernation file"):

```powershell
cmd /c dir /a C:\pagefile.sys C:\hiberfil.sys
```

The sizes should match. "File Not Found" for hiberfil.sys means hibernation is off; the scan then
says "not present".

**Your temp folder** (scan: Green, "User temp files"):

```powershell
Get-ChildItem $env:LOCALAPPDATA\Temp -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum | Select-Object Count, Sum
```

The scan's number should be the **same or smaller**: it leaves out anything changed in the last 24
hours (your decision 4) and anything behind a link, and counts hard-linked files once.

**Downloads** (scan: Amber, "Old installers"): open Downloads in Explorer, sort by "Date modified",
and check that the installers (`.exe`, `.msi`, `.msix`, `.zip`, `.iso`) older than 30 days are the
ones the scan counted. A cloud (OneDrive) Downloads folder shows "[cloud file]" in the largest list.

**Two of the 20 largest items**: right-click each in Explorer → Properties. The size should match the
scan's line.

## 5. Tell Claude

Paste only these parts of the scan output, or just the numbers:

- the "Looking in" and any "Not scanned" lines (you can shorten your user name);
- the Totals block and the Red block;
- the "What the scan could not or would not read" counts;
- the scan time;
- whether each comparison in step 4 matched.

Claude checks them read-only. A mismatch is a bug to fix with a test before merging.

## 6. Merge

On your yes, Claude merges `phase-2-scanner` into `main` with `--ff-only`, then runs the checks
again on `main`.
