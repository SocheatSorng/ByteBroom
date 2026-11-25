# Recovery recipe

How to undo what ByteBroom's red tier does, and how to roll Windows back if something goes wrong.
Keep this page at hand (printed, or open on another device) before you run any red action.

Sources: Microsoft Support's
[Use System Restore](https://support.microsoft.com/en-us/windows/use-system-restore-a5ae3ed9-07c4-fd56-45ee-096777ecd14e),
[Windows Recovery Environment](https://support.microsoft.com/en-us/windows/windows-recovery-environment-0eb14733-6301-41cb-8d26-06a12b42770b)
and [Recovery options in Windows](https://support.microsoft.com/en-us/windows/recovery-options-in-windows-31ce2444-7de3-818c-d626-e3b5a3024da5),
read on 2026-11-25, and the action pages listed in `docs/phase4-plan.md` (task 0). Where Microsoft
doesn't say something, this page says "not stated" rather than guess.

## Before a red action

1. **Make sure C: has free space.** When C: fills up, Windows deletes restore points without
   asking: on 2026-11-25 every restore point on the owner's PC went this way (volsnap event 36).
   Keep several GB free.
2. **The helper makes or confirms a restore point first,** in the same run, and does nothing if
   it can't. It answers `Done` only once Windows lists the point. A point from the last 24 hours
   counts, because Windows makes at most one a day; so the point can be up to a day old, and
   changes made since then aren't in it.
3. **Check the point yourself:** press Win+R, type `rstrui.exe`, press Enter, and look at the
   newest restore point (choose "Choose a different restore point" if asked). Close it with
   **Cancel**.

## Undo each action

| Action | Undo | Notes |
| --- | --- | --- |
| Restore point (`restore-point`) | Nothing to undo. | It only adds a restore point, named "ByteBroom: restore point on request". Windows deletes old points itself as their space fills. |
| Hibernation off (`hibernation-off`) | In an **administrator** PowerShell: `powercfg /hibernate on` | Brings back Hibernate, Hybrid Sleep and `hiberfil.sys`. Check with `powercfg /a`. Fast Startup stays as your policy sets it (disabled on the owner's PC). |
| Delivery Optimization cache (`delivery-optimization-cache`) | Can't be undone. | Microsoft: "Deletion can't be undone". Nothing is lost for good: Windows downloads again what it needs. |
| Empty the Recycle Bin | Can't be undone. | The files are gone. A restore point doesn't bring personal files back. |
| The helper itself | In an **administrator** PowerShell, in your project folder: `./tools/uninstall-helper.ps1` | Removes `Program Files\ByteBroom`. |

## Roll Windows back with System Restore

System Restore "reverts the system files, registry settings, and installed programs" to the
restore point. Microsoft: "Your personal files are kept", but recently installed apps, drivers,
updates or settings may be affected. Before you finish, **Scan for affected programs** shows which
programs the restore touches.

Microsoft doesn't state whether a restore can be undone, so don't count on it.

### From Windows (it still starts)

1. Open **Control Panel › Recovery › Open System Restore**, or press Win+R, type `rstrui.exe`
   and press Enter.
2. In "Restore system files and settings", select **Next**.
3. Pick the restore point ("Show more restore points" lists older ones). Optionally select
   **Scan for affected programs**.
4. Select **Next**, then **Finish**. Windows restarts and applies it.

### From Windows' recovery screen (Windows RE)

Get to Windows RE in any of these ways:

- **Settings › Update & Security › Recovery › Advanced startup › Restart now.**
- Hold **Shift** while you select **Power › Restart**.
- **If Windows can't start:** Windows opens Windows RE itself after it fails to start several
  times. To force it, interrupt the start twice (hold the power button); on the third start, the
  Automatic Repair screen appears; select **Advanced options**.
- **From a USB recovery drive or Windows installation media:** start the PC from it. On
  installation media, select **Next**, then **Repair my PC**.

Then select **Troubleshoot › Advanced options › System Restore**, and follow steps 2 to 4 above,
ending with **Restart**.

**BitLocker:** if the drive is encrypted, Windows RE needs the BitLocker recovery key. Have it
before you start. (On the owner's PC, BitLocker is off for C:, checked read-only on
2026-11-25.)

## What can't be undone

- Emptying the Recycle Bin.
- Clearing the Delivery Optimization cache (Windows re-downloads what it needs).
- Removing **Windows.old** (ends going back to the previous Windows). ByteBroom only shows it and
  opens Windows' Storage page; it never removes it.
- Deleting **old restore points**. ByteBroom never deletes restore points; it only shows their size.
- `DISM /ResetBase` makes installed updates impossible to uninstall. ByteBroom never suggests it.

## Known gaps

- A restore point can be up to 24 hours old (Windows makes at most one a day).
- Windows can delete a confirmed restore point later, for example when C: fills up.
- Microsoft's recovery pages apply to Windows 11 and Windows 10, with no build named; Windows 10
  support ended on 2025-10-14.

## Roll back an update (phase 6)

An update replaces `Program Files\ByteBroom` with the newer version. It never touches your history
in `%LOCALAPPDATA%\ByteBroom`. To go back to an earlier version:

1. Download that version's `ByteBroom_<version>_x64-setup.exe` from this repository's Releases page.
2. Uninstall ByteBroom (**Settings → Apps → Installed apps → ByteBroom → Uninstall**). Leave
   "Delete the application data" unticked; it never removes your history anyway.
3. Run the older installer and accept Windows' administrator prompt.
4. Optional: run `./tools/verify-install.ps1` in your project folder to check the install, read-only.

At the next start the older version offers the newer update again. Press **Not now** until a fixed
version is out.

## The signing key

The private key is `bytebroom.key` in `%LOCALAPPDATA%\ByteBroom-signing`, and its password is the
one you typed when you made it. Neither is ever in this repository or on GitHub.

- **Lost on this PC:** copy `bytebroom.key` and `bytebroom.key.pub` back from your offline backup
  into that folder. `./release.ps1` refuses any key whose public half isn't the one in
  `src-tauri/tauri.conf.json`.
- **Lost for good (no backup):** installed copies can never update again. Make a new key and put
  its public half in `tauri.conf.json`. Then tell users in the release notes to download and
  install the new version by hand once.
- **Leaked (someone else may have the file and the password):** make a new key, release a version
  that carries the new public key at once, and say in its release notes why. Until users have
  that version, an update signed with the old key would still be accepted, so watch the
  repository's Releases for anything you didn't publish.

Two rules for the key:

- **Never sign a test build with it.** A genuinely signed installer stays valid for good. A test
  build signed as, say, 9.9.9 could be served later as an "update" to everyone. Test with a
  throwaway key, as the tests do.
- **Known limit:** the installer has no paid Authenticode certificate. Windows' administrator
  prompt therefore shows "Unknown publisher" for every ByteBroom installer, genuine or not. The
  updater checks the signature before it starts the installer. A program already running as you
  could still swap the downloaded file in your temp folder in that moment. Install updates only on
  a PC you trust. A paid certificate (out of scope for V1) would let the prompt name the publisher.
