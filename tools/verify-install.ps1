# Checks an installed ByteBroom, read-only (phase 6): the installer put the window and the elevated
# helper in Program Files\ByteBroom, and only administrators can change the folder or either
# program. It changes nothing and needs no administrator rights.
# The owner runs it after installing, in an ordinary PowerShell, in your project folder:
#     ./tools/verify-install.ps1
$ErrorActionPreference = 'Stop'

if (-not [Environment]::Is64BitProcess) {
    throw 'Run this in 64-bit PowerShell (ByteBroom installs into Program Files, not Program Files (x86)).'
}
# The known-folder API, not an environment variable (as crates/core/src/win/admin.rs, helper_path).
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$dest = Join-Path $programFiles 'ByteBroom'
$window = Join-Path $dest 'bytebroom.exe'
$helper = Join-Path $dest 'bytebroom-admin.exe'
# Run as administrator by every update and uninstall, so it must be admin-owned too.
$uninstaller = Join-Path $dest 'uninstall.exe'

if (-not (Test-Path -LiteralPath $dest -PathType Container)) {
    throw "$dest is missing: ByteBroom isn't installed for all users, or went to another folder."
}
. (Join-Path $PSScriptRoot 'helper-acl.ps1')
$problems = @()
foreach ($path in @($dest, $window, $helper, $uninstaller)) {
    if (-not (Test-Path -LiteralPath $path)) { $problems += "$path is missing"; continue }
    $problem = Get-AdminOwnedProblem $path
    if ($problem) { $problems += $problem }
}
# Windows' own record of the install (read only) must point at this folder, not another copy.
$record = Get-ItemProperty -LiteralPath 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ByteBroom' -ErrorAction SilentlyContinue
if (-not $record) {
    $problems += 'Windows has no record of a ByteBroom install for all users'
} else {
    if ($record.InstallLocation.Trim('"').TrimEnd('\') -ne $dest) {
        $problems += "Windows' record says ByteBroom is installed in $($record.InstallLocation)"
    }
    if ($record.UninstallString.Trim('"') -ne $uninstaller) {
        $problems += "Windows' record runs $($record.UninstallString) to uninstall"
    }
}
if ($problems) {
    $problems | ForEach-Object { Write-Host "PROBLEM: $_" }
    throw 'The install is not admin-owned as expected. Tell Claude; do not use the red actions.'
}
foreach ($path in @($window, $helper)) {
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    Write-Host "OK: $path (SHA-256 $hash)"
}
Write-Host "OK: only administrators can change $dest and both programs."
