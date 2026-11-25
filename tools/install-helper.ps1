#Requires -RunAsAdministrator
# Installs ByteBroom's elevated helper (bytebroom-admin.exe) into Program Files\ByteBroom, an
# admin-owned folder, for phase 4 (the owner's decision 2; phase 6's installer replaces this).
# The owner runs it, in an administrator PowerShell, in your project folder, after ./build.ps1:
#     ./tools/install-helper.ps1
# Undo: ./tools/uninstall-helper.ps1
#
# What it trusts: the helper is copied from your build folder (target\release), which your own
# account can change, so installing trusts your account at that moment. Run ./build.ps1 and this
# script one after the other, on a PC you trust. From then on, only administrators can change
# the installed copy, and the helper refuses to run from anywhere else.
#
# It never runs the copied program as administrator (security review of task 1, S1): it checks
# the folder's and the file's permissions here, and the helper checks itself again when you
# first start it through UAC (the elevate_noop example).
$ErrorActionPreference = 'Stop'

if (-not [Environment]::Is64BitProcess) {
    throw 'Run this in 64-bit PowerShell (the helper belongs in Program Files, not Program Files (x86)).'
}
$source = Join-Path $PSScriptRoot '..\target\release\bytebroom-admin.exe'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw 'No helper built yet: run ./build.ps1 first.'
}
if ((Get-Item -LiteralPath $source -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw "$source is a link; rebuild with ./build.ps1."
}
# The known-folder API, not an environment variable.
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$dest = Join-Path $programFiles 'ByteBroom'
$exe = Join-Path $dest 'bytebroom-admin.exe'

# Start from a fresh folder, so no program keeps a handle or a permission from before.
if (Test-Path -LiteralPath $dest) {
    $item = Get-Item -LiteralPath $dest -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "$dest is a link; remove it by hand and run this again."
    }
    if (-not $item.PSIsContainer) { throw "$dest is a file, not a folder." }
    $others = Get-ChildItem -LiteralPath $dest -Force | Where-Object { $_.Name -ne 'bytebroom-admin.exe' }
    if ($others) { throw "$dest holds other files; not touching it. Look at it and remove it by hand." }
    Remove-Item -LiteralPath $dest -Recurse -Force
}
# A new folder under Program Files inherits its admin-only permissions.
New-Item -ItemType Directory -Path $dest | Out-Null
Copy-Item -LiteralPath $source -Destination $exe

$a = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
$b = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
if ($a -ne $b) { throw "The copy does not match the build ($a vs $b)." }

# The same rule the helper applies (crates/core/src/admin.rs): only these may own or change it.
. (Join-Path $PSScriptRoot 'helper-acl.ps1')
foreach ($path in @($dest, $exe)) {
    $problem = Get-AdminOwnedProblem $path
    if ($problem) { throw "$problem. Run ./tools/uninstall-helper.ps1 and tell Claude." }
}
Write-Host "Installed: $exe (SHA-256 $b). Only administrators can change it."
Write-Host 'Next, in an ordinary PowerShell: cargo run --release -p bytebroom-admin --example elevate_noop'
