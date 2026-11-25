#Requires -RunAsAdministrator
# Installs ByteBroom's elevated helper (bytebroom-admin.exe) into Program Files\ByteBroom, an
# admin-owned folder, for phase 4 (the owner's decision 2; phase 6's installer replaces this).
# The owner runs it, in an administrator PowerShell, in your project folder, after ./build.ps1:
#     ./tools/install-helper.ps1
# Undo: ./tools/uninstall-helper.ps1
$ErrorActionPreference = 'Stop'

$source = Join-Path $PSScriptRoot '..\target\release\bytebroom-admin.exe'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "No helper built yet: run ./build.ps1 first."
}
# The known-folder API, not an environment variable.
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$dest = Join-Path $programFiles 'ByteBroom'
$exe = Join-Path $dest 'bytebroom-admin.exe'

if (Test-Path -LiteralPath $dest) {
    $item = Get-Item -LiteralPath $dest -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "$dest is a link; remove it by hand and run this again."
    }
    if (-not $item.PSIsContainer) { throw "$dest is a file, not a folder." }
} else {
    # A new folder under Program Files inherits its admin-only permissions.
    New-Item -ItemType Directory -Path $dest | Out-Null
}
Copy-Item -LiteralPath $source -Destination $exe -Force

$a = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
$b = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
if ($a -ne $b) { throw "The copy does not match the build ($a vs $b)." }

# The helper checks its own place: run as administrator from here, the no-op must answer 0.
& $exe noop
$code = $LASTEXITCODE
switch ($code) {
    0 { Write-Host "Installed: $exe (SHA-256 $b). The helper accepts its place." }
    3 { throw "Installed, but the helper finds $dest changeable by ordinary users (exit 3). Run ./tools/uninstall-helper.ps1 and tell Claude." }
    default { throw "Installed, but the helper's self-test answered $code. Run ./tools/uninstall-helper.ps1 and tell Claude." }
}
