# Builds ByteBroom's elevated helper, target\release\bytebroom-admin.exe, then the window,
# target\release\bytebroom.exe, and the unsigned per-machine installer that holds both:
# target\release\bundle\nsis\ByteBroom_<version>_x64-setup.exe (phase 6). ./release.ps1 runs this,
# then signs the installer.
# Usage (in your project folder):  ./build.ps1
# Needs the Tauri CLI once: cargo install --locked tauri-cli
# 'Continue', not 'Stop': cargo writes progress to stderr (see check.ps1); the shared helpers stop
# on their own errors.
$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot
. (Join-Path $PSScriptRoot 'tools\build-common.ps1')
$savedFlags = $env:RUSTFLAGS
Set-NoProfilePathsInBinaries
try {

Write-Host '== Build the elevated helper (release)'
cargo build --release -p bytebroom-admin
if ($LASTEXITCODE -ne 0) { throw "Helper build failed (exit $LASTEXITCODE)" }
Write-Host "Built: $(Join-Path $PSScriptRoot 'target\release\bytebroom-admin.exe')"

# Tauri packs a sidecar from src-tauri\binaries\<name>-<target triple>.exe and installs it as
# <name>.exe beside the window, in <Program Files>\ByteBroom (src-tauri/tests/installer.rs).
Copy-StagedHelper $PSScriptRoot

Write-Host '== Build the window and the installer (release, unsigned)'
Push-Location (Join-Path $PSScriptRoot 'src-tauri')
cargo tauri build --config tauri.installer.json
$code = $LASTEXITCODE
Pop-Location
if ($code -ne 0) { throw "Build failed (exit $code)" }
# Nothing replaced the staged helper while the installer was packed.
Assert-StagedHelperMatches $PSScriptRoot
foreach ($exe in @('target\release\bytebroom.exe', 'target\release\bytebroom-admin.exe')) {
    Assert-NoProfilePath (Join-Path $PSScriptRoot $exe)
}
Write-Host "Built: $(Join-Path $PSScriptRoot 'target\release\bytebroom.exe')"
$setup = Get-ChildItem -Path (Join-Path $PSScriptRoot 'target\release\bundle\nsis') -Filter '*-setup.exe' |
    Sort-Object LastWriteTime | Select-Object -Last 1
Write-Host "Installer: $($setup.FullName) (installs both into Program Files\ByteBroom; asks UAC)"
Write-Host 'For a dev build without installing, tools/install-helper.ps1 still installs the helper alone.'

} finally {
    # Your PowerShell keeps its own RUSTFLAGS afterwards (or none).
    $env:RUSTFLAGS = $savedFlags
}
