# Builds ByteBroom's elevated helper, target\release\bytebroom-admin.exe, then the window,
# target\release\bytebroom.exe, and the unsigned per-machine installer that holds both:
# target\release\bundle\nsis\ByteBroom_<version>_x64-setup.exe (phase 6). Signed releases with
# updater files come from ./release.ps1.
# Usage (in your project folder):  ./build.ps1
# Needs the Tauri CLI once: cargo install --locked tauri-cli
# 'Continue', not 'Stop': cargo writes progress to stderr (see check.ps1).
$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot

Write-Host '== Build the elevated helper (release)'
cargo build --release -p bytebroom-admin
if ($LASTEXITCODE -ne 0) { throw "Helper build failed (exit $LASTEXITCODE)" }
$helper = Join-Path $PSScriptRoot 'target\release\bytebroom-admin.exe'
Write-Host "Built: $helper"

# Tauri packs a sidecar from src-tauri\binaries\<name>-<target triple>.exe and installs it as
# <name>.exe beside the window, in <Program Files>\ByteBroom (src-tauri/tests/installer.rs).
$binaries = Join-Path $PSScriptRoot 'src-tauri\binaries'
New-Item -ItemType Directory -Force -Path $binaries | Out-Null
Copy-Item -LiteralPath $helper -Destination (Join-Path $binaries 'bytebroom-admin-x86_64-pc-windows-msvc.exe') -Force

Write-Host '== Build the window and the installer (release, unsigned)'
Push-Location (Join-Path $PSScriptRoot 'src-tauri')
cargo tauri build --config tauri.installer.json
$code = $LASTEXITCODE
Pop-Location
if ($code -ne 0) { throw "Build failed (exit $code)" }
Write-Host "Built: $(Join-Path $PSScriptRoot 'target\release\bytebroom.exe')"
$setup = Get-ChildItem -Path (Join-Path $PSScriptRoot 'target\release\bundle\nsis') -Filter '*-setup.exe' |
    Sort-Object LastWriteTime | Select-Object -Last 1
Write-Host "Installer: $($setup.FullName) (installs both into Program Files\ByteBroom; asks UAC)"
Write-Host 'For a dev build without installing, tools/install-helper.ps1 still installs the helper alone.'
