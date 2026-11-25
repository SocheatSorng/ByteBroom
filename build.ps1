# Builds ByteBroom's window, target\release\bytebroom.exe, and its elevated helper,
# target\release\bytebroom-admin.exe (no installer until phase 6).
# Usage (in your project folder):  ./build.ps1
# Needs the Tauri CLI once: cargo install --locked tauri-cli
# 'Continue', not 'Stop': cargo writes progress to stderr (see check.ps1).
$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot

Write-Host '== Build (release, no installer)'
cargo tauri build --no-bundle
if ($LASTEXITCODE -ne 0) { throw "Build failed (exit $LASTEXITCODE)" }
Write-Host "Built: $(Join-Path $PSScriptRoot 'target\release\bytebroom.exe')"

Write-Host '== Build the elevated helper (release)'
cargo build --release -p bytebroom-admin
if ($LASTEXITCODE -ne 0) { throw "Helper build failed (exit $LASTEXITCODE)" }
Write-Host "Built: $(Join-Path $PSScriptRoot 'target\release\bytebroom-admin.exe') (install with tools/install-helper.ps1, as administrator)"
