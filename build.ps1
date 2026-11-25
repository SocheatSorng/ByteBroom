# Builds ByteBroom's window as one program: target\release\bytebroom.exe (no installer until phase 6).
# Usage (in your project folder):  ./build.ps1
# Needs the Tauri CLI once: cargo install --locked tauri-cli
# 'Continue', not 'Stop': cargo writes progress to stderr (see check.ps1).
$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot

Write-Host '== Build (release, no installer)'
cargo tauri build --no-bundle
if ($LASTEXITCODE -ne 0) { throw "Build failed (exit $LASTEXITCODE)" }
Write-Host "Built: $(Join-Path $PSScriptRoot 'target\release\bytebroom.exe')"
