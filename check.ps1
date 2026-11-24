# Runs every check ByteBroom needs before a commit: format, lint, tests, dependency audit.
# Usage (in your project folder):  ./check.ps1
# 'Continue', not 'Stop': cargo writes progress to stderr, which PowerShell 5.1 would turn into a
# terminating error. Each step is judged by its exit code instead.
$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot

function Invoke-Step([string]$Name, [scriptblock]$Command) {
    Write-Host "== $Name"
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$Name failed (exit $LASTEXITCODE)" }
}

Invoke-Step 'Format check' { cargo fmt --all -- --check }
Invoke-Step 'Lint' { cargo clippy --workspace --all-targets -- -D warnings }
Invoke-Step 'Test' { cargo test --workspace }
Invoke-Step 'Dependency audit' { cargo deny check }
Write-Host 'All checks passed.'
