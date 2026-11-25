# Builds a signed ByteBroom release on your PC (phase 6, owner's decisions 3 and 4): the checks,
# the per-machine installer with the helper, its updater signature, and latest.json, then checks
# the result independently (tools/verify-release.mjs). The private key never leaves your PC.
# Usage: open a new PowerShell, go to your project folder, run  ./release.ps1  and close that
# PowerShell afterwards. You type the signing key's password when asked; nothing is uploaded. At the
# end it prints the three files to attach to a GitHub release named v<version>, in the browser.
# 'Continue', not 'Stop': cargo writes progress to stderr (see check.ps1).
$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot
. (Join-Path $PSScriptRoot 'tools\build-common.ps1')

# The key lives outside every repo (decision 4); only its .pub is compared, never printed.
$keyDir = Join-Path $env:LOCALAPPDATA 'ByteBroom-signing'
$key = Join-Path $keyDir 'bytebroom.key'
$pub = Join-Path $keyDir 'bytebroom.key.pub'
if (-not (Test-Path -LiteralPath $key -PathType Leaf) -or -not (Test-Path -LiteralPath $pub -PathType Leaf)) {
    throw "No signing key in $keyDir. Restore it from your offline backup (see docs/recovery.md)."
}
$conf = Get-Content -Raw -LiteralPath 'src-tauri\tauri.conf.json' | ConvertFrom-Json
if ((Get-Content -Raw -LiteralPath $pub).Trim() -ne $conf.plugins.updater.pubkey) {
    throw 'The key in your signing folder is not the one in src-tauri\tauri.conf.json. Nothing was built.'
}

$dirty = git status --porcelain
if ($LASTEXITCODE -ne 0) { throw 'git could not read this folder: run this in your project folder.' }
if ($dirty) { throw 'Commit or put aside your changes first: a release is built from a clean commit.' }
$commit = git rev-parse --short HEAD
$branch = git rev-parse --abbrev-ref HEAD
$version = (cargo metadata --no-deps --format-version 1 | ConvertFrom-Json).packages |
    Where-Object { $_.name -eq 'bytebroom-app' } | Select-Object -ExpandProperty version
Write-Host "== Release $version from $branch at $commit"

Write-Host '== Checks'
& (Join-Path $PSScriptRoot 'check.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Checks failed: nothing was built.' }

# Build first, with no key or password anywhere in the environment: cargo runs every dependency's
# build script and macros, and none of them may see the secrets (security review S1).
$nsis = Join-Path $PSScriptRoot 'target\release\bundle\nsis'
if (Test-Path -LiteralPath $nsis) { Get-ChildItem -LiteralPath $nsis -File | Remove-Item -Force -ErrorAction Stop }
& (Join-Path $PSScriptRoot 'build.ps1')
if (-not $?) { throw 'The build failed: nothing was signed.' }

$setupName = "ByteBroom_${version}_x64-setup.exe"
$setup = Join-Path $nsis $setupName
$sig = "$setup.sig"
if (-not (Test-Path -LiteralPath $setup)) { throw "Expected $setupName in $nsis." }

Write-Host '== Sign the installer'
$secure = Read-Host -AsSecureString 'Signing key password (typed by you, not stored)'
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    # Only the signer runs while these are set, and they are removed again below.
    $env:TAURI_SIGNING_PRIVATE_KEY_PATH = $key
    $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    cargo tauri signer sign --app-version $version $setup
    $code = $LASTEXITCODE
} finally {
    Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:TAURI_SIGNING_PRIVATE_KEY_PATH -ErrorAction SilentlyContinue
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
if ($code -ne 0 -or -not (Test-Path -LiteralPath $sig)) { throw "Signing failed (exit $code). A wrong password fails here." }

Write-Host '== latest.json'
$latest = [ordered]@{
    version   = $version
    notes     = "ByteBroom $version"
    pub_date  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    platforms = [ordered]@{
        'windows-x86_64' = [ordered]@{
            signature = (Get-Content -Raw -LiteralPath $sig).Trim()
            url       = "https://github.com/SocheatSorng/ByteBroom/releases/download/v$version/$setupName"
        }
    }
}
$latestPath = Join-Path $nsis 'latest.json'
# UTF-8 without a byte-order mark, so every JSON reader accepts it.
[IO.File]::WriteAllText($latestPath, ($latest | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))

Write-Host '== Independent check of the signature, version and URL'
node tools/verify-release.mjs $latestPath $setup
if ($LASTEXITCODE -ne 0) { throw 'The release did not verify: do not upload it.' }

Write-Host ''
Write-Host "Ready: release v$version from $commit. In the browser, draft a GitHub release with tag v$version and attach:"
foreach ($f in @($setup, $sig, $latestPath)) {
    $hash = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
    Write-Host "  $(Split-Path -Leaf $f)  SHA-256 $hash"
}
Write-Host 'Put the SHA-256 lines in the release notes. Updates reach users once the release is published (not a draft or pre-release).'
Write-Host 'Now close this PowerShell window, so the password leaves memory.'
