# Shared by build.ps1 and release.ps1 (phase 6, security review S6 and S7). Dot-source it:
#     . (Join-Path $PSScriptRoot 'tools\build-common.ps1')

# Release binaries would otherwise carry your Windows user folder in their panic messages (the
# cargo registry's source paths): replace it with "~" in everything rustc builds.
function Set-NoProfilePathsInBinaries {
    $env:RUSTFLAGS = "--remap-path-prefix=$($env:USERPROFILE)=~"
}

# Copy the just-built helper to where Tauri packs it from, and fail loudly if that didn't work:
# a stale staged helper must never end up in an installer.
function Copy-StagedHelper([string]$Root) {
    $built = Join-Path $Root 'target\release\bytebroom-admin.exe'
    $binaries = Join-Path $Root 'src-tauri\binaries'
    $staged = Join-Path $binaries 'bytebroom-admin-x86_64-pc-windows-msvc.exe'
    New-Item -ItemType Directory -Force -Path $binaries -ErrorAction Stop | Out-Null
    Copy-Item -LiteralPath $built -Destination $staged -Force -ErrorAction Stop
    Assert-StagedHelperMatches $Root
}

# The staged helper is byte-for-byte the one just built.
function Assert-StagedHelperMatches([string]$Root) {
    $built = Join-Path $Root 'target\release\bytebroom-admin.exe'
    $staged = Join-Path $Root 'src-tauri\binaries\bytebroom-admin-x86_64-pc-windows-msvc.exe'
    $a = (Get-FileHash -LiteralPath $built -Algorithm SHA256 -ErrorAction Stop).Hash
    $b = (Get-FileHash -LiteralPath $staged -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($a -ne $b) { throw 'The staged helper is not the one just built. Nothing was packed; run the build again.' }
}

# Fail if a binary still names your user folder (in ANSI or UTF-16 text). Never prints the path.
function Assert-NoProfilePath([string]$File) {
    $bytes = [IO.File]::ReadAllBytes($File)
    $needles = @($env:USERPROFILE, ($env:USERPROFILE -replace '\\', '/'))
    $texts = @(
        [Text.Encoding]::GetEncoding(28591).GetString($bytes),
        [Text.Encoding]::Unicode.GetString($bytes),
        [Text.Encoding]::Unicode.GetString($bytes, 1, $bytes.Length - 1)
    )
    foreach ($text in $texts) {
        foreach ($needle in $needles) {
            if ($text.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw "$(Split-Path -Leaf $File) contains your user folder's path. Don't publish it; tell Claude."
            }
        }
    }
}
