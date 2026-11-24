<#
.SYNOPSIS
  Independent checker for ByteBroom's tests: snapshots a folder tree and compares two snapshots.

.DESCRIPTION
  Written in PowerShell on purpose, so the Rust engine is not the only judge of what it changed.
  Records every entry's relative path, kind, size and SHA-256. Links and junctions are recorded
  with their target but never entered.

  Snapshot:  ./verify-tree.ps1 -Snapshot -Path <folder> -Out <file.json>
  Compare:   ./verify-tree.ps1 -Compare -Before <a.json> -After <b.json>
             Exit 0 when identical; exit 1 and one line per difference otherwise.

  Only meant for test folders in a temp directory.
#>
[CmdletBinding(DefaultParameterSetName = 'Snapshot')]
param(
    [Parameter(ParameterSetName = 'Snapshot', Mandatory)] [switch] $Snapshot,
    [Parameter(ParameterSetName = 'Snapshot', Mandatory)] [string] $Path,
    [Parameter(ParameterSetName = 'Snapshot', Mandatory)] [string] $Out,
    [Parameter(ParameterSetName = 'Compare', Mandatory)] [switch] $Compare,
    [Parameter(ParameterSetName = 'Compare', Mandatory)] [string] $Before,
    [Parameter(ParameterSetName = 'Compare', Mandatory)] [string] $After
)
$ErrorActionPreference = 'Stop'

function Get-Sha256([string] $File) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::Open($File, 'Open', 'Read', 'ReadWrite, Delete')
    } catch {
        # Held open without sharing (the fixture's locked file): existence and size still count.
        $sha.Dispose()
        return 'unreadable'
    }
    try { return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '') }
    finally { $stream.Dispose(); $sha.Dispose() }
}

function Read-Snapshot([string] $File) {
    # PowerShell 5.1's ConvertFrom-Json emits a JSON array as ONE object; assign it first so
    # foreach enumerates the entries.
    $list = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($File))
    $map = @{}
    foreach ($e in $list) { $map[[string]$e.path] = $e }
    return $map
}

function Get-Entries([string] $Root) {
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $result = New-Object System.Collections.Generic.List[object]
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($rootFull)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries($dir)) {
            $info = New-Object System.IO.FileInfo($entry)
            $attrs = [System.IO.File]::GetAttributes($entry)
            $rel = $entry.Substring($rootFull.Length + 1)
            $isLink = ($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            $isDir = ($attrs -band [System.IO.FileAttributes]::Directory) -ne 0
            if ($isLink) {
                $target = (Get-Item -LiteralPath $entry -Force).Target
                $result.Add([pscustomobject]@{ path = $rel; kind = 'link'; size = 0; hash = "$target" })
            } elseif ($isDir) {
                $result.Add([pscustomobject]@{ path = $rel; kind = 'dir'; size = 0; hash = '' })
                $stack.Push($entry)
            } else {
                $result.Add([pscustomobject]@{ path = $rel; kind = 'file'; size = $info.Length; hash = (Get-Sha256 $entry) })
            }
        }
    }
    return $result | Sort-Object path
}

if ($Snapshot) {
    $entries = @(Get-Entries $Path)
    $json = ConvertTo-Json -InputObject $entries -Depth 3
    [System.IO.File]::WriteAllText($Out, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Output "snapshot: $($entries.Count) entries"
    exit 0
}

$a = Read-Snapshot $Before
$b = Read-Snapshot $After
$diffs = New-Object System.Collections.Generic.List[string]
foreach ($k in $a.Keys) {
    if (-not $b.ContainsKey($k)) { $diffs.Add("removed: $k"); continue }
    $x = $a[$k]; $y = $b[$k]
    if ($x.kind -ne $y.kind -or $x.size -ne $y.size -or $x.hash -ne $y.hash) { $diffs.Add("changed: $k") }
}
foreach ($k in $b.Keys) { if (-not $a.ContainsKey($k)) { $diffs.Add("added: $k") } }
if ($diffs.Count -eq 0) { Write-Output 'identical'; exit 0 }
$diffs | Sort-Object | ForEach-Object { Write-Output $_ }
exit 1
