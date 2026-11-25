#Requires -RunAsAdministrator
# Removes ByteBroom's elevated helper from Program Files\ByteBroom (undoes install-helper.ps1).
# Only the helper file is removed, then the folder if it is empty. Run as administrator:
#     ./tools/uninstall-helper.ps1
$ErrorActionPreference = 'Stop'

$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$dest = Join-Path $programFiles 'ByteBroom'
$exe = Join-Path $dest 'bytebroom-admin.exe'

if (Test-Path -LiteralPath $dest) {
    $item = Get-Item -LiteralPath $dest -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "$dest is a link; not touching it. Remove the link by hand."
    }
}
if (Test-Path -LiteralPath $exe -PathType Leaf) {
    Remove-Item -LiteralPath $exe
    Write-Host "Removed $exe"
} else {
    Write-Host "No helper at $exe"
}
if ((Test-Path -LiteralPath $dest) -and -not (Get-ChildItem -LiteralPath $dest -Force)) {
    Remove-Item -LiteralPath $dest
    Write-Host "Removed the empty folder $dest"
}
