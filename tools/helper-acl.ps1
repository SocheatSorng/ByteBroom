# The helper's admin-owned rule (crates/core/src/admin.rs, Place::Own), written again in PowerShell
# for tools/install-helper.ps1. It only reads permissions, so it runs without administrator
# rights; crates/core/tests/admin.rs checks that it agrees with the Rust rule on real files.
#     . ./tools/helper-acl.ps1; Get-AdminOwnedProblem 'C:\Windows\System32\cmd.exe'
# Returns $null when only SYSTEM, Administrators and TrustedInstaller own or can change the item.

function Get-AdminOwnedProblem([string]$Path) {
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    # Write, append, write-EA, delete-child, write-attributes, delete, write-DAC, write-owner,
    # maximum-allowed, generic-all, generic-write.
    $dangerous = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x2000000 -bor 0x10000000 -bor 0x40000000
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return "$Path is a link" }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($trusted -notcontains $owner) { return "$Path is owned by $owner" }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        $sid = $rule.IdentityReference.Value
        if ($trusted -contains $sid) { continue }
        if ([int64]$rule.FileSystemRights -band $dangerous) {
            return "$Path can be changed by $sid ($($rule.FileSystemRights))"
        }
    }
    return $null
}
