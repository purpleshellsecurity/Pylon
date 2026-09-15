#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users

<#
.SYNOPSIS
    Emit one real "Add member to role outside of PIM (permanent)" AuditLogs event.

.DESCRIPTION
    Produces the telemetry the Entra RoleManagement detection matches, so the
    detection can be tested against a row Azure actually wrote rather than one
    we guessed the shape of.

    The detection filters on Category, OperationName and Result only -- it does
    NOT filter by how privileged the role is. So this uses the least privileged
    directory role that still produces the operation. Nothing here grants
    administrative access.

    The membership is REMOVED in the finally block. The audit event survives the
    removal, which is the point: the event is the artifact, not the assignment.

.PARAMETER UserPrincipalName
    An existing user to add and then remove. Use a disposable lab account.

.PARAMETER RoleName
    Directory role to use. Defaults to Directory Readers, which grants read of
    directory objects and nothing else.

.PARAMETER Execute
    Required. Without it the script prints what it would do and exits, so a
    stray run cannot change the directory.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [string]$RoleName = "Directory Readers",
    [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "TRIGGER  Entra / AuditLogs / Add member to role outside of PIM (permanent)"
Write-Host "  user   $UserPrincipalName"
Write-Host "  role   $RoleName"

if (-not $Execute) {
    Write-Host "`nDRY RUN. Re-run with -Execute to emit the event." -ForegroundColor Yellow
    return
}

Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory","User.Read.All" -NoWelcome

$user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'"
if (-not $user) { throw "no user '$UserPrincipalName' in this tenant" }

# A directory role must be ACTIVATED before it can hold members; an inactive one
# exists only as a template and Get-MgDirectoryRole will not return it.
$role = Get-MgDirectoryRole -Filter "displayName eq '$RoleName'"
if (-not $role) {
    $template = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $RoleName }
    if (-not $template) { throw "no directory role or template named '$RoleName'" }
    Write-Host "  activating role template $($template.Id)"
    $role = New-MgDirectoryRole -RoleTemplateId $template.Id
}

$added = $false
try {
    New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id `
        -OdataId "https://graph.microsoft.com/v1.0/directoryObjects/$($user.Id)"
    $added = $true
    Write-Host "  ✅ member added — AuditLogs event emitted" -ForegroundColor Green
    Write-Host "  ingestion lag is typically 2-5 minutes before the row is queryable"
}
finally {
    if ($added) {
        Remove-MgDirectoryRoleMemberDirectoryObjectByRef `
            -DirectoryRoleId $role.Id -DirectoryObjectId $user.Id
        Write-Host "  cleaned up: membership removed (the audit event remains)"
    }
}
