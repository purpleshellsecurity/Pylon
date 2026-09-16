#Requires -Modules Az.Accounts, Az.Resources

<#
.SYNOPSIS
    Emit one real MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE AzureActivity
    event carrying role "Owner".

.DESCRIPTION
    Produces the telemetry the ARM roleAssignments detection matches. That
    detection requires the role to be Owner, so a lesser role will not trigger
    it and there is no safer substitute that still exercises the query.

    The blast radius is bounded instead. The grant is scoped to a resource group
    this script CREATES and deletes, holding nothing, and the grantee is the
    identity already running the script -- so no principal ends the run with
    access it did not start with. The assignment is removed and the group
    deleted in the finally block.

    The AzureActivity event survives both, which is the point.

.PARAMETER ResourceGroupName
    Disposable group to create. Must not already exist: the script refuses to
    touch a group it did not make, and deletes what it made.

.PARAMETER Location
    Azure region for the throwaway group.

.PARAMETER Execute
    Required. Without it the script prints the plan and exits.
#>
[CmdletBinding()]
param(
    [string]$ResourceGroupName = "pylon-trigger-rg",
    [string]$Location = "eastus",
    [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "TRIGGER  ARM / AzureActivity / ROLEASSIGNMENTS/WRITE (role Owner)"
Write-Host "  scope  resource group $ResourceGroupName ($Location), created and deleted here"
Write-Host "  grantee the identity running this script"

if (-not $Execute) {
    Write-Host "`nDRY RUN. Re-run with -Execute to emit the event." -ForegroundColor Yellow
    return
}

$context = Get-AzContext
if (-not $context) { throw "not signed in — run Connect-AzAccount" }

$existing = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if ($existing) {
    throw "resource group '$ResourceGroupName' already exists; this script only " +
          "deletes groups it created. Pass a different -ResourceGroupName."
}

# The signed-in identity. `Get-AzADUser -SignedIn` is the direct answer but only
# exists for a user principal, so a service-principal context falls back to the
# object id on the front of HomeAccountId ("<objectId>.<tenantId>"). Both were
# checked against this tenant and agree.
$objectId = (Get-AzADUser -SignedIn -ErrorAction SilentlyContinue).Id
if (-not $objectId) {
    $objectId = ($context.Account.ExtendedProperties["HomeAccountId"] -split "\.") | Select-Object -First 1
}
if (-not $objectId) { throw "could not determine the signed-in object id" }

$group = $null
$assignment = $null
try {
    $group = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
    Write-Host "  created $($group.ResourceId)"

    $assignment = New-AzRoleAssignment -ObjectId $objectId `
        -RoleDefinitionName "Owner" -Scope $group.ResourceId
    Write-Host "  ✅ Owner granted at the group scope — AzureActivity event emitted" -ForegroundColor Green
    Write-Host "  ingestion lag is typically 1-5 minutes before the row is queryable"
}
finally {
    if ($assignment) {
        Remove-AzRoleAssignment -ObjectId $objectId `
            -RoleDefinitionName "Owner" -Scope $group.ResourceId
        Write-Host "  cleaned up: role assignment removed"
    }
    if ($group) {
        Remove-AzResourceGroup -Name $ResourceGroupName -Force | Out-Null
        Write-Host "  cleaned up: resource group deleted (the activity event remains)"
    }
}
