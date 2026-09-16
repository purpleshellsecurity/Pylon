#Requires -Modules Az.Accounts, Az.Resources

<#
.SYNOPSIS
    Execute a playbook's Azure containment blocks against a disposable target.

.DESCRIPTION
    The PowerShell in a playbook is what a responder runs at 3am, and it had
    only ever been PARSE checked -- every cmdlet and parameter resolves against
    the installed modules and not one had been executed. Parse checking cannot
    see a logic error: the Key Vault trigger raced its own soft delete and
    passed every static gate.

    So these run for real, against a resource group this script creates and
    deletes. The role assignment removed is one this script made seconds
    earlier, on a group holding nothing, granted to the identity already running
    it. Nothing that existed before the run is touched.

    Covers the two Azure containment shapes the playbooks emit:
      Remove-AzRoleAssignment   undo the grant
      New-AzResourceLock        freeze the resource

    NOT covered: the Microsoft Graph blocks, which disable an account and revoke
    its sessions. Those need a Graph session and a disposable user, and are a
    separate decision.

.PARAMETER Execute
    Required. Without it the script prints the plan and exits.
#>
[CmdletBinding()]
param(
    [string]$ResourceGroupName = "pylon-containment-test",
    [string]$Location = "eastus",
    [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "CONTAINMENT TEST  playbook PowerShell, executed against a disposable group"
Write-Host "  group  $ResourceGroupName ($Location), created and deleted here"

if (-not $Execute) {
    Write-Host "`nDRY RUN. Re-run with -Execute." -ForegroundColor Yellow
    return
}

$context = Get-AzContext
if (-not $context) { throw "not signed in — run Connect-AzAccount" }
if (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue) {
    throw "'$ResourceGroupName' already exists; this script only deletes groups it made."
}

$objectId = (Get-AzADUser -SignedIn -ErrorAction SilentlyContinue).Id
if (-not $objectId) {
    $objectId = ($context.Account.ExtendedProperties["HomeAccountId"] -split "\.") | Select-Object -First 1
}

$results = [ordered]@{}
$group = $null
try {
    $group = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
    $scope = $group.ResourceId
    Write-Host "  created $scope"

    # ---- shape 1: undo the grant -------------------------------------------
    New-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName "Reader" -Scope $scope | Out-Null
    Write-Host "  seeded a Reader assignment to remove"
    try {
        Remove-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName "Reader" -Scope $scope
        $still = Get-AzRoleAssignment -ObjectId $objectId -Scope $scope -ErrorAction SilentlyContinue |
                 Where-Object { $_.RoleDefinitionName -eq "Reader" -and $_.Scope -eq $scope }
        $results["Remove-AzRoleAssignment"] = if ($still) { "RAN but the assignment REMAINS" } else { "ok" }
    } catch {
        $results["Remove-AzRoleAssignment"] = "FAILED: $($_.Exception.Message)"
    }

    # ---- shape 2: freeze the resource --------------------------------------
    try {
        New-AzResourceLock -LockName "ir-hold" -LockLevel CanNotDelete -Scope $scope -Force | Out-Null
        $lock = Get-AzResourceLock -LockName "ir-hold" -Scope $scope -ErrorAction SilentlyContinue
        $results["New-AzResourceLock"] = if ($lock) { "ok" } else { "RAN but no lock exists" }
        if ($lock) {
            Remove-AzResourceLock -LockName "ir-hold" -Scope $scope -Force | Out-Null
            Write-Host "  lock removed so the group can be deleted"
        }
    } catch {
        $results["New-AzResourceLock"] = "FAILED: $($_.Exception.Message)"
    }
}
finally {
    if ($group) {
        # A CanNotDelete lock left in place makes the group undeletable, so the
        # lock is removed above before this runs. If that failed, say so loudly
        # rather than leaving a group nobody can remove.
        try {
            Remove-AzResourceGroup -Name $ResourceGroupName -Force | Out-Null
            Write-Host "  cleaned up: resource group deleted"
        } catch {
            Write-Warning "could not delete '$ResourceGroupName': $($_.Exception.Message)"
            Write-Warning "check for a remaining lock: Get-AzResourceLock -Scope $($group.ResourceId)"
        }
    }
}

Write-Host "`nRESULTS"
foreach ($k in $results.Keys) { "  {0,-26} {1}" -f $k, $results[$k] | Write-Host }
