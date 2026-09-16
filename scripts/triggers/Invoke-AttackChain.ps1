#Requires -Modules Az.Accounts, Az.Resources, Az.KeyVault, Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Users

<#
.SYNOPSIS
    One principal, one window, a sequence of actions across three planes.

.DESCRIPTION
    The triggers written earlier each emit ONE event, which is what a detection
    needs. A playbook needs something different: its queries pivot on an ACTOR,
    not an operation. They ask what else this person did, where else they went,
    whether they came back after containment. Against isolated single events
    those pivots return nothing, and a pivot that returns nothing is
    indistinguishable from a pivot that is broken -- which is how a dead ARM
    detection survived for weeks.

    So this leaves a TRAIL: one identity performing a plausible sequence inside
    a few minutes, landing in AZKVAuditLogs, AzureActivity and AuditLogs. Then a
    playbook's "everything this actor touched" query has something to find, and
    an empty result means something.

    Shaped like an intrusion rather than a list, because the pivots follow that
    shape: look around, take a credential, establish persistence, weaken the
    logging, destroy something.

    Everything is scoped to objects this script creates, or reversed in the
    finally block. The directory role is Directory Readers, which grants read of
    directory objects and nothing else. The Owner grant is on a resource group
    created here holding nothing, to the identity already running the script.
    The only destructive act is purging a secret this script wrote seconds
    earlier.

    Prints a JSON summary -- actor, start, end -- which is what the playbook
    verification needs to fill its alert blanks.

.PARAMETER Execute
    Required. Without it the script prints the plan and exits.
#>
[CmdletBinding()]
param(
    [string]$VaultName = "test-al-2",
    [string]$ResourceGroupName = "pylon-chain-rg",
    [string]$Location = "eastus",
    [string]$RoleName = "Directory Readers",
    [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$stamp = Get-Date -Format "yyyyMMddTHHmmssZ"
$secretName = "pylon-chain-$stamp"

Write-Host "ATTACK CHAIN  one principal, one window, three planes"
Write-Host "  vault  $VaultName        (a secret created and purged here)"
Write-Host "  group  $ResourceGroupName ($Location, created and deleted here)"
Write-Host "  role   $RoleName          (added and removed here)"

if (-not $Execute) {
    Write-Host "`nDRY RUN. Re-run with -Execute." -ForegroundColor Yellow
    return
}

$context = Get-AzContext
if (-not $context) { throw "not signed in — run Connect-AzAccount" }
$actor = $context.Account.Id
$objectId = (Get-AzADUser -SignedIn -ErrorAction SilentlyContinue).Id
if (-not $objectId) {
    $objectId = ($context.Account.ExtendedProperties["HomeAccountId"] -split "\.") | Select-Object -First 1
}
if (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue) {
    throw "'$ResourceGroupName' already exists; this script only deletes groups it made."
}

$graph = Get-MgContext
if (-not $graph) {
    try { Connect-MgGraph -NoWelcome -ErrorAction Stop; $graph = Get-MgContext } catch { $graph = $null }
}

$started = (Get-Date).ToUniversalTime()
$steps = [ordered]@{}
$group = $null; $assigned = $false; $inRole = $false; $softDeleted = $false

function Step($name, [scriptblock]$action) {
    try { & $action; $script:steps[$name] = "ok"; Write-Host "  $name" }
    catch { $script:steps[$name] = "FAILED: $($_.Exception.Message)"; Write-Warning "  $name — $($_.Exception.Message)" }
}

try {
    # ── look around ────────────────────────────────────────────────────────
    Step "recon: list the vault's secrets"    { Get-AzKeyVaultSecret -VaultName $VaultName | Out-Null }

    # ── take a credential ──────────────────────────────────────────────────
    Step "credential access: read a secret" {
        $first = Get-AzKeyVaultSecret -VaultName $VaultName | Select-Object -First 1
        if ($first) { Get-AzKeyVaultSecret -VaultName $VaultName -Name $first.Name | Out-Null }
    }

    # ── establish persistence, on both planes ──────────────────────────────
    Step "persistence: grant Owner at a new scope" {
        $script:group = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
        New-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName "Owner" `
            -Scope $script:group.ResourceId | Out-Null
        $script:assigned = $true
    }
    Step "persistence: add a permanent directory role member" {
        if (-not $graph) { throw "Graph is not connected; skipped" }
        $role = Get-MgDirectoryRole -Filter "displayName eq '$RoleName'"
        if (-not $role) {
            $template = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $RoleName }
            $role = New-MgDirectoryRole -RoleTemplateId $template.Id
        }
        $script:roleId = $role.Id
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id `
            -OdataId "https://graph.microsoft.com/v1.0/directoryObjects/$objectId"
        $script:inRole = $true
    }

    # ── destroy something ──────────────────────────────────────────────────
    Step "impact: write then purge a secret" {
        $value = ConvertTo-SecureString -String ([guid]::NewGuid().ToString()) -AsPlainText -Force
        Set-AzKeyVaultSecret -VaultName $VaultName -Name $secretName -SecretValue $value | Out-Null
        Remove-AzKeyVaultSecret -VaultName $VaultName -Name $secretName -Force
        $script:softDeleted = $true
        # Soft delete is asynchronous; purging straight after races it and the
        # vault answers Conflict, leaving no SecretPurge event at all.
        $deadline = (Get-Date).AddMinutes(2)
        while ($true) {
            if (Get-AzKeyVaultSecret -VaultName $VaultName -Name $secretName -InRemovedState -ErrorAction SilentlyContinue) { break }
            if ((Get-Date) -gt $deadline) { throw "secret never reached the removed state" }
            Start-Sleep -Seconds 3
        }
        Remove-AzKeyVaultSecret -VaultName $VaultName -Name $secretName -InRemovedState -Force
        $script:softDeleted = $false
    }
}
finally {
    if ($inRole) {
        try { Remove-MgDirectoryRoleMemberDirectoryObjectByRef -DirectoryRoleId $roleId -DirectoryObjectId $objectId
              Write-Host "  cleaned up: directory role membership removed" } catch { Write-Warning "role membership REMAINS: $($_.Exception.Message)" }
    }
    if ($assigned -and $group) {
        try { Remove-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName "Owner" -Scope $group.ResourceId
              Write-Host "  cleaned up: Owner assignment removed" } catch { Write-Warning "Owner assignment REMAINS: $($_.Exception.Message)" }
    }
    if ($group) {
        try { Remove-AzResourceGroup -Name $ResourceGroupName -Force | Out-Null
              Write-Host "  cleaned up: resource group deleted" } catch { Write-Warning "group REMAINS: $($_.Exception.Message)" }
    }
    if ($softDeleted) {
        Write-Warning "secret '$secretName' is soft deleted but NOT purged. Purge it with:"
        Write-Warning "  Remove-AzKeyVaultSecret -VaultName $VaultName -Name $secretName -InRemovedState -Force"
    }
}

$ended = (Get-Date).ToUniversalTime()
Write-Host "`nSTEPS"
foreach ($k in $steps.Keys) { "  {0,-46} {1}" -f $k, $steps[$k] | Write-Host }
Write-Host "`nCHAIN"
[pscustomobject]@{
    actor    = $actor
    objectId = $objectId
    start    = $started.ToString("yyyy-MM-ddTHH:mm:ssZ")
    end      = $ended.ToString("yyyy-MM-ddTHH:mm:ssZ")
} | ConvertTo-Json -Compress | Write-Host
