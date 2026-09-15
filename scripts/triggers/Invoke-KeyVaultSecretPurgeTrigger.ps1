#Requires -Modules Az.Accounts, Az.KeyVault

<#
.SYNOPSIS
    Emit one real SecretPurge event into AZKVAuditLogs.

.DESCRIPTION
    Produces the telemetry the Key Vault SecretPurge detection matches.

    SecretPurge is irreversible by definition -- the operation catalogue records
    "Recovery: NONE" -- so this script never purges a secret it did not create.
    It writes a secret under a name stamped with the current UTC time, soft
    deletes it, then purges that. Nothing that existed before the run is
    touched, and the value written is a random GUID rather than anything
    resembling a credential.

    Requires purge protection to be DISABLED on the vault. With it enabled the
    purge cannot happen at all, which the script checks up front and says
    plainly rather than failing inside the operation.

.PARAMETER VaultName
    The vault to write to. Use a lab vault.

.PARAMETER Execute
    Required. Without it the script prints the plan and exits.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VaultName,
    [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$secretName = "pylon-trigger-{0}" -f (Get-Date -Format "yyyyMMddTHHmmssZ")

Write-Host "TRIGGER  Key Vault / AZKVAuditLogs / SecretPurge"
Write-Host "  vault  $VaultName"
Write-Host "  secret $secretName  (created by this run, purged by this run)"

if (-not $Execute) {
    Write-Host "`nDRY RUN. Re-run with -Execute to emit the event." -ForegroundColor Yellow
    return
}

$vault = Get-AzKeyVault -VaultName $VaultName
if (-not $vault) { throw "no vault named '$VaultName' in reach" }
if ($vault.EnablePurgeProtection) {
    throw "purge protection is enabled on '$VaultName', so SecretPurge cannot " +
          "occur there. Use a lab vault without it; do not disable it on a " +
          "vault that holds anything."
}

$created = $false
$softDeleted = $false
try {
    $value = ConvertTo-SecureString -String ([guid]::NewGuid().ToString()) -AsPlainText -Force
    Set-AzKeyVaultSecret -VaultName $VaultName -Name $secretName -SecretValue $value | Out-Null
    $created = $true
    Write-Host "  created secret (SecretSet event)"

    Remove-AzKeyVaultSecret -VaultName $VaultName -Name $secretName -Force
    $softDeleted = $true
    Write-Host "  soft deleted (SecretDelete event)"

    # Soft delete is ASYNCHRONOUS. Purging straight after it returns races the
    # deletion and the vault answers:
    #     Conflict  Message: Secret is currently being deleted.
    # which leaves the secret soft deleted and the SecretPurge event unwritten,
    # so the run looks like a trigger failure rather than a timing one. Wait for
    # the secret to actually appear in the removed state before purging it.
    $deadline = (Get-Date).AddMinutes(2)
    while ($true) {
        $removed = Get-AzKeyVaultSecret -VaultName $VaultName -Name $secretName `
            -InRemovedState -ErrorAction SilentlyContinue
        if ($removed) { break }
        if ((Get-Date) -gt $deadline) {
            throw "secret did not reach the removed state within 2 minutes"
        }
        Start-Sleep -Seconds 3
    }
    Write-Host "  confirmed in removed state"

    Remove-AzKeyVaultSecret -VaultName $VaultName -Name $secretName -InRemovedState -Force
    $softDeleted = $false
    Write-Host "  ✅ purged — SecretPurge event emitted" -ForegroundColor Green
    Write-Host "  ingestion lag is typically 5-10 minutes before the row is queryable"
}
finally {
    # Only reachable if the purge itself failed: the secret is sitting in the
    # soft-deleted state and would linger for the vault's retention period.
    if ($softDeleted) {
        Write-Warning "secret '$secretName' is soft deleted but NOT purged. Purge it with:"
        Write-Warning "  Remove-AzKeyVaultSecret -VaultName $VaultName -Name $secretName -InRemovedState -Force"
    }
    elseif ($created -and -not $softDeleted) {
        Write-Host "  nothing left behind"
    }
}
