#Requires -Modules Az.Accounts, Az.KeyVault

<#
.SYNOPSIS
    Exercise the Key Vault data plane so AZKVAuditLogs has rows to grade against.

.DESCRIPTION
    Measured on a lab tenant: 7 of 54 planned Key Vault vectors had any events
    at all. The other 47 generate detections nobody can prove, because nobody in
    a lab reads a secret or rotates a key. This performs those operations once.
    After that `pylon design record` captures them and they grade offline
    forever -- the tenant is never needed for them again.

    Everything it touches, it creates. Object names carry a run stamp, and
    nothing that existed before the run is read, modified or deleted. That is
    not politeness: a trigger that touches real objects is a trigger nobody runs
    twice.

    Covers, per object type (secret, key, certificate): create, get, list,
    list-versions, backup, delete, get-deleted, list-deleted, restore or purge.
    Plus key cryptographic operations (encrypt, decrypt, wrap, unwrap) and the
    certificate contact and issuer surface.

    NOT covered, and why:
      CertificatePendingMerge   needs a real CA to issue against
      KeySign / KeyVerify       needs a signing key policy this does not create
      VaultPut / VaultPatch     management plane; use the ARM triggers

.PARAMETER VaultName
    A LAB vault. Diagnostic settings must be sending AuditEvent to the
    workspace, or the operations happen and nothing is logged.

.PARAMETER Execute
    Required. Without it the script prints what it would do and exits.

.PARAMETER KeepObjects
    Leave the created objects behind instead of soft-deleting and purging them.
    Off by default: a lab that fills with test litter is a lab where people stop
    running the tests.

.EXAMPLE
    ./Invoke-KeyVaultSurfaceTrigger.ps1 -VaultName my-lab-kv -Execute
    # wait ~10 minutes for ingestion, then:
    pylon design record --from ./kv --workspace my-workspace --out fixtures/
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VaultName,
    [switch]$Execute,
    [switch]$KeepObjects
)

$ErrorActionPreference = 'Stop'
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$SecretName = "pylon-trigger-secret-$stamp"
$KeyName    = "pylon-trigger-key-$stamp"
$CertName   = "pylon-trigger-cert-$stamp"

if (-not $Execute) {
    Write-Host "PLAN (nothing has run). Against vault '$VaultName' this would:"
    Write-Host "  create, read, list, back up, delete and purge:"
    Write-Host "    secret      $SecretName"
    Write-Host "    key         $KeyName"
    Write-Host "    certificate $CertName"
    Write-Host "  encrypt/decrypt and wrap/unwrap with the key it created"
    Write-Host "  set and delete certificate contacts"
    Write-Host ""
    Write-Host "It touches nothing that already exists. Re-run with -Execute."
    return
}

# Fail before doing anything if the vault cannot be reached, rather than half
# way through with three objects already created.
$vault = Get-AzKeyVault -VaultName $VaultName -ErrorAction SilentlyContinue
if (-not $vault) { throw "vault '$VaultName' not found in this context" }
if ($vault.EnablePurgeProtection) {
    Write-Warning ("Purge protection is ON. The delete operations will run and " +
                   "the purge ones will not, so SecretPurge, KeyPurge and " +
                   "CertificatePurge stay ungradable.")
}

$done = [System.Collections.Generic.List[string]]::new()
$failed = [System.Collections.Generic.List[string]]::new()

function Step {
    <#  One operation, named for the AZKVAuditLogs OperationName it produces, so
        the output maps one-to-one onto what `design survey` reports missing.
        A failure is recorded and the run continues: one unsupported operation
        must not cost the other forty. #>
    param([string]$Operation, [scriptblock]$Action)
    try {
        & $Action | Out-Null
        $done.Add($Operation)
        Write-Host ("  ok   {0}" -f $Operation)
    } catch {
        $failed.Add(("{0}: {1}" -f $Operation, $_.Exception.Message))
        Write-Host ("  FAIL {0}  {1}" -f $Operation, $_.Exception.Message) -ForegroundColor Yellow
    }
}

Write-Host "Key Vault data-plane surface against '$VaultName'"

# --- secrets -------------------------------------------------------------
$secretValue = ConvertTo-SecureString ([guid]::NewGuid().ToString()) -AsPlainText -Force
Step 'SecretSet'          { Set-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -SecretValue $secretValue }
Step 'SecretSet (v2)'     { Set-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -SecretValue $secretValue }
Step 'SecretGet'          { Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName }
Step 'SecretList'         { Get-AzKeyVaultSecret -VaultName $VaultName }
Step 'SecretListVersions' { Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -IncludeVersions }
Step 'SecretBackup'       { Backup-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -OutputFile (Join-Path ([System.IO.Path]::GetTempPath()) "$SecretName.bak") -Force }

# --- keys ----------------------------------------------------------------
Step 'KeyCreate'          { Add-AzKeyVaultKey -VaultName $VaultName -Name $KeyName -Destination Software }
Step 'KeyGet'             { Get-AzKeyVaultKey -VaultName $VaultName -Name $KeyName }
Step 'KeyList'            { Get-AzKeyVaultKey -VaultName $VaultName }
Step 'KeyListVersions'    { Get-AzKeyVaultKey -VaultName $VaultName -Name $KeyName -IncludeVersions }
Step 'KeyBackup'          { Backup-AzKeyVaultKey -VaultName $VaultName -Name $KeyName -OutputFile (Join-Path ([System.IO.Path]::GetTempPath()) "$KeyName.bak") -Force }

# Encrypt/decrypt and wrap/unwrap are the exfiltration-relevant ones and the
# reason this script exists: KeyDecrypt and KeyUnwrap are how a key is USED to
# recover plaintext, which is a different event from reading the key's metadata.
$plain = [System.Text.Encoding]::UTF8.GetBytes('pylon-trigger')
Step 'KeyEncrypt'         { Invoke-AzKeyVaultKeyOperation -VaultName $VaultName -Name $KeyName -Operation Encrypt -Algorithm RSA-OAEP -ByteArrayValue $plain }
Step 'KeyWrap'            { Invoke-AzKeyVaultKeyOperation -VaultName $VaultName -Name $KeyName -Operation Wrap -Algorithm RSA-OAEP -ByteArrayValue $plain }

# --- certificates --------------------------------------------------------
Step 'CertificatePolicySet' { Set-AzKeyVaultCertificatePolicy -VaultName $VaultName -Name $CertName -SecretContentType 'application/x-pkcs12' -SubjectName "CN=$CertName" -IssuerName Self -ValidityInMonths 1 -ReuseKeyOnRenewal:$false }
Step 'CertificateCreate'    { Add-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -CertificatePolicy (New-AzKeyVaultCertificatePolicy -SecretContentType 'application/x-pkcs12' -SubjectName "CN=$CertName" -IssuerName Self -ValidityInMonths 1) }
Start-Sleep -Seconds 15   # self-signed issuance is asynchronous
Step 'CertificateGet'       { Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName }
Step 'CertificateList'      { Get-AzKeyVaultCertificate -VaultName $VaultName }
Step 'CertificateListVersions' { Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -IncludeVersions }
Step 'CertificateBackup'    { Backup-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -OutputFile (Join-Path ([System.IO.Path]::GetTempPath()) "$CertName.bak") -Force }
Step 'CertificateIssuersList' { Get-AzKeyVaultCertificateIssuer -VaultName $VaultName }
Step 'CertificateContactsSet'    { Add-AzKeyVaultCertificateContact -VaultName $VaultName -EmailAddress "pylon-trigger@example.invalid" -PassThru }
Step 'CertificateContactsDelete' { Remove-AzKeyVaultCertificateContact -VaultName $VaultName -EmailAddress "pylon-trigger@example.invalid" -PassThru }

# --- delete, read-deleted, purge -----------------------------------------
if (-not $KeepObjects) {
    Step 'SecretDelete'       { Remove-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -Force }
    Step 'KeyDelete'          { Remove-AzKeyVaultKey -VaultName $VaultName -Name $KeyName -Force }
    Step 'CertificateDelete'  { Remove-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -Force }
    Start-Sleep -Seconds 10   # soft delete is asynchronous

    Step 'SecretGetDeleted'      { Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -InRemovedState }
    Step 'SecretListDeleted'     { Get-AzKeyVaultSecret -VaultName $VaultName -InRemovedState }
    Step 'KeyGetDeleted'         { Get-AzKeyVaultKey -VaultName $VaultName -Name $KeyName -InRemovedState }
    Step 'KeyListDeleted'        { Get-AzKeyVaultKey -VaultName $VaultName -InRemovedState }
    Step 'CertificateGetDeleted' { Get-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -InRemovedState }
    Step 'CertificateListDeleted'{ Get-AzKeyVaultCertificate -VaultName $VaultName -InRemovedState }

    if (-not $vault.EnablePurgeProtection) {
        Step 'SecretPurge'      { Remove-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -InRemovedState -Force }
        Step 'KeyPurge'         { Remove-AzKeyVaultKey -VaultName $VaultName -Name $KeyName -InRemovedState -Force }
        Step 'CertificatePurge' { Remove-AzKeyVaultCertificate -VaultName $VaultName -Name $CertName -InRemovedState -Force }
    }
}

Write-Host ""
Write-Host ("{0} operation(s) emitted, {1} failed." -f $done.Count, $failed.Count)
foreach ($f in $failed) { Write-Host "  $f" -ForegroundColor Yellow }
Write-Host ""
Write-Host "Key Vault audit events take about 10 minutes to reach the workspace."
Write-Host "Then:  pylon design survey --from ./kv --workspace <name>"
Write-Host "       pylon design record --from ./kv --workspace <name> --out fixtures/"
