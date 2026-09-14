#Requires -Modules Az.Accounts, Az.Automation

<#
.SYNOPSIS
    Exercise the Automation account surface so AzureDiagnostics has rows to grade.

.DESCRIPTION
    A lab automation account emits almost nothing. Measured before this: the only
    activity in thirty days was a runbook being created, run and deleted, so a
    generated detection for a webhook, a schedule or a credential asset had no
    event to grade against and shipped unproven.

    This creates and removes one of each asset type. Every object it touches it
    made, every name carries a run stamp, and nothing that existed before the run
    is read, modified or deleted.

    Emits, per asset: a Create AuditEvent and a Delete AuditEvent, both under
    Category "AuditEvent" with targetResources_Resource_s naming the kind.

    WHAT THE ROWS LOOK LIKE, and why a detection must be told:
      clientInfo_PrincipalName_s and clientInfo_IpAddress_s are REDACTED to the
      literal string "{scrubbed}" on every audit event. Only
      clientInfo_ObjectId_g carries the caller. _ResourceId is the ACCOUNT, not
      the asset; the asset is in targetResources_RunbookName_s.

.PARAMETER AccountName
    A LAB automation account. Diagnostic settings must send AuditEvent to the
    workspace, or the operations happen and nothing is logged.

.PARAMETER Execute
    Required. Without it the script prints the plan and exits.

.PARAMETER KeepObjects
    Leave the assets behind. Off by default, and leaving them on means the
    Delete audit events are never emitted.

.EXAMPLE
    ./Invoke-AutomationSurfaceTrigger.ps1 -AccountName my-lab-automation -Execute
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AccountName,
    [string]$ResourceGroupName,
    [switch]$Execute,
    [switch]$KeepObjects
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$stamp  = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$suffix = ($stamp -replace '[^0-9]', '')
$names  = @{
    Variable   = "pylon-var-$suffix"
    Credential = "pylon-cred-$suffix"
    Schedule   = "pylon-sched-$suffix"
    Connection = "pylon-conn-$suffix"
}

Write-Host "TRIGGER  Automation account surface"
Write-Host "  account  $AccountName"
Write-Host "  assets   $($names.Values -join ', ')"

if (-not $Execute) {
    Write-Host "`nDRY RUN. Re-run with -Execute to emit the events." -ForegroundColor Yellow
    return
}

if (-not $ResourceGroupName) {
    $acct = Get-AzAutomationAccount | Where-Object AutomationAccountName -eq $AccountName |
        Select-Object -First 1
    if (-not $acct) { throw "no automation account named '$AccountName' in reach" }
    $ResourceGroupName = $acct.ResourceGroupName
}
Write-Host "  group    $ResourceGroupName"
$common = @{ ResourceGroupName = $ResourceGroupName; AutomationAccountName = $AccountName }

$made = [System.Collections.ArrayList]::new()
function Note($kind, $name) { [void]$made.Add(@{ Kind = $kind; Name = $name }) }

try {
    Write-Host "`n  CREATE  (each of these is an AuditEvent with OperationName 'Create')"

    New-AzAutomationVariable @common -Name $names.Variable -Value "pylon-trigger" `
        -Encrypted $false | Out-Null
    Note 'Variable' $names.Variable; Write-Host "    Variable    $($names.Variable)"

    # A random GUID, never a real or plausible credential. Deleted below.
    $secret = ConvertTo-SecureString ([guid]::NewGuid().ToString()) -AsPlainText -Force
    $cred   = [pscredential]::new("pylon-trigger-user", $secret)
    New-AzAutomationCredential @common -Name $names.Credential -Value $cred | Out-Null
    Note 'Credential' $names.Credential; Write-Host "    Credential  $($names.Credential)"

    # One-time, an hour out, so it never actually fires.
    New-AzAutomationSchedule @common -Name $names.Schedule -OneTime `
        -StartTime (Get-Date).AddHours(1) | Out-Null
    Note 'Schedule' $names.Schedule; Write-Host "    Schedule    $($names.Schedule)"

    Write-Host "`n  UPDATE  (OperationName 'Update')"
    Set-AzAutomationVariable @common -Name $names.Variable -Value "pylon-trigger-updated" `
        -Encrypted $false | Out-Null
    Write-Host "    Variable    updated"
}
finally {
    if ($KeepObjects) {
        Write-Warning "-KeepObjects set: no Delete events were emitted, and these remain:"
        foreach ($m in $made) { Write-Warning "  $($m.Kind) $($m.Name)" }
    }
    else {
        Write-Host "`n  DELETE  (each of these is an AuditEvent with OperationName 'Delete')"
        foreach ($m in $made) {
            try {
                switch ($m.Kind) {
                    'Variable'   { Remove-AzAutomationVariable @common -Name $m.Name }
                    'Credential' { Remove-AzAutomationCredential @common -Name $m.Name }
                    'Schedule'   { Remove-AzAutomationSchedule @common -Name $m.Name -Force }
                    'Connection' { Remove-AzAutomationConnection @common -Name $m.Name -Force }
                }
                Write-Host "    removed $($m.Kind) $($m.Name)"
            }
            catch {
                Write-Warning "could not remove $($m.Kind) '$($m.Name)': $($_.Exception.Message)"
            }
        }
    }
    Write-Host "`n  ingestion lag is about 5 minutes before these rows are queryable"
}
