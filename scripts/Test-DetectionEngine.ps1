#Requires -Version 7.0
<#
.SYNOPSIS
    Run pylon across a matrix of tracks unattended and print one
    pass/fail summary — so you don't babysit each slow run.

.DESCRIPTION
    Runs a set of `pylon` invocations back to back, each into its own
    output folder, parses the run.json it produces, and prints a table of
    target / valid / invalid / self-corrected / duration. Full per-run output is
    tee'd to a .log next to the reports. Exits non-zero if any run failed to
    complete or produced an invalid detection.

    Assumes the provider is already configured (e.g. via `pylon --setup`)
    — these are real model calls and cost money. Use -ListOnly to preview the
    matrix without running anything.

.PARAMETER OutputDir
    Root folder for this test run's reports/logs. Default: ./test-reports.

.PARAMETER Full
    Run the full matrix (7 tracks) instead of the core subset (3).

.PARAMETER Only
    Run only cases whose label contains one of these substrings (e.g. -Only graph,defender).

.PARAMETER ListOnly
    Print the matrix that WOULD run and exit — no model calls, no cost.

.EXAMPLE
    ./scripts/Test-DetectionEngine.ps1            # core 3-track smoke
.EXAMPLE
    ./scripts/Test-DetectionEngine.ps1 -Full      # full 7-track matrix
.EXAMPLE
    ./scripts/Test-DetectionEngine.ps1 -Only graph -ListOnly
#>
[CmdletBinding()]
param(
    [string]$OutputDir = 'test-reports',
    [switch]$Full,
    [string[]]$Only,
    [switch]$ListOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Write-Step { param([string]$m) Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "  OK  $m" -ForegroundColor Green }
function Write-Bad  { param([string]$m) Write-Host "  !!  $m" -ForegroundColor Red }

# --- Test matrix. Core = a representative slice: one resource with both planes,
# one control-plane-only resource, and the directory. Every case is a resource
# type, which is what the CLI takes -- the old platform/service pairs named
# platforms ('entra', 'm365', 'defender-endpoint') that no longer exist, so this
# matrix had been failing on every row since the scope narrowed.
$cases = @(
    @{ Label = 'key-vault-both-planes'; Core = $true;  Args = @('Microsoft.KeyVault/vaults') }
    @{ Label = 'entra-directory';       Core = $true;  Args = @('Entra') }
    @{ Label = 'role-assignment';       Core = $true;  Args = @('Microsoft.Authorization/roleAssignments') }
    @{ Label = 'blob-storage';          Core = $false; Args = @('Microsoft.Storage/storageAccounts/blobServices') }
    @{ Label = 'queue-storage';         Core = $false; Args = @('Microsoft.Storage/storageAccounts/queueServices') }
    @{ Label = 'web-sites';             Core = $false; Args = @('Microsoft.Web/sites') }
    @{ Label = 'virtual-machine';       Core = $false; Args = @('Microsoft.Compute/virtualMachines') }
)

if (-not $Full) { $cases = @($cases | Where-Object { $_.Core }) }
if ($Only) {
    $cases = @($cases | Where-Object {
            $label = $_.Label
            @($Only | Where-Object { $label -like "*$_*" }).Count -gt 0
        })
}
if (-not $cases -or $cases.Count -eq 0) { throw 'No test cases match the given filters.' }

# --- Resolve how to invoke the CLI. ---
# pylon must be on PATH (an activated venv or global install).
# @(...) keeps $runner an array under StrictMode for the call machinery below.
if (Get-Command pylon -ErrorAction SilentlyContinue) { $runner = @('pylon') }
else { throw 'pylon not found on PATH. Install it (uv tool install pylon-detect) and run `pylon --setup`.' }
$runner = @($runner)

Write-Step ("Matrix: {0} run(s) -> {1}" -f $cases.Count, $OutputDir)
foreach ($c in $cases) { Write-Host ("    {0,-20} pylon {1}" -f $c.Label, ($c.Args -join ' ')) }
if ($ListOnly) { Write-Host "`n(-ListOnly: nothing was run.)" -ForegroundColor Yellow; return }

Push-Location $RepoRoot
$results = @()
try {
    foreach ($c in $cases) {
        $caseDir = Join-Path $OutputDir $c.Label
        $log = Join-Path $OutputDir ("{0}.log" -f $c.Label)
        New-Item -ItemType Directory -Force -Path $caseDir | Out-Null

        Write-Step "Running $($c.Label) ..."
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $exe = $runner[0]
        $runnerRest = if ($runner.Count -gt 1) { $runner[1..($runner.Count - 1)] } else { @() }
        $exeArgs = @($runnerRest) + $c.Args + @('--output-dir', $caseDir)
        & $exe @exeArgs *> $log
        $exit = $LASTEXITCODE
        $sw.Stop()

        # Find the run.json the CLI wrote (in a <platform>-<service>-<timestamp> subfolder).
        $runJson = Get-ChildItem -Path $caseDir -Filter run.json -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime | Select-Object -Last 1

        $row = [ordered]@{
            Case = $c.Label; Target = ''; Vectors = 0; Valid = 0; Invalid = 0
            SelfCorr = 0; Sec = [int]$sw.Elapsed.TotalSeconds; Status = ''
        }
        if ($exit -ne 0 -or -not $runJson) {
            $row.Status = "FAIL (exit $exit)"
            Write-Bad "$($c.Label): did not complete — see $log"
        }
        else {
            $j = Get-Content $runJson.FullName -Raw | ConvertFrom-Json
            $row.Target = $j.target
            $row.Vectors = $j.counts.attack_vectors
            $row.Valid = $j.counts.valid
            $row.Invalid = $j.counts.invalid
            $row.SelfCorr = $j.counts.self_corrected
            $row.Status = if ($j.counts.invalid -eq 0 -and $j.counts.valid -eq $j.counts.attack_vectors) { 'PASS' } else { 'CHECK' }
            if ($row.Status -eq 'PASS') { Write-Ok "$($c.Label): $($row.Valid)/$($row.Vectors) valid in $($row.Sec)s" }
            else { Write-Bad "$($c.Label): $($row.Valid)/$($row.Vectors) valid, $($row.Invalid) invalid — see $log" }
        }
        $results += [pscustomobject]$row
    }
}
finally {
    Pop-Location
}

Write-Host ''
Write-Step 'Summary'
# Force a render width — Format-Table -AutoSize prints blank when the host has no
# console width (redirected / non-interactive), which is common in CI or a pipe.
($results | Format-Table Case, Target, Vectors, Valid, Invalid, SelfCorr, Sec, Status -AutoSize |
    Out-String -Width 200).TrimEnd() | Write-Host

$failed = @($results | Where-Object { $_.Status -ne 'PASS' })
if ($failed.Count) {
    Write-Bad ("{0} of {1} run(s) need attention." -f $failed.Count, $results.Count)
    exit 1
}
Write-Ok ("All {0} run(s) passed." -f $results.Count)

# Reminder: the operation filter is worth an eyeball on the two-plane runs.
$both = $results | Where-Object { $_.Case -eq 'key-vault-both-planes' -and $_.Status -eq 'PASS' }
if ($both) {
    Write-Host ''
    Write-Host 'Tip: confirm both planes were used on the Key Vault run —' -ForegroundColor Cyan
    Write-Host "  Select-String -Path $OutputDir/key-vault-both-planes/**/detections/*.kql -Pattern 'AZKVAuditLogs|AzureActivity'"
    Write-Host '  (expect BOTH; a run that only produced one lost half the resource)'
}
