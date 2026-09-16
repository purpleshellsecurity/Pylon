#Requires -Version 7.0
<#
.SYNOPSIS
    Generate a cross-service attack-path graph (+ the detections behind it) and
    package it as a single deliverable to hand to a red teamer.

.DESCRIPTION
    Runs pylon across a set of services into one folder, then builds the attack
    graph (`--build-graph`) and the ATT&CK detection map (`--build-map`) from
    those runs, and zips the whole thing up.

    The graph draws each detection as a node linked to the footholds it needs
    (`requires`) and grants (`enables`); a foothold one detection grants and
    another needs becomes a shared hub, so cross-service attack paths appear on
    their own. The red teamer walks those paths and checks whether each hop's
    detection actually fires.

    The per-service runs are real model calls and cost money (the default set is
    nine runs — identity, Azure Functions, Key Vault, a VM, and storage across
    its control plane + blob/file/queue/table). `-MaxCost` caps each run; pass
    `-Services` to trim the set. `-SkipRuns` reuses run.json
    already under the output folder and only rebuilds the graph/map + repackages —
    free, and handy for re-running after you tweak detections.

.PARAMETER OutputDir
    Package folder. Default: attack-graph-package (runs land in OutputDir/runs).

.PARAMETER MaxCost
    Per-service USD cap passed to pylon --max-cost. Default: 3.

.PARAMETER SkipRuns
    Don't run the model — reuse existing run.json under OutputDir/runs, just
    rebuild the graph/map and repackage.

.PARAMETER NoZip
    Leave the folder unzipped (skip Compress-Archive).

.PARAMETER Services
    Advanced: override the default set. Array of hashtables @{ Label=..; Args=@(..) }.

.EXAMPLE
    ./scripts/Build-AttackGraph.ps1
.EXAMPLE
    ./scripts/Build-AttackGraph.ps1 -SkipRuns          # rebuild graph from existing runs, no cost
#>
[CmdletBinding()]
param(
    [string]$OutputDir = 'attack-graph-package',
    [double]$MaxCost = 3.0,
    [switch]$SkipRuns,
    [switch]$NoZip,
    [object[]]$Services
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Write-Step { param([string]$m) Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "  OK  $m" -ForegroundColor Green }
function Write-Bad  { param([string]$m) Write-Host "  !!  $m" -ForegroundColor Red }

# The default set: the directory plus the Azure resources a red teamer cares
# about, each named by its resource type, which is what the CLI takes.
#
# Storage no longer needs five entries. A target carries every plane the resource
# writes to, so blobServices covers account management in AzureActivity AND blob
# access in StorageBlobLogs in one run -- which is also the point of the graph,
# since a foothold granted on the control plane and used on the data plane is
# exactly the cross-plane edge it exists to draw.
#
# Azure Functions is gone as a separate entry: it is Microsoft.Web/sites, the
# same resource type as App Service, and it ran control-plane only either way.
# Each entry is (Label, pylon Args). -MaxCost caps each; trim with -Services.
if (-not $Services) {
    $Services = @(
        @{ Label = 'identity';        Args = @('Entra') }
        @{ Label = 'key-vault';       Args = @('Microsoft.KeyVault/vaults') }
        @{ Label = 'storage-blob';    Args = @('Microsoft.Storage/storageAccounts/blobServices') }
        @{ Label = 'storage-file';    Args = @('Microsoft.Storage/storageAccounts/fileServices') }
        @{ Label = 'storage-queue';   Args = @('Microsoft.Storage/storageAccounts/queueServices') }
        @{ Label = 'storage-table';   Args = @('Microsoft.Storage/storageAccounts/tableServices') }
        @{ Label = 'web-sites';       Args = @('Microsoft.Web/sites') }
        @{ Label = 'virtual-machine'; Args = @('Microsoft.Compute/virtualMachines') }
        @{ Label = 'role-assignment'; Args = @('Microsoft.Authorization/roleAssignments') }
    )
}

# Resolve the CLI (pylon must be on PATH — activate the venv it was installed into).
if (Get-Command pylon -ErrorAction SilentlyContinue) { $runner = @('pylon') }
else { throw 'pylon not found on PATH. Install it (uv tool install pylon-detect) and run `pylon --setup`.' }
$runner = @($runner)
$exe = $runner[0]
$runnerRest = if ($runner.Count -gt 1) { $runner[1..($runner.Count - 1)] } else { @() }

$runsDir = Join-Path $OutputDir 'runs'
New-Item -ItemType Directory -Force -Path $runsDir | Out-Null

Push-Location $RepoRoot
try {
    # --- 1. Generate the per-service detections (real model calls) ------------
    $ran = @()
    if ($SkipRuns) {
        Write-Step 'Skipping model runs (-SkipRuns) — using existing run.json'
    }
    else {
        foreach ($s in $Services) {
            $caseDir = Join-Path $runsDir $s.Label
            $log = Join-Path $runsDir ("{0}.log" -f $s.Label)
            New-Item -ItemType Directory -Force -Path $caseDir | Out-Null
            Write-Step "Generating $($s.Label): pylon $($s.Args -join ' ')"
            $callArgs = @($runnerRest) + $s.Args + @('--output-dir', $caseDir, '--max-cost', "$MaxCost")
            & $exe @callArgs *> $log
            if ($LASTEXITCODE -eq 0) { Write-Ok "$($s.Label) done"; $ran += $s.Label }
            else { Write-Bad "$($s.Label) failed (exit $LASTEXITCODE) — see $log (continuing)" }
        }
        if (-not $ran) { throw 'No service run completed — cannot build a graph. Check the .log files and your provider config.' }
    }

    # --- 2. Build the attack graph + the ATT&CK detection map -----------------
    Write-Step 'Building the attack-path graph'
    & $exe @runnerRest '--build-graph' $runsDir
    if ($LASTEXITCODE -ne 0) { throw "pylon --build-graph failed (exit $LASTEXITCODE)." }

    Write-Step 'Building the ATT&CK detection map'
    & $exe @runnerRest '--build-map' $runsDir
    if ($LASTEXITCODE -ne 0) { Write-Bad "pylon --build-map failed (exit $LASTEXITCODE) — continuing with the graph only." }

    $graph = Get-ChildItem -Path $runsDir -Filter 'attack-graph.html' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $graph) { throw "attack-graph.html was not produced under $runsDir." }

    # --- 3. Drop a hand-off note so the zip is self-explanatory ---------------
    $svcLines = ($Services | ForEach-Object { "  - {0}: pylon {1}" -f $_.Label, ($_.Args -join ' ') }) -join "`n"
    $handoff = @"
# Pylon - attack-path graph hand-off

Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm').

## Start here
1. Open **attack-graph.html** in a browser (offline, no install). Grey dots are
   detections; rings are footholds (access an attacker gains). A line means one
   detection catches an action that hands another detection the foothold it
   needs - follow the lines to read cross-service attack paths.
2. Open **detection-map.html** for the ATT&CK-technique coverage view.

## Your job (stress-test it)
For each hop on a path, perform the action in the tenant and confirm the alert
fires. The queries are under each service folder:
  <service>/detections/*.kql - the detection query (Sentinel / Defender KQL)
  <service>/rules/*.yaml      - the same as a deployable Sentinel analytics rule
  <service>/report.md         - strategy, tuning, false positives per detection
  <service>/run.json          - machine record incl. the requires/enables tokens

Tell us which hops did NOT fire - those are the detection gaps to close.

## Services in this package
$svcLines
"@
    Set-Content -Path (Join-Path $runsDir 'HANDOFF.md') -Value $handoff -Encoding utf8

    # --- 4. Package -----------------------------------------------------------
    $stamp = (Get-Date -Format 'yyyyMMdd-HHmm')
    if ($NoZip) {
        $deliverable = (Resolve-Path $runsDir).Path
    }
    else {
        Write-Step 'Packaging the deliverable (zip)'
        $zip = Join-Path $OutputDir ("pylon-attack-graph-{0}.zip" -f $stamp)
        if (Test-Path $zip) { Remove-Item $zip -Force }
        Compress-Archive -Path (Join-Path $runsDir '*') -DestinationPath $zip
        $deliverable = (Resolve-Path $zip).Path
    }
}
finally {
    Pop-Location
}

$kqlCount = (Get-ChildItem -Path $runsDir -Recurse -Filter '*.kql' -ErrorAction SilentlyContinue | Measure-Object).Count
$runJsonCount = (Get-ChildItem -Path $runsDir -Recurse -Filter 'run.json' -ErrorAction SilentlyContinue | Measure-Object).Count

Write-Host ''
Write-Step 'Ready to hand off'
Write-Host "  Services in graph : $runJsonCount run(s)"
Write-Host "  Detections (.kql) : $kqlCount"
Write-Host "  Attack graph      : $((Resolve-Path (Join-Path $runsDir 'attack-graph.html')).Path)"
Write-Host "  Deliverable       : $deliverable" -ForegroundColor Green
Write-Host ''
Write-Host 'Send the deliverable to the red teamer. It contains:' -ForegroundColor Cyan
Write-Host '  attack-graph.html  — the cross-service attack-path map (open in a browser)'
Write-Host '  <service>/detections/*.kql — the queries to test each hop against'
Write-Host '  <service>/report.md, rules/*.yaml, run.json — full context + deployable rules'
