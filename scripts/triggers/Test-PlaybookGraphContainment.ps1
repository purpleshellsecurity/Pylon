#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Execute a playbook's Microsoft Graph containment blocks against a throwaway user.

.DESCRIPTION
    These are the blocks that disable an account and revoke its sessions. They
    had only ever been PARSE checked, which resolves every cmdlet and parameter
    against the installed modules and cannot see a logic error -- the Key Vault
    trigger raced its own soft delete and passed every static gate.

    So they run for real, against a user this script CREATES seconds earlier and
    deletes in its finally block. No account that existed before the run is
    touched, which is the only safe way to test "disable this account".

    Covers the three Graph shapes the playbooks emit:
      Get-MgUser / Get-MgUserAuthenticationMethod   collect evidence (read only)
      Revoke-MgUserSignInSession                    kill the sessions
      Update-MgUser -AccountEnabled:$false          disable the account

    Each is verified by EFFECT -- the account is read back to confirm it is
    actually disabled -- rather than by the absence of an exception.

    Needs Graph connected with a scope that survives into this process:
      Connect-MgGraph -ContextScope CurrentUser -Scopes `
        "User.ReadWrite.All","UserAuthenticationMethod.Read.All","Directory.ReadWrite.All"

.PARAMETER Execute
    Required. Without it the script prints the plan and exits.
#>
[CmdletBinding()]
param([switch]$Execute)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$stamp  = Get-Date -Format "yyyyMMddTHHmmssZ"
$nick   = "pylon-ctest-$stamp"

Write-Host "CONTAINMENT TEST  playbook Graph blocks, executed against a throwaway user"
Write-Host "  user   $nick@<verified domain>  (created and deleted by this run)"

if (-not $Execute) {
    Write-Host "`nDRY RUN. Re-run with -Execute." -ForegroundColor Yellow
    return
}

# A Graph token does NOT survive into a new process on its own -- Get-MgContext
# in a fresh shell reports nothing even after a successful connect. What DOES
# survive is the CurrentUser token cache, and `Connect-MgGraph` with no
# arguments resolves from it silently. So connect rather than demand a context,
# and fail with the instruction rather than a bare "not connected".
$context = Get-MgContext
if (-not $context) {
    try {
        Connect-MgGraph -NoWelcome -ErrorAction Stop
        $context = Get-MgContext
    } catch {
        throw ("no cached Graph token. Connect once with:`n" +
               "  Connect-MgGraph -ContextScope CurrentUser -Scopes " +
               '"User.ReadWrite.All","UserAuthenticationMethod.Read.All","Directory.ReadWrite.All"')
    }
}
Write-Host "  graph  $($context.Account)"

$domain = (Get-MgDomain -All | Where-Object { $_.IsVerified -and $_.IsDefault } | Select-Object -First 1).Id
if (-not $domain) {
    $domain = (Get-MgDomain -All | Where-Object { $_.IsVerified } | Select-Object -First 1).Id
}
if (-not $domain) { throw "no verified domain in this tenant" }

$upn = "$nick@$domain"
# Never logged. A throwaway account still gets a real password.
#
# NOT [System.Web.Security.Membership]::GeneratePassword -- that type is Windows
# PowerShell only and does not exist in PowerShell 7 on macOS or Linux, which is
# where this runs. RandomNumberGenerator is cross-platform and actually
# cryptographic; Get-Random is neither.
$classes = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz',
             '23456789', '!@#$%^&*-_')
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
# One character from each class first, so the result always satisfies Entra's
# complexity rule rather than satisfying it by luck.
$picked = for ($i = 0; $i -lt 32; $i++) {
    # .Length, not .Count: this is an array literal and both are correct, but
    # the script gate cannot prove a variable is an array and .Count on $null
    # terminates under Set-StrictMode. Keeping the gate green matters more than
    # the two characters -- a check people learn to ignore stops being a check.
    $set = $classes[$i % $classes.Length]
    $set[$bytes[$i] % $set.Length]
}
$secret = -join $picked

$results = [ordered]@{}
$user = $null
try {
    $user = New-MgUser -AccountEnabled -DisplayName "Pylon containment test" `
        -MailNickname $nick -UserPrincipalName $upn `
        -PasswordProfile @{ Password = $secret; ForceChangePasswordNextSignIn = $true }
    Write-Host "  created $upn"

    # ---- shape 1: collect evidence (read only) -----------------------------
    try {
        $read = Get-MgUser -UserId $user.Id -Property "id,displayName,userPrincipalName,accountEnabled"
        # Measure-Object, not .Count: under Set-StrictMode a pipeline matching
        # nothing yields $null and $null.Count TERMINATES, so the evidence step
        # would die on exactly the account that has no auth methods -- which a
        # freshly created one never does.
        $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
        $methodCount = ($methods | Measure-Object).Count
        $results["evidence collection"] =
            if ($read.Id -eq $user.Id) { "ok ($methodCount auth method(s))" }
            else { "RAN but read back the wrong user" }
    } catch {
        $results["evidence collection"] = "FAILED: $($_.Exception.Message)"
    }

    # ---- shape 2: revoke the sessions --------------------------------------
    try {
        Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
        # A fresh account has no sessions, so this proves the CALL works, not
        # that anything was signed out. Stated rather than implied.
        $results["Revoke-MgUserSignInSession"] = "ok (no sessions existed to kill)"
    } catch {
        $results["Revoke-MgUserSignInSession"] = "FAILED: $($_.Exception.Message)"
    }

    # ---- shape 3: disable the account --------------------------------------
    try {
        Update-MgUser -UserId $user.Id -AccountEnabled:$false
        # Verified by effect. Directory writes are eventually consistent, so
        # read back with a few attempts rather than once.
        $enabled = $true
        foreach ($attempt in 1..6) {
            Start-Sleep -Seconds 2
            $enabled = (Get-MgUser -UserId $user.Id -Property "accountEnabled").AccountEnabled
            if (-not $enabled) { break }
        }
        $results["Update-MgUser (disable)"] =
            if (-not $enabled) { "ok (account reads back disabled)" }
            else { "RAN but the account is STILL ENABLED" }
    } catch {
        $results["Update-MgUser (disable)"] = "FAILED: $($_.Exception.Message)"
    }
}
finally {
    if ($user) {
        try {
            Remove-MgUser -UserId $user.Id
            Write-Host "  cleaned up: $upn deleted"
        } catch {
            Write-Warning "could NOT delete $upn : $($_.Exception.Message)"
            Write-Warning "remove it by hand: Remove-MgUser -UserId $($user.Id)"
        }
    }
}

Write-Host "`nRESULTS"
foreach ($k in $results.Keys) { "  {0,-28} {1}" -f $k, $results[$k] | Write-Host }
