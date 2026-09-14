<!-- GUIDE -->
## Task: Phase 3 — IR Playbook for <service>__SERVICE__</service> (Entra ID directory changes)

The detection above is from Phase 2. Build ONE focused IR playbook for: <target>__TARGET__</target>

Use exact field names and OperationName values from Phase 2. Designed for 3am incidents —
no enterprise hierarchy, just what to do.

PRIMARY queries use __SERVICE__. The Cross-Log Pivots section may use the grounded pivot
queries supplied with this prompt; nothing else may invent another table's schema.

Produce exactly the structure below.
<!-- /GUIDE -->

<!-- SLOT: metadata -->
**Alert:** [Detection name from Phase 2]
**Severity:** [from Phase 2]
**Actor:** [FROM ALERT: ActorUpn or ActorId]
**What happened:** [1 sentence]

**MITRE ATT&CK:** [technique ID and name]
**Common false positives:** [common false positives]

<!-- SLOT: quick_decision -->
was this a directory change a human intended? Most alerts here are provisioning
automation. Check the actor against `AllowedActors` before anything else.

<!-- SLOT: quick_triage -->
**Query 1 — What did this actor change, in the window?**
```kql
__SERVICE__
| where TimeGenerated between (AlertTime - TriageWindow .. AlertTime + TriageWindow)
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName),
         ActorId  = tostring(InitiatedBy.user.id),
         SrcIp    = tostring(InitiatedBy.user.ipAddress)
| where ActorUpn == AlertActor or ActorId == AlertActor
| where ActorUpn !in (AllowedActors)
| extend ActorName = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[0]), ""),
         ActorUpnSuffix = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[1]), "")
| extend Operation = OperationName, TargetResource = tostring(TargetResources[0].id)
| project TimeGenerated, ActorUpn, ActorName, ActorUpnSuffix, ActorId, SrcIp,
          Operation, TargetResource, Result, TargetResources
| top 30 by TimeGenerated desc;
```

<!-- SLOT: investigation -->
**Query 1 — Everything in the same correlated operation:**
```kql
let AlertCorrelationId = "[FROM ALERT: CorrelationId]";
__SERVICE__
| where TimeGenerated between (AlertTime - 1h .. AlertTime + 1h)
| where CorrelationId == AlertCorrelationId
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName), Operation = OperationName
| project TimeGenerated, Operation, ActorUpn, Result, TargetResources;
```

<!-- SLOT: blast_radius -->
```kql
__SERVICE__
| where TimeGenerated between (AlertTime - TriageWindow .. AlertTime + TriageWindow)
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
| where ActorUpn == AlertActor
| summarize Operations = dcount(OperationName), Targets = dcount(tostring(TargetResources[0].id)),
            Ops = make_set(OperationName, 15) by ActorUpn;
```

<!-- SLOT: scope_query -->
```kql
// AuditLogs is a CHANGE log — every row is a write. There is no read/write axis to
// split on, and no user agent column. Both omitted rather than faked.
// NOT filtered by operation, deliberately. See the note above the query.
let LookbackStart = AlertTime - 30d;
let WinStart = AlertTime - TriageWindow;
let WinEnd   = AlertTime + TriageWindow;
let BaselineIps = toscalar(
    __SERVICE__
    | where TimeGenerated between (LookbackStart .. WinStart)
    | where tostring(InitiatedBy.user.userPrincipalName) == AlertActor
    | summarize make_set(tostring(InitiatedBy.user.ipAddress), 500));
let BaselinePerHour = toscalar(
    __SERVICE__
    | where TimeGenerated between (LookbackStart .. WinStart)
    | where tostring(InitiatedBy.user.userPrincipalName) == AlertActor
    | summarize todouble(count()) / ((WinStart - LookbackStart) / 1h));
__SERVICE__
| where TimeGenerated between (WinStart .. WinEnd)
| where tostring(InitiatedBy.user.userPrincipalName) == AlertActor
| extend SrcIp = tostring(InitiatedBy.user.ipAddress)
| summarize Changes = count(),
            Succeeded = countif(Result =~ "success"),
            Failed    = countif(Result !~ "success"),
            Operations = make_set(OperationName, 100),
            Categories = make_set(Category, 30),
            SrcIps = make_set(SrcIp, 50)
| extend WindowPerHour = round(todouble(Changes) / ((WinEnd - WinStart) / 1h), 2),
         BaselinePerHour = round(BaselinePerHour, 2),
         NewSrcIps = set_difference(SrcIps, BaselineIps)
| extend RateMultiple = round(WindowPerHour / iff(BaselinePerHour > 0.0, BaselinePerHour, 0.01), 1)
| project Changes, WindowPerHour, BaselinePerHour, RateMultiple,
          Succeeded, Failed, SrcIps, NewSrcIps, Categories, Operations;
```

<!-- SLOT: scope_guidance -->
Conditional Access policy changes, diagnostic setting changes, and audit log
retention changes. Also any credential or authentication-method addition — that is
how an attacker keeps access after you revoke sessions.

<!-- SLOT: preserve -->
```powershell
#Requires -Modules Microsoft.Graph.Authentication
#Requires -Modules Microsoft.Graph.Identity.SignIns
#Requires -Modules Microsoft.Graph.Users
Connect-MgGraph -Scopes "User.Read.All","UserAuthenticationMethod.Read.All" -NoWelcome
Get-MgUser -UserId "[FROM ALERT: ActorUpn]" -Property * |
    ConvertTo-Json -Depth 6 | Out-File ".\evidence-user-$(Get-Date -Format yyyyMMddTHHmmssZ).json"
Get-MgUserAuthenticationMethod -UserId "[FROM ALERT: ActorUpn]" |
    ConvertTo-Json -Depth 6 | Out-File ".\evidence-authmethods-$(Get-Date -Format yyyyMMddTHHmmssZ).json"
```
Capture the authentication methods BEFORE you revoke anything — the list of what the
attacker enrolled is the evidence, and eradication removes it.

<!-- SLOT: containment -->
**Option A — Preferred (reversible): reverse the directory change**
[the reverse operation]
**Undo:** re-apply the original change, which the Preserve Evidence capture above records.

**Option B — Revoke the actor's sessions**
```powershell
#Requires -Modules Microsoft.Graph.Authentication
#Requires -Modules Microsoft.Graph.Users.Actions
Connect-MgGraph -Scopes "User.ReadWrite.All" -NoWelcome
$UserId = "[FROM ALERT: ActorUpn]"
try {
    Revoke-MgUserSignInSession -UserId $UserId
    Write-Host "✅ Sessions revoked" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "MANUAL: Entra Portal → Users → $UserId → Revoke sessions"
}
```
**Undo:** none needed — the user simply signs in again. That is exactly why Option B alone
is not containment: see Eradication.

**Option C — If the actor account is compromised: disable it**
```powershell
#Requires -Modules Microsoft.Graph.Authentication
#Requires -Modules Microsoft.Graph.Users
#Requires -Modules Microsoft.Graph.Users.Actions
Connect-MgGraph -Scopes "User.ReadWrite.All" -NoWelcome
$UserId = "[FROM ALERT: ActorUpn]"
try {
    Update-MgUser -UserId $UserId -AccountEnabled:$false
    Revoke-MgUserSignInSession -UserId $UserId
    Write-Host "✅ Account disabled and sessions revoked" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "MANUAL: Entra Portal → Users → $UserId → Account enabled = No"
}
```
**Undo:** `Update-MgUser -UserId $UserId -AccountEnabled:$true`

<!-- SLOT: undo_stakes -->
someone will disable the service principal that turns out to be the payroll connector at 2am.

<!-- SLOT: eradication -->
This is the substance of the incident on this plane. Revoking sessions and disabling the
account does NOT remove what the attacker left — enrolling their own authenticator is
standard AiTM persistence, and an account re-enabled without this list is an account the
attacker signs straight back into.

- **Authentication methods newly registered on the user** — the attacker's own
  authenticator app, phone number or FIDO key:
  `Get-MgUserAuthenticationMethod -UserId $UserId` — compare against the evidence capture
  and remove anything the user does not recognise.
- **Mailbox rules** created in the window, especially forwarding or delete-on-arrival.
- **Additional credentials and certificates** on any service principal the actor touched.
- **Federated identity credentials** on app registrations — these survive password resets.
- **App role assignments and consent grants** the actor made.
- **Owners** the actor added to groups, applications or service principals.
- **Conditional Access policy modifications** from the anti-forensics query — a policy
  exclusion added for the actor is persistence with no credential attached.

<!-- SLOT: dwell_time -->
AuditLogs ingestion is typically a few minutes but can reach 15 — wait 15 before reading
an empty result as success.

<!-- SLOT: positive_control -->
let ContainmentTime = datetime([TIME YOU RAN CONTAINMENT]);
__SERVICE__
| where TimeGenerated > ContainmentTime
| summarize TotalRowsInWindow = count()

<!-- SLOT: validation -->
```kql
let ContainmentTime = datetime([TIME YOU RAN CONTAINMENT]);
// Stay on this table. A role assignment or CA policy change targets a directory
// object, not an AppId, so a service-principal sign-in table returns zero rows for
// the wrong reason — and zero would then read as success.
__SERVICE__
| where TimeGenerated > ContainmentTime
| where OperationName __OPERATOR__ "[the operation from Phase 2]"
| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName)
| where ActorUpn == AlertActor
| summarize Attempts = count(), Successes = countif(Result =~ "success")
    by bin(TimeGenerated, 5m);
```
✅ Expected: Successes = 0
🚨 If Successes > 0: containment failed — check for additional credentials and for a CA
exclusion the actor added.

<!-- SLOT: recovery -->
1. The directory change is reversed and verified in the portal.
2. Authentication methods reviewed against the evidence capture — nothing unrecognised.
3. Sessions revoked AFTER the eradication list, not before it.
4. The user has re-registered MFA under supervision, if their methods were removed.

<!-- SLOT: prevention -->
- Conditional Access requiring a compliant device or phishing-resistant MFA for the role.
- PIM for the directory role rather than standing assignment.
- An alert on authentication-method registration for privileged accounts.

<!-- SLOT: escalation -->
- The actor registered an authentication method, added a federated credential, or modified
  a Conditional Access policy — access survives a password reset and this is no longer a
  single-account incident.
- A Global Administrator or Privileged Role Administrator assignment is involved.
