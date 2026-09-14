<!-- GUIDE -->
## Task: Phase 3 — IR Playbook for <service>__SERVICE__</service> (Azure ARM)

The detection above is from Phase 2. Build ONE focused IR playbook for: <target>__TARGET__</target>

Use exact field names and OperationNameValue from Phase 2. Every command must be copy-paste
ready. Designed for 3am incidents — no enterprise hierarchy, just what to do.

PRIMARY queries use AzureActivity. The Cross-Log Pivots section may use the grounded pivot
queries supplied with this prompt; nothing else may invent another table's schema.

Produce exactly the structure below.
<!-- /GUIDE -->

<!-- SLOT: metadata -->
**Alert:** [Detection name from Phase 2]
**Severity:** [from Phase 2]
**What happened:** [1 sentence]

**Why it matters:**
[why it matters]

**MITRE ATT&CK:** [technique ID and name]
**Common false positives:** [common false positives]

<!-- SLOT: quick_decision -->
was this a human or an automation principal, and was it in scope for the change? An ARM
write by a CI/CD service principal inside a change window is the common benign shape.

<!-- SLOT: quick_triage -->
**Query 1 — What exactly did this actor do, in the window?**
```kql
AzureActivity
| where TimeGenerated between (AlertTime - TriageWindow .. AlertTime + TriageWindow)
| where Caller == AlertActor
| where Caller !in (AllowedActors)
| extend Props = parse_json(Properties), Auth = parse_json(Authorization)
| extend ActorUpn = Caller, ActorId = tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"])
| extend ActorName = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[0]), ""),
         ActorUpnSuffix = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[1]), "")
| extend SrcIp = CallerIpAddress, TargetResource = _ResourceId, Operation = OperationNameValue
| project TimeGenerated, ActorUpn, ActorName, ActorUpnSuffix, ActorId, SrcIp,
          TargetResource, Operation, ActivityStatusValue, ResourceGroup, SubscriptionId
| top 30 by TimeGenerated desc;
```

<!-- SLOT: investigation -->
**Query 1 — Everything in the same correlated operation:**
```kql
AzureActivity
| where TimeGenerated between (AlertTime - 1h .. AlertTime + 1h)
| where CorrelationId == "[FROM ALERT: CorrelationId]"
| extend Props = parse_json(Properties), Auth = parse_json(Authorization)
| extend AuthAction = tostring(Auth.action), AuthScope = tostring(Auth.scope)
| extend StatusCode = tostring(Props.statusCode)
| extend ActorUpn = Caller, SrcIp = CallerIpAddress, TargetResource = _ResourceId,
         Operation = OperationNameValue
| project TimeGenerated, Operation, ActorUpn, SrcIp, TargetResource, ResourceGroup,
          SubscriptionId, AuthAction, AuthScope, StatusCode;
```

<!-- SLOT: blast_radius -->
```kql
AzureActivity
| where TimeGenerated between (AlertTime - TriageWindow .. AlertTime + TriageWindow)
| where Caller == AlertActor
| summarize Operations = dcount(OperationNameValue), Resources = dcount(_ResourceId),
            Subscriptions = dcount(SubscriptionId), Ops = make_set(OperationNameValue, 10)
  by Caller;
```
One resource is an incident; forty across three subscriptions is a different incident.

<!-- SLOT: scope_query -->
```kql
// AzureActivity records ARM WRITES. Control-plane READS are not logged natively —
// that is expected, not a gap in your configuration. A read-heavy actor doing
// reconnaissance is invisible in this table by design, so the absence of reads is
// not evidence that none happened. Do not add a read filter here.
// NOT filtered by operation, deliberately. See the note above the query.
let LookbackStart = AlertTime - 30d;
let WinStart = AlertTime - TriageWindow;
let WinEnd   = AlertTime + TriageWindow;
let BaselineIps = toscalar(
    AzureActivity
    | where TimeGenerated between (LookbackStart .. WinStart)
    | where Caller == AlertActor
    | summarize make_set(CallerIpAddress, 500));
let BaselinePerHour = toscalar(
    AzureActivity
    | where TimeGenerated between (LookbackStart .. WinStart)
    | where Caller == AlertActor
    | summarize todouble(count()) / ((WinStart - LookbackStart) / 1h));
AzureActivity
| where TimeGenerated between (WinStart .. WinEnd)
| where Caller == AlertActor
| extend RbacAction = tostring(parse_json(Authorization).action)
| summarize Ops = count(),
            Succeeded = countif(ActivityStatusValue =~ "Success"),
            Failed    = countif(ActivityStatusValue =~ "Failure"),
            Started   = countif(ActivityStatusValue =~ "Start"),
            RbacVerbs = make_set(RbacAction, 50),
            Operations = make_set(OperationNameValue, 100),
            SrcIps = make_set(CallerIpAddress, 50)
| extend WindowPerHour = round(todouble(Ops) / ((WinEnd - WinStart) / 1h), 2),
         BaselinePerHour = round(BaselinePerHour, 2),
         NewSrcIps = set_difference(SrcIps, BaselineIps)
| extend RateMultiple = round(WindowPerHour / iff(BaselinePerHour > 0.0, BaselinePerHour, 0.01), 1)
| project Ops, WindowPerHour, BaselinePerHour, RateMultiple,
          Succeeded, Failed, Started, SrcIps, NewSrcIps, RbacVerbs, Operations;
```
No user agent column exists on AzureActivity — omitted rather than invented.

<!-- SLOT: scope_guidance -->
diagnostic settings, activity log alerts, and log profiles (a log profile is the
legacy activity-log export; Microsoft retires it 30 September 2026 in favour of
diagnostic settings, so expect it to stop appearing). An actor working on the
visibility rather than the resource has changed the nature of the incident.

<!-- SLOT: preserve -->
- `az resource show --ids "[FROM ALERT: TargetResource]" -o json > evidence-resource-$(date -u +%Y%m%dT%H%M%SZ).json`
- `az role assignment list --assignee "[FROM ALERT: ActorUpn or ActorId]" --all -o json > evidence-roles-...json`

<!-- SLOT: containment -->
**Option A — Preferred (reversible): remove the role assignment the actor gained**
```powershell
Connect-AzAccount
$Assignee = "[FROM ALERT: ActorId]"
$Scope    = "[FROM ALERT: TargetResource]"
$Role     = "[the role that grants this operation]"
try {
    Remove-AzRoleAssignment -ObjectId $Assignee -RoleDefinitionName $Role -Scope $Scope
    Write-Host "✅ Role assignment removed" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "MANUAL: Portal → the resource → Access control (IAM) → Role assignments"
}
```
**Undo:** `New-AzRoleAssignment -ObjectId $Assignee -RoleDefinitionName $Role -Scope $Scope`

**Option B — Lock the resource against further change (reversible)**
```powershell
try {
    New-AzResourceLock -LockName "ir-hold" -LockLevel CanNotDelete `
        -Scope "[FROM ALERT: TargetResource]" -Force
    Write-Host "✅ Resource locked" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "MANUAL: Portal → the resource → Locks → Add"
}
```
**Undo:** `Remove-AzResourceLock -LockName "ir-hold" -Scope "[FROM ALERT: TargetResource]" -Force`

**Option C — If the actor account is compromised**
```powershell
#Requires -Modules Microsoft.Graph.Authentication
#Requires -Modules Microsoft.Graph.Users
#Requires -Modules Microsoft.Graph.Users.Actions
# Get-Mg* / Update-Mg* are Microsoft Graph cmdlets — they need Connect-MgGraph,
# not Connect-AzAccount. An Az context cannot authenticate them.
Connect-MgGraph -Scopes "User.ReadWrite.All" -NoWelcome
$UserUPN = "[FROM ALERT: ActorUpn]"
try {
    $User = Get-MgUser -Filter "userPrincipalName eq '$UserUPN'"
    Update-MgUser -UserId $User.Id -AccountEnabled:$false
    Revoke-MgUserSignInSession -UserId $User.Id
    Write-Host "✅ Account disabled and sessions revoked" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "MANUAL: Entra Portal → Users → $UserUPN → Account enabled = No"
}
```
**Undo:** `Update-MgUser -UserId $User.Id -AccountEnabled:$true`. Sessions cannot be
un-revoked; the user signs in again.

<!-- SLOT: undo_stakes -->
someone will pull the role assignment the deployment pipeline was using at 2am.

<!-- SLOT: eradication -->
- **Role assignments and custom role definitions** the actor created anywhere in scope:
  `Get-AzRoleAssignment -SignInName "[FROM ALERT: ActorUpn or ActorId]"` and check for new definitions.
- **Resource-level credentials**: storage account keys, Key Vault access policies,
  automation account credentials touched in the window.
- **Persistence in the control plane**: deployment scripts, automation runbooks,
  Logic Apps, managed identities newly assigned to resources.
- **Policy exemptions** the actor added, which would let the same action pass next time.
- **The diagnostic settings from the anti-forensics query** — if any were removed,
  re-create them before closing, or the next attempt is invisible too.

<!-- SLOT: dwell_time -->
AzureActivity entries are "usually available for analysis and alerting within 3 to 20
minutes of the event occurring" — wait 20 minutes.

<!-- SLOT: positive_control -->
let ContainmentTime = datetime([TIME YOU RAN CONTAINMENT]);
AzureActivity
| where TimeGenerated > ContainmentTime
| summarize TotalRowsInWindow = count()

<!-- SLOT: validation -->
```kql
let ContainmentTime = datetime([TIME YOU RAN CONTAINMENT]);
AzureActivity
| where TimeGenerated > ContainmentTime
| where Caller == AlertActor
| where OperationNameValue __OPERATOR__ "[the operation from Phase 2]"
| summarize Attempts = count(), Successes = countif(ActivityStatusValue =~ "Success")
    by bin(TimeGenerated, 5m);
```
✅ Expected: Successes = 0
🚨 If Successes > 0: containment failed — the actor has another path.

<!-- SLOT: recovery -->
1. The role assignment or resource change is reverted, verified in the portal.
2. The actor's other access is enumerated and justified, not assumed.
3. Diagnostic settings confirmed present and flowing (the positive control above).
4. The owning team knows the resource changed and why.

<!-- SLOT: prevention -->
- An Azure Policy denying the operation at the scope it was abused, or a lock.
- PIM/just-in-time for the role rather than standing assignment.
- An alert on modification of diagnostic settings — the anti-forensics query above,
  as a rule.

<!-- SLOT: escalation -->
- The actor modified diagnostic settings, log profiles or alert rules — treat visibility
  as compromised for the whole window, not just this resource.
- The blast radius crosses subscriptions, or reaches a production data plane.
