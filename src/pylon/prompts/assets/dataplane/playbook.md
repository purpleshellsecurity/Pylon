<!-- GUIDE -->
## Task: Phase 3 — IR Playbook for <service>__SERVICE__</service> (Azure Data Plane)

The detection above is from Phase 2. Build ONE focused IR playbook for: <target>__TARGET__</target>

Use exact field names and operation values from Phase 2. Designed for 3am incidents —
no enterprise hierarchy, just what to do.

PRIMARY queries use __SERVICE__. The Cross-Log Pivots section may use the grounded pivot
queries supplied with this prompt; nothing else may invent another table's schema.

Produce exactly the structure below.
<!-- /GUIDE -->

<!-- SLOT: metadata -->
**Alert:** [Detection name from Phase 2]
**Severity:** [from Phase 2]
**Resource:** [the resource from the alert]
**What happened:** [1 sentence]

**MITRE ATT&CK:** [technique ID and name]
**Common false positives:** [common false positives]

<!-- SLOT: quick_decision -->
is this the application that normally reads this resource, or something else? Data-plane
alerts are dominated by an app's own service principal doing its job.

<!-- SLOT: quick_triage -->
**Query 1 — What did this identity touch, in the window?**

The first `extend` gives this table's own columns the normalized names the alert
uses — `ActorUpn`, `ActorId`, `IsFailure`, `UserAgent` — so the rest of the
playbook reads the same on every plane.

```kql
__SERVICE__
| where TimeGenerated between (AlertTime - TriageWindow .. AlertTime + TriageWindow)
__NORMALISE_FULL__
| where ActorUpn == AlertActor or ActorId == AlertActor
| where ActorUpn !in (AllowedActors)
__NORMALISE_CONTEXT__
| project TimeGenerated, ActorUpn, ActorId, SrcIp, UserAgent, Operation,
          TargetResource, IsFailure
| top 30 by TimeGenerated desc;
```

<!-- SLOT: investigation -->
__CORRELATED_QUERY__

<!-- SLOT: blast_radius -->
```kql
__SERVICE__
| where TimeGenerated between (AlertTime - TriageWindow .. AlertTime + TriageWindow)
__NORMALISE_ACTOR__
| where ActorUpn == AlertActor
| summarize Operations = dcount(__OPERATION_COLUMN__), Resources = dcount(_ResourceId),
            Ops = make_set(__OPERATION_COLUMN__, 15);
```
For a secrets store, distinct objects read IS the exposure count.

<!-- SLOT: scope_query -->
```kql
// NOT filtered by operation, deliberately. See the note above the query.
// Reads and writes are split on the operation names __SERVICE__ itself uses.
let LookbackStart = AlertTime - 30d;
let WinStart = AlertTime - TriageWindow;
let WinEnd   = AlertTime + TriageWindow;
// ── normalise ONCE, for __SERVICE__. ──
let Events = __SERVICE__
    __NORMALISE_ACTOR_FAIL__;
let BaselineIps = toscalar(
    Events
    | where TimeGenerated between (LookbackStart .. WinStart)
    | where ActorUpn == AlertActor
    | summarize make_set(__SRC_IP__, 500));
let BaselinePerHour = toscalar(
    Events
    | where TimeGenerated between (LookbackStart .. WinStart)
    | where ActorUpn == AlertActor
    | summarize todouble(count()) / ((WinStart - LookbackStart) / 1h));
Events
| where TimeGenerated between (WinStart .. WinEnd)
| where ActorUpn == AlertActor
| summarize Ops = count(),
            Reads  = countif(__OPERATION_COLUMN__ has_any ([the read operations for this table])),
            Writes = countif(__OPERATION_COLUMN__ has_any ([the write operations for this table])),
            Succeeded = countif(not(IsFailure)),
            Failed    = countif(IsFailure),
            Operations = make_set(__OPERATION_COLUMN__, 100),
            SrcIps = make_set(__SRC_IP__, 50)
| extend WindowPerHour = round(todouble(Ops) / ((WinEnd - WinStart) / 1h), 2),
         BaselinePerHour = round(BaselinePerHour, 2),
         NewSrcIps = set_difference(SrcIps, BaselineIps)
| extend RateMultiple = round(WindowPerHour / iff(BaselinePerHour > 0.0, BaselinePerHour, 0.01), 1)
| project Ops, Reads, Writes, WindowPerHour, BaselinePerHour, RateMultiple,
          Succeeded, Failed, SrcIps, NewSrcIps, Operations;
```

<!-- SLOT: scope_guidance -->
diagnostic setting changes on the resource, key or SAS regeneration, firewall and
network rule changes, and a read volume far above this actor's baseline — bulk
reads are what exfiltration looks like on a data plane.

<!-- SLOT: preserve -->
- Export the triage results before rotating anything — a rotated secret's access history
  is the only record of what was reachable.
- `az resource show --ids "[FROM ALERT: TargetResource]" -o json > evidence-resource-...json`

<!-- SLOT: containment -->
**Option A — Preferred (reversible): remove the identity's data-plane access**
```powershell
Connect-AzAccount
try {
    # Use the access model this resource actually uses; RBAC is the common one.
    Remove-AzRoleAssignment -ObjectId "[FROM ALERT: ActorId]" `
        -RoleDefinitionName "[the role that grants this operation]" -Scope "[the resource id]"
    Write-Host "✅ Data-plane access removed" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "MANUAL: Portal → the resource → Access control (IAM), or this service's own key/policy model"
}
```
**Undo:** `New-AzRoleAssignment` with the same three arguments.

**Option B — Rotate what was read (NOT reversible)**
Rotate every secret, key or credential the blast-radius query shows was accessed. The old
value cannot be restored, and that is the point — but every consumer must be updated, so
list them before you start.

<!-- SLOT: undo_stakes -->
someone will revoke the credential the nightly export job authenticates with at 2am.

<!-- SLOT: eradication -->
- **Everything the actor read** must be treated as disclosed and rotated, not just the
  object named in the alert.
- **Other access paths to the same resource**: access policies, SAS tokens, connection
  strings, firewall rules the actor added.
- **Consumers of the rotated material** — a rotation that misses one breaks production and
  teaches everyone not to rotate next time.
- **The diagnostic setting from the anti-forensics query**, if it was changed.

<!-- SLOT: dwell_time -->
Resource logs are typically 5–15 minutes behind — wait 15 before believing an empty result.

<!-- SLOT: positive_control -->
let ContainmentTime = datetime([TIME YOU RAN CONTAINMENT]);
__SERVICE__
| where TimeGenerated > ContainmentTime
| summarize TotalRowsInWindow = count()

<!-- SLOT: validation -->
```kql
let ContainmentTime = datetime([TIME YOU RAN CONTAINMENT]);
__SERVICE__
__NORMALISE_ACTOR_FAIL__
| where TimeGenerated > ContainmentTime
| where ActorUpn == AlertActor
| where __OPERATION_COLUMN__ __OPERATOR__ "[the operation from Phase 2]"
| summarize Attempts = count(), Successes = countif(not(IsFailure))
    by bin(TimeGenerated, 5m);
```
✅ Expected: Successes = 0
🚨 If Successes > 0: another access path is open — go back to Eradication.

<!-- SLOT: recovery -->
1. Access removed and verified in the portal.
2. Everything read has been rotated, and every consumer updated.
3. Diagnostic settings confirmed flowing (the positive control above).
4. The owning application team knows what was rotated and when.

<!-- SLOT: prevention -->
- Private endpoint or firewall restriction so the data plane is not reachable from where
  this came from.
- RBAC instead of shared keys or per-service access policies, scoped to the object
  rather than the whole account.

<!-- SLOT: escalation -->
- The actor read secrets, keys or customer data — assume disclosure and start the rotation
  and notification clocks now.
- The diagnostic setting for this resource was modified in the same window.
