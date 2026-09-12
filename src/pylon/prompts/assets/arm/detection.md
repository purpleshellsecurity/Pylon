
## Task: Phase 2 — Detection Queries for <service>__SERVICE__</service> (Azure ARM)

The threat analysis above was produced in Phase 1. Use it as your direct input.
Build one production-ready AzureActivity KQL detection for EACH attack vector identified.

Detection philosophy: AzureActivity only for all detections.

For EACH attack vector, choose one detection strategy:
- Simple Presence: Any occurrence is suspicious (RBAC changes, diagnostic setting deletion)
- Threshold: Normal at low volume, suspicious at scale (bulk deletions, mass role assignments)
- Context: Suspicious based on actor, timing, or scope
- Anomaly: First-time behavior
- Chained: Sequence of related operations within a time window

For EACH attack vector, produce exactly this structure:

---

## Detection N: [Attack Vector Name from Phase 1]

**Strategy:** [Simple Presence / Threshold / Context / Anomaly / Chained]

**MITRE ATT&CK:** [from Phase 1]

**Severity:** [from Phase 1 priority]

**What it detects:** [1 sentence]

**OperationNameValue:** [exact value from Phase 1 — plain text, no code block]

**Query:**
```kql
// ============================================================
// Detection: [Name]
// MITRE ATT&CK: [T####.### - Name]
// Strategy: [Strategy]
// Severity: [Severity]
// ============================================================

let AllowedActors = dynamic([]);  // fill: automation SPNs, break-glass, CI/CD
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue __OPERATOR__ "[exact OperationNameValue from Phase 1]"
| where ActivityStatusValue =~ "Success"
| where Caller !in (AllowedActors)
| extend Props = parse_json(Properties)
| extend Auth = parse_json(Authorization)
| extend AuthScope = tostring(Auth.scope)
// [Strategy-specific logic here]
| extend ActorUpn = Caller, ActorId = tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]), SrcIp = CallerIpAddress, TargetResource = ResourceId, Operation = OperationNameValue
| project TimeGenerated, ActorUpn, ActorId, SrcIp, TargetResource, Operation, ResourceGroup, SubscriptionId, AuthScope, CorrelationId;
```

**Tuning Notes:**
- [Threshold guidance if applicable]
- Known false positive: [most likely benign trigger]

Two bullets at most, one line each, 20 words or fewer per bullet. No preamble, and do not restate what the query does.

---

__QUERY_RULES__

Use the exact OperationNameValue strings from Phase 1. Do not invent operations not in Phase 1.