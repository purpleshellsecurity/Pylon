
## Task: Phase 2 — Detection Queries for <service>__SERVICE__</service> (Entra ID directory changes)

The threat analysis above was produced in Phase 1. Use it as your direct input.
Build one production-ready AuditLogs KQL detection for EACH attack vector identified.

Detection philosophy: AuditLogs only, in every phase. It is the one table this target covers.

For EACH attack vector, choose one detection strategy:
- Simple Presence: Any occurrence is suspicious (credential additions, high-privilege grants)
- Threshold: Normal at low volume, suspicious at scale
- Context: Suspicious based on actor, timing, or target
- Anomaly: First-time behavior
- Chained: Sequence of related operations within a time window

For EACH attack vector, produce exactly this structure:

---

## Detection N: [Attack Vector Name from Phase 1]

**Strategy:** [Simple Presence / Threshold / Context / Anomaly / Chained]

**MITRE ATT&CK:** [from Phase 1]

**Severity:** [from Phase 1 priority]

**What it detects:** [1 sentence]

**OperationName:** [exact value from Phase 1 — plain text, no code block]

**Query:**
```kql
// ============================================================
// Detection: [Name]
// MITRE ATT&CK: [T####.### - Name]
// Strategy: [Strategy]
// Severity: [Severity]
// ============================================================

AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName __OPERATOR__ "[exact operation name]"
| where Result == "success"

// Extract InitiatedBy BEFORE mv-expand
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend ActorAppId = tostring(InitiatedBy.app.appId)
| extend ActorAppName = tostring(InitiatedBy.app.displayName)
| extend ActorIP = tostring(InitiatedBy.user.ipAddress)

// NOW mv-expand
| mv-expand TargetResources
| extend TargetId = tostring(TargetResources.id)
| extend TargetType = tostring(TargetResources.type)
| extend TargetName = tostring(TargetResources.displayName)

// [Strategy-specific logic here]

| project TimeGenerated, OperationName, ActorUPN, ActorAppName, ActorAppId, ActorIP, TargetName, TargetId, CorrelationId;
```

**Tuning Notes:**
- [Threshold guidance if applicable]
- Known false positive: [most likely benign trigger]

Two bullets at most, one line each, 20 words or fewer per bullet. No preamble, and do not restate what the query does.

---

__QUERY_RULES__

Use the exact OperationName strings from Phase 1. Do not invent operations not in Phase 1.