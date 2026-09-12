
## Task: Phase 2 — Detection Queries for <service>__SERVICE__</service> (Azure Data Plane)

The threat analysis above was produced in Phase 1. Use it as your direct input.
Build one production-ready KQL detection for EACH attack vector identified.

CRITICAL TABLE INSTRUCTION:
The Log Analytics table for ALL queries in this task is: __SERVICE__
Every single KQL query MUST start with: __SERVICE__
Do NOT use AzureDiagnostics. Do NOT use AzureActivity. Do NOT use any other table.
If you find yourself writing a different table name — stop and use __SERVICE__ instead.

For EACH attack vector, produce exactly this structure:

---

## Detection N: [Attack Vector Name from Phase 1]

**Strategy:** [Simple Presence / Threshold / Context / Anomaly / Chained]

**MITRE ATT&CK:** [from Phase 1]

**Severity:** [from Phase 1 priority]

**What it detects:** [1 sentence]

**Operation:** [exact value from Phase 1 — plain text, no code block]

**Log Table:** __SERVICE__

**Query:**
```kql
// ============================================================
// Detection: [Name]
// MITRE ATT&CK: [T####.### - Name]
// Strategy: [Strategy]
// Severity: [Severity]
// Log Table: __SERVICE__
// ============================================================

__SERVICE__
| where TimeGenerated > ago(1h)
| where [operation field] == "[exact operation value from Phase 1]"
| where [success filter appropriate for __SERVICE__]
| extend [identity fields appropriate for __SERVICE__]
// [Strategy-specific logic]
// CorrelationId is on all five of these tables. Project it — it is what
// joins a data-plane action to the ARM change that enabled it.
| project TimeGenerated, [operation field], [identity fields], [resource fields];
```

**Tuning Notes:**
- [Threshold guidance]
- Known false positive: [most likely benign trigger]

Two bullets at most, one line each, 20 words or fewer per bullet. No preamble, and do not restate what the query does.

---

__QUERY_RULES__

Use the exact operation strings from Phase 1. The column is OperationName on
all five of these tables.
Every query must use __SERVICE__ as the table — not AzureDiagnostics, not AzureActivity.