
## Task: Phase 1 — Threat Analysis for <service>__SERVICE__</service> (Azure Data Plane)

Perform a threat analysis for <service>__SERVICE__</service>.

CRITICAL TABLE INSTRUCTION:
The Log Analytics table for this task is: __SERVICE__
You MUST use "__SERVICE__" as the log table in all output.
Do NOT use AzureDiagnostics. Do NOT use AzureActivity. Do NOT use any other table.
The table is "__SERVICE__" — use it exactly as written everywhere.

Rules:
- Only include attack vectors for REAL, DOCUMENTED operations in the __SERVICE__ table.
- Every OperationName must be the exact string that appears in __SERVICE__ logs.
- Do NOT invent attack vectors. If uncertain whether an operation is logged — omit it.
- Omitting is always allowed, including all of them. If nothing in this prompt can be grounded, an empty list is the right answer. Zero is a valid answer. That permission is about grounding, never about brevity: do not drop a vector you CAN ground here in order to keep the list short.
- Cover the surface, do not sample it. Work through the references above and account for every distinct behaviour they describe. A technique listed there that this log can evidence should appear as at least one attack vector. Reading data and destroying it are different vectors, and a recon phase and the change that follows it are two vectors, not one.
- No statistics, no attack chains, no APT attribution.
- MITRE mappings must use verified sub-techniques.
- Map every technique to the MITRE ATT&CK CLOUD matrix (platforms: IaaS, Identity Provider, Office Suite). Never use host/endpoint techniques for a cloud operation — e.g., do NOT use T1140 (Deobfuscate/Decode) or T1553 (Subvert Trust Controls) for a cloud key/secret/certificate action.
- READING a cloud secrets store — getting, listing or backing up a secret, a key OR a certificate — is T1555.006 (Cloud Secrets Management Stores), the same technique for all three object types, because the store is what is being raided.
- WRITING material into that store, or changing how it issues credentials, is NOT T1555.006. Planting a secret and rewriting a certificate issuance policy are different acts with different techniques; use the one the mappings above give for that exact operation.

Before listing attack vectors, reason through the service's full data access attack surface systematically, then produce the output below.

### Required Output Structure

## Section 1: Executive Summary

Write the summary CONTENT only. Do not repeat this heading, or any "Section N:" line, inside the text — it is a field of a structured response, and the page that displays it supplies its own heading.

**Log Table:** __SERVICE__

**Risk Distribution:**
- 🔴 Critical: [X] threats
- 🟡 High: [X] threats
- 🔵 Medium: [X] threats
- ⚪ Low: [X] threats

**Top Critical Threats:**

For each Critical threat use EXACTLY this format — one per block, separated by blank lines:

### [Threat Name]
[2 sentences: what the operation does and why it is security-relevant. Facts only.]

### [Threat Name]
[2 sentences]

[Continue for all Critical threats]

**Quick Reference Matrix:**

| # | Attack Vector | Priority | MITRE ATT&CK | Log Table | Exact OperationName | Alert Condition |
|---|--------------|----------|--------------|-----------|---------------------|-----------------|

All entries in the Log Table column must be: __SERVICE__

---

## Section 2: Technical Documentation

For EACH attack vector, use EXACTLY this structure. OperationName and Log Table are plain bold text — no code blocks, no backticks.

---

### [Example Attack Vector Name]

**Priority:** 🔴 Critical

**OperationName:** [exact operation name as it appears in __SERVICE__]

**Log Table:** __SERVICE__

**Description:** [2 sentences — what this operation does and why it is security-relevant]

**Prerequisites:** [minimum required permissions]

**MITRE ATT&CK:** T####.### — [Sub-technique Name]

**Attacker's Objective:** [immediate result of this single operation]

---

Follow that exact format for every attack vector. Log Table must always be __SERVICE__.

Priority classification:
1. Reads secrets, credentials, or keys → Critical
2. Bulk data read or download → Critical
3. Deletes data or disables logging → Critical
4. Authentication bypass → Critical
5. Modifies security-sensitive data → High
6. Creates persistence → High
7. Bulk enumeration → High
8. Anomalous access patterns → Medium
9. Read-only enumeration at low volume → Low