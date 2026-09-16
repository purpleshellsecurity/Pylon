
## Task: Phase 1 — Threat Analysis for <service>__SERVICE__</service> (Entra ID directory changes)

Perform a threat analysis for <service>__SERVICE__</service>. This output feeds Phase 2 detection development.

Rules:
- Only include attack vectors for REAL, DOCUMENTED Entra ID audit activities —
  the activity names Entra writes to AuditLogs, not Graph API method names.
- Every OperationName must be the exact string that appears in AuditLogs.
- Do NOT invent attack vectors. If uncertain whether an operation is logged — omit it.
- Omitting is always allowed, including all of them. If nothing in this prompt can be grounded, an empty list is the right answer. Zero is a valid answer. That permission is about grounding, never about brevity: do not drop a vector you CAN ground here in order to keep the list short.
- Cover the surface, do not sample it. Work through the references above and account for every distinct behaviour they describe. A technique listed there that this log can evidence should appear as at least one attack vector. Reading data and destroying it are different vectors, and a recon phase and the change that follows it are two vectors, not one.
- No statistics, no attack chains, no APT attribution, no speculative logging gaps.
- MITRE mappings must use verified sub-techniques.

Before listing attack vectors, reason through the service's full attack surface systematically, then produce the output below.

### Required Output Structure

## Section 1: Executive Summary

Write the summary CONTENT only. Do not repeat this heading, or any "Section N:" line, inside the text — it is a field of a structured response, and the page that displays it supplies its own heading.

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

| # | Attack Vector | Priority | MITRE ATT&CK | Log Table | Exact Operation Name | Alert Condition |
|---|--------------|----------|--------------|-----------|---------------------|-----------------|

---

## Section 2: Technical Documentation

For EACH attack vector, use EXACTLY this structure. Operation and Log Table are plain bold text — no code blocks, no backticks, no fencing.

---

### Service Principal Credential Addition

**Priority:** 🔴 Critical

**Operation:** Add service principal credentials

**Log Table:** AuditLogs

**Description:** This operation adds password or certificate credentials to an existing service principal. Attackers use this to authenticate as the application without needing existing credentials.

**Prerequisites:** Application.ReadWrite.All or Directory.ReadWrite.All

**MITRE ATT&CK:** T1098.001 — Additional Cloud Credentials

**Attacker's Objective:** Establish persistent authentication as the target service principal.

---

Follow that exact format for every attack vector. Operation and Log Table are plain text — no code formatting.

Priority classification:
1. Adds authentication credentials → Critical
2. Grants high-privilege permissions → Critical
3. Disables or bypasses authentication / MFA / conditional access → Critical
4. Destroys evidence or removes indicators of compromise → Critical
5. Creates new service principal or application → High
6. Modifies security-relevant properties → High
7. Deletes resources causing disruption → High
8. Grants lower-privilege permissions → High
9. Read-only enumeration at scale → Medium / Low

MITRE sub-technique decision tree:
- Adding credentials (passwords, certs, keys, federated identities) → T1098.001
- Granting roles or permissions → T1098.003
- New account or service principal creation → T1136.003
- Resource deletion for evidence removal (single) → T1070.004
- Resource deletion for disruption (bulk 5+) → T1485
- Modifying authentication mechanism → T1556
- Account discovery / enumeration → T1087.004
- Removing permissions (disruption / access denial) → T1531