
## Task: Phase 1 — Threat Analysis for <service>__SERVICE__</service> (Azure ARM)

Perform a threat analysis for <service>__SERVICE__</service>. This output feeds Phase 2 detection development.

Rules:
- Only include attack vectors for REAL, DOCUMENTED Azure Resource Manager operations.
- Every OperationNameValue must be in exact PROVIDER/RESOURCETYPE/ACTION format as it appears in AzureActivity.
- Do NOT invent attack vectors. If uncertain whether an operation is logged in AzureActivity — omit it.
- Omitting is always allowed, including all of them. If nothing in this prompt can be grounded, an empty list is the right answer. Zero is a valid answer. That permission is about grounding, never about brevity: do not drop a vector you CAN ground here in order to keep the list short.
- Cover the surface, do not sample it. Work through the references above and account for every distinct behaviour they describe. A technique listed there that this log can evidence should appear as at least one attack vector. Reading data and destroying it are different vectors, and a recon phase and the change that follows it are two vectors, not one.
- No statistics, no attack chains, no APT attribution, no speculative logging gaps.
- MITRE mappings must use verified sub-techniques.
- Map every technique to the MITRE ATT&CK CLOUD matrix (platforms: IaaS, Identity Provider, Office Suite). Never use host/endpoint techniques for a cloud operation — e.g., do NOT use T1140 (Deobfuscate/Decode) or T1553 (Subvert Trust Controls) for a cloud key/secret/certificate action.
- READING a cloud secrets store — getting, listing or backing up a secret, a key OR a certificate — is T1555.006 (Cloud Secrets Management Stores), the same technique for all three object types, because the store is what is being raided.
- WRITING material into that store, or changing how it issues credentials, is NOT T1555.006. Planting a secret and rewriting a certificate issuance policy are different acts with different techniques; use the one the mappings above give for that exact operation.

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

| # | Attack Vector | Priority | MITRE ATT&CK | Log Table | Exact OperationNameValue | Alert Condition |
|---|--------------|----------|--------------|-----------|--------------------------|-----------------|

---

## Section 2: Technical Documentation

For EACH attack vector, use EXACTLY this structure. OperationNameValue and Log Table are plain bold text — no code blocks, no backticks.

---

### RBAC Role Assignment

**Priority:** 🔴 Critical

**OperationNameValue:** MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE

**Log Table:** AzureActivity

**Description:** This operation creates a new RBAC role assignment, granting a user, group, or service principal permissions over an Azure resource or scope. Attackers use this to establish persistent privileged access to Azure resources.

**Prerequisites:** Microsoft.Authorization/roleAssignments/write permission (Owner or User Access Administrator role)

**MITRE ATT&CK:** T1098.003 — Additional Cloud Roles

**Attacker's Objective:** Establish persistent privileged access to the target Azure resource scope.

---

Follow that exact format for every attack vector. OperationNameValue and Log Table are plain text — no code formatting.

Priority classification:
1. Modifies RBAC assignments or role definitions → Critical
2. Deletes or disables diagnostic settings or log profiles → Critical
3. Destroys evidence or removes monitoring resources → Critical
4. Modifies Key Vault access policies or firewall rules → Critical
5. Creates or modifies automation accounts or runbooks → High
6. Modifies NSG rules or network security configurations → High
7. Creates or modifies resources enabling persistence → High
8. Deletes resources causing disruption → High
9. Modifies storage account access or network rules → High
10. Read-only enumeration → Medium / Low

MITRE sub-technique decision tree:
- RBAC role assignment or modification → T1098.003
- Diagnostic setting or log profile deletion → T1562.008
- NSG or firewall rule modification → T1562.007
- Automation account or runbook modification → T1053.003
- VM run command or script execution → T1059.009
- Key Vault or secret access modification → T1552.001
- Resource deletion for disruption (bulk) → T1485
- Resource deletion for evidence removal → T1070.004
- Storage account public access → T1530
- New privileged resource creation → T1136.003