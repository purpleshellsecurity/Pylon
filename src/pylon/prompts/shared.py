"""Shared prompt fragments — verbatim port of lib/prompts/shared/.

LOG_SOURCE is injected into system prompts so the model knows which tables
to use; QUERY_RULES into Phase 2 prompts; CONTAINMENT_CMD into Phase 3.
"""

LOG_SOURCE: dict[str, str] = {
    "arm": "AzureActivity",
    "dataplane": (
        "Service-specific diagnostic tables: AZKVAuditLogs, StorageBlobLogs, "
        "StorageFileLogs, StorageQueueLogs, StorageTableLogs"
    ),
    "entra": "AuditLogs",
}

# Appended to EVERY plane's rules (see prompts.build_detection_prompt). Sentinel's
# strong Account identifier for a cloud user is Name + UPNSuffix — the pair, split.
# The single full-UPN identifier (FullName) is documented as "not part of schema,
# included for backward compatibility", and resolves weakly. Since July 2026 the
# Name field holds only the UPN prefix, so the full UPN must be reconstructed from
# Name + UPNSuffix rather than stored whole.
# https://learn.microsoft.com/en-us/azure/sentinel/entities-reference
ACTOR_IDENTITY_RULE = """
- SPLIT THE ACTOR UPN (required, immediately after the normalize extend): `| extend ActorName = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[0]), ""), ActorUpnSuffix = iff(ActorUpn has "@", tostring(split(ActorUpn, "@")[1]), "")` and add both to the final project alongside ActorUpn. Sentinel's strong Account identifier is Name + UPNSuffix as a pair; the full UPN alone identifies an account only weakly. The iff guards a non-UPN actor (an object GUID, a service name), which must leave both empty rather than land a GUID in Name."""

QUERY_RULES: dict[str, str] = {
    "arm": """KQL Rules for AzureActivity (ARM):
- Time filter FIRST: | where TimeGenerated > ago(1h)
- Filter on OperationNameValue with =~ (case-insensitive): | where OperationNameValue =~ "MICROSOFT.PROVIDER/RESOURCE/ACTION"
- Filter ActivityStatusValue =~ "Success" — never use Result (that is an AuditLogs field)
- Caller and CallerIpAddress are plain strings — no tostring() or parse needed
- Claims is a JSON STRING; parse_json it first. The caller's object ID is under the FULL URI key `http://schemas.microsoft.com/identity/claims/objectidentifier` — there is no `oid` key. `appid` IS a short key. A wrong key name parses without error and silently yields "", so use these spellings exactly.
- Extract nested data with parse_json(): | extend Detail = parse_json(Properties)
- No COLUMN here holds an array, so never mv-expand a column. A value parsed
  out of Properties can be an array and must be expanded
- End let-statement queries with a semicolon
- EXCLUSION SCAFFOLDING (required): begin the query with `let AllowedActors = _GetWatchlist('ApprovedAutomation') | project SearchKey;` so the org maintains ONE list that both the detection and its Phase 3 playbook read, and add `// let AllowedActors = dynamic([]);  // fallback: no watchlist in this tenant` immediately below it and add `| where Caller !in (AllowedActors)` — empty by default, so the rule ships with a place to suppress known-good principals instead of firing on them on day one
- NORMALIZE OUTPUT (required): before the final project, map this table's fields to the shared entity schema — `| extend ActorUpn = Caller, ActorId = tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]), SrcIp = CallerIpAddress, TargetResource = ResourceId, Operation = OperationNameValue` — then `| project TimeGenerated, ActorUpn, ActorId, SrcIp, TargetResource, Operation` plus any raw columns useful for triage. Leave a field = "" when the table has no such value. This makes entity mapping and cross-table correlation uniform.""",
    "dataplane": """KQL Rules for Data Plane diagnostic tables:
- Time filter FIRST: | where TimeGenerated > ago(1h)
- Use the exact service-specific table provided — never substitute AzureDiagnostics
- Identity field varies by service — use the correct field for each table
- Always tostring() on dynamic fields
- End let-statement queries with a semicolon
- EXCLUSION SCAFFOLDING (required): begin the query with `let AllowedActors = _GetWatchlist('ApprovedAutomation') | project SearchKey;` so the org maintains ONE list that both the detection and its Phase 3 playbook read, and add `// let AllowedActors = dynamic([]);  // fallback: no watchlist in this tenant` immediately below it and add `| where the table's caller/identity field !in (AllowedActors)` — empty by default, so the rule ships with a place to suppress known-good principals instead of firing on them on day one
- NORMALIZE OUTPUT (required): before the final project, map this table's fields to the shared entity schema — `| extend ActorUpn/ActorId from the table's identity field(s), SrcIp from its client-IP field, TargetResource from the object/resource field, Operation = OperationName` — then `| project TimeGenerated, ActorUpn, ActorId, SrcIp, TargetResource, Operation` plus any raw columns useful for triage. Leave a field = "" when the table has no such value. This makes entity mapping and cross-table correlation uniform.""",
    "azure-diagnostics": """KQL Rules for the generic AzureDiagnostics table:
- Query the AzureDiagnostics table — this resource publishes NO resource-specific
  table, so AzureDiagnostics is correct here (do NOT invent a per-resource table)
- Time filter FIRST: | where TimeGenerated > ago(1h)
- SCOPE EVERY query to this resource type: | where ResourceProvider == "<PROVIDER>"
  (immediately after the time filter) — AzureDiagnostics is a shared table and an
  unscoped query matches unrelated resources
- Then scope the log Category: | where Category == "<one of the resource's categories>"
- AzureDiagnostics stores resource-specific fields as type-suffixed dynamic columns
  (_s string, _d double, _g guid, _b bool) — use the suffixed column names
  (e.g. httpStatusCode_d, identity_claim_upn_s); do not assume unsuffixed names
- Filter on OperationName plus ResourceProvider/Category — this generic path is
  lower fidelity than a curated table, so keep filters conservative and documented
- End let-statement queries with a semicolon
- EXCLUSION SCAFFOLDING (required): begin the query with `let AllowedActors = _GetWatchlist('ApprovedAutomation') | project SearchKey;` so the org maintains ONE list that both the detection and its Phase 3 playbook read, and add `// let AllowedActors = dynamic([]);  // fallback: no watchlist in this tenant` immediately below it and add `| where the caller identity column (e.g. identity_claim_upn_s) !in (AllowedActors)` — empty by default, so the rule ships with a place to suppress known-good principals instead of firing on them on day one
- NORMALIZE OUTPUT (required): before the final project, map this table's fields to the shared entity schema — `| extend ActorUpn from the caller-identity column (e.g. identity_claim_upn_s), SrcIp from the client-IP column, TargetResource = _ResourceId, Operation = OperationName` — then `| project TimeGenerated, ActorUpn, ActorId, SrcIp, TargetResource, Operation` plus any raw columns useful for triage. Leave a field = "" when the table has no such value. This makes entity mapping and cross-table correlation uniform.""",
    "entra": """KQL Rules for AuditLogs (Entra ID):
- OperationName MUST be matched with `=~`, never `==`. Documented activity names
  and the casing a tenant actually writes differ ("Delete Conditional Access
  policy" documented, "Delete conditional access policy" logged), and `==` is
  case-sensitive — the query then parses, runs clean and never matches.
- Time filter FIRST: | where TimeGenerated > ago(1h)
- Extract ALL InitiatedBy fields BEFORE mv-expand — violations produce empty fields
- Always tostring() on dynamic fields — never compare dynamic fields directly
- Clean modifiedProperties values: trim(@'[\\[\\]"\\s]', value) before comparison
- End let-statement queries with a semicolon
- Filter Result == "success" unless explicitly detecting failures
- EXCLUSION SCAFFOLDING (required): begin the query with `let AllowedActors = _GetWatchlist('ApprovedAutomation') | project SearchKey;` so the org maintains ONE list that both the detection and its Phase 3 playbook read, and add `// let AllowedActors = dynamic([]);  // fallback: no watchlist in this tenant` immediately below it and add `| where tostring(InitiatedBy.user.userPrincipalName) !in (AllowedActors)` — empty by default, so the rule ships with a place to suppress known-good principals instead of firing on them on day one
- NORMALIZE OUTPUT (required): before the final project, map this table's fields to the shared entity schema — `| extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName), ActorId = tostring(InitiatedBy.user.id), SrcIp = tostring(InitiatedBy.user.ipAddress), TargetResource = tostring(TargetResources[0].id), Operation = OperationName` — then `| project TimeGenerated, ActorUpn, ActorId, SrcIp, TargetResource, Operation` plus any raw columns useful for triage. Leave a field = "" when the table has no such value. This makes entity mapping and cross-table correlation uniform.""",
}

CONTAINMENT_CMD: dict[str, str] = {
    "arm": "Azure CLI / PowerShell with error handling and manual Azure Portal fallback",
    "dataplane": "Azure CLI / PowerShell with error handling and manual Azure Portal fallback",
    "azure-diagnostics": "Azure CLI / PowerShell with error handling and manual Azure Portal fallback",
    "entra": "PowerShell via Microsoft Graph SDK with try/catch and manual Entra Portal fallback",
}


# ── The Phase 3 playbook skeleton ─────────────────────────────────────────────
#
# The playbook assets were ~70% identical and their differences were accidental
# rather than designed: one plane had no Quick Decision block, another no blast
# radius, and only one had prevention or a structured recovery checklist. A
# correctness fix therefore had to be made once per plane, and was — `\$` survived
# in four files because nobody made the fifth edit.
#
# So the structure lives here once and each plane supplies only what differs,
# through the SLOTS below. A new doctrine section is added in one place and every
# plane gets it; a plane's genuine speciality still overrides.
#
# Slot names are the contract. An asset fills a slot with
#   <!-- SLOT: name -->
#   ...markdown...
# and anything it omits falls back to the generic text here, so a plane is never
# silently missing a section.
PLAYBOOK_SKELETON = """<!-- GUIDE -->
Output rules for this document, before anything else:

- EVERY query goes inside a fenced block opened with ```kql and closed with ```.
  Every PowerShell command goes inside a ```powershell fence. A bare indented
  query is not validated, cannot be copied cleanly at a console, and will be
  rejected. This is not formatting preference; it is how the queries get checked.
- Produce the sections below, in this order, with these headings. The order is
  the procedure: evidence is preserved BEFORE anything is contained, because
  containment destroys the evidence of what was reached.
- Use the MITRE technique the detection carries. Do not re-map it, do not mark it
  unmapped, and do not argue it belongs to another platform. If you think it is
  wrong, write the playbook against it anyway and say why in one line.
<!-- /GUIDE -->
# IR Playbook: __TARGET__

## Playbook Metadata
{metadata}

---

## Fill these in first

Every query below reads these. Set them ONCE here rather than pasting the same
value into eight separate `let` statements at 3am.

```kql
// ── paste from the alert, once ──────────────────────────────────────────────
let AlertTime      = datetime([FROM ALERT: TimeGenerated]);
let AlertActor     = "[FROM ALERT: ActorUpn or ActorId]";
let AlertSrcIp     = "[FROM ALERT: SrcIp]";
let AlertTarget    = "[FROM ALERT: TargetResource]";
// Triage window: derive it from the window the DETECTION itself aggregates over,
// not from habit. A rule firing on a 24h summarize gets nothing from ago(1h).
let TriageWindow   = [THE WINDOW THE DETECTION AGGREGATES OVER, e.g. 1h / 24h / 7d];
// Known-good principals. Prefer a Sentinel watchlist so one list serves both the
// detection and this playbook; the empty array is the documented fallback for a
// tenant with no watchlist configured.
let AllowedActors  = _GetWatchlist('ApprovedAutomation') | project SearchKey;
// let AllowedActors = dynamic([]);   // fallback: no watchlist in this tenant
```

---

## Attack Context
{attack_context}

---

## Quick Triage (3 minutes)

**Decide first:** {quick_decision}

{quick_triage}

---

## Scope of Actor Activity

**This query is deliberately NOT filtered by operation.** Every other query in this
playbook narrows to the operation that fired the alert; this one must not. The
question here is everything this actor did in the window, not the one thing you
already know about. Logging and monitoring tampering, credential additions and
lateral movement surface here on their own precisely because nothing filters them
out — and they are what turns one alert into an incident.

{scope_query}

**If any of these appear in the results, stop and look at them now:** {scope_guidance}

**Source IP and user agent are attacker-controlled.** Treat them as clustering and
anomaly signals — "this differs from the actor's own baseline" — never as evidence
that activity was benign. Do not clear an incident because the user agent looked
ordinary; an attacker who can set a header can set a familiar one.

---

## Investigation (5–10 minutes)

Project the NORMALIZED entity names — `ActorUpn`, `ActorName`, `ActorUpnSuffix`,
`ActorId`, `SrcIp`, `TargetResource`, `Operation` — alongside this table's raw
fields. The alert carries the normalized names; a playbook that shows only raw
per-table columns makes the analyst translate between two vocabularies while the
incident is live.

{investigation}

### Blast radius
{blast_radius}

---

## Cross-Log Pivots

The queries above stay on this playbook's PRIMARY table. Following one actor
ACROSS logs is a different job, and each of these carries the other table's real
field names rather than this one's.

{pivots}

---

## Preserve Evidence

**Run this BEFORE containment.** Containment destroys volatile state: revoking a
grant deletes the record of what scopes it held, isolating a device ends the
sessions you would have enumerated. Preservation is not paperwork, it is the only
chance to capture what the attacker had.

{preserve}

- Export the triage and investigation query results (Logs → Export → CSV), or
  re-run them later against a retention window that may have rolled.
- Capture the affected object as it stands now:
  `... | ConvertTo-Json -Depth 6 | Out-File ".\\evidence-<object>-<utc>.json"`
- Record token and session metadata before revocation — which sessions existed,
  issued when, from where.

---

## Containment

{containment}

**Every option above must state its undo.** "Reversible" is a claim, and {undo_stakes}
<!-- GUIDE -->
Where a grounded containment reverse was supplied with this prompt, use that
exact operation; where one was not, write the real command or say plainly that
the step cannot be reversed.
<!-- /GUIDE -->

---

## Eradication

Containment stops the access in flight. Eradication removes what the attacker
LEFT, and skipping it is how an account is disabled at 03:10 and signed back into
at 03:40. Work this list before declaring the incident closed:

{eradication}

---

## Validation

**Wait before you believe an empty result.** {dwell_time} A validation query run
sixty seconds after containment returns nothing because the data has not landed,
not because you succeeded.

**Positive control — run this first.** A broken diagnostic setting is
indistinguishable from successful containment: both produce zero rows.

```kql
{positive_control}
```

If THAT is also zero, your logging is broken, not your attacker. Stop and fix the
pipeline before reading anything below as success.

{validation}

---

## Recovery Verification
<!-- GUIDE -->
Read the operation reference supplied with this prompt before writing this section.

- It says **Recovery: NONE** — the object is destroyed and nothing brings it back.
  Say that in the first line. Do NOT write a restore, undelete or recover step, and
  do NOT imply the alert can be undone. Recovery here means restoring SERVICE:
  issue a replacement, update every consumer of the destroyed object, and record
  what was lost and who must be told.
- It names a reversing operation — use that operation, and say the retention window
  it must happen inside, because it expires.
- It says nothing about recovery — do not assume either way. Say what must be true
  before the resource returns to service, and leave the restore question to the
  responder rather than inventing a command.
<!-- /GUIDE -->

{recovery}

---

## Prevention
{prevention}

---

## Escalate immediately if

{escalation}
"""

# What a plane does not override. Every one of these is deliberately generic —
# a plane with something better says so in its own asset.
PLAYBOOK_SLOT_DEFAULTS: dict[str, str] = {
    "metadata": (
        "- **Detection:** __TARGET__\n- **MITRE:** [from Phase 2]\n"
        "- **Log source:** __SERVICE__\n- **Severity:** [from Phase 2]"
    ),
    "attack_context": "[2–3 sentences: what the attacker achieved, and why it matters here.]",
    "quick_decision": (
        "is this a known-good automation principal, or not? Check `AllowedActors` "
        "first — most alerts on this plane end here."
    ),
    "quick_triage": "[The 1–2 fastest queries that separate benign from real.]",
    "investigation": "[Queries that establish scope, sequence, and the actor's other activity.]",
    "blast_radius": (
        "[What else did this actor touch in the window? Count the distinct targets, "
        "not just the one in the alert.]"
    ),
    # NOT filtered by operation, on every plane — see the section text. Read/write
    # is offered only where the schema supports it: AzureActivity does not log
    # control-plane reads, AuditLogs is a change log so every row is a write, a
    # sign-in is neither, and the Device* tables have no read ActionType.
    "scope_query": (
        "[UNFILTERED by operation. The actor's full activity in the window: volume "
        "and rate against their own 30-day baseline, distinct source IPs and whether "
        "each is new to this actor, success vs failure.]"
    ),
    "scope_guidance": (
        "operations that modify logging, alerting, or authentication for this plane."
    ),
    "preserve": "",
    # Filled from the correlation map at render time, never by a model. The
    # section used to say the pivots were "supplied with this prompt", which is
    # an instruction that survived into the document — so the finished playbook
    # pointed the responder at something they could not see.
    "pivots": "_No cross-log pivots are catalogued for this table._",
    "containment": "[Options, least destructive first, each with its undo.]",
    "eradication": (
        "- Credentials or keys the actor added\n"
        "- Permissions, roles or grants the actor assigned\n"
        "- Persistence the actor configured (scheduled tasks, automation, rules)\n"
        "- Anything the actor created that outlives the session"
    ),
    "dwell_time": "Give the table its normal ingestion latency before reading a zero.",
    # Its OWN let. This is the FIRST query a responder runs, and it read
    # ContainmentTime from the block below it -- so it did not run at all, and
    # "no rows" would have read as a broken pipeline rather than a broken query.
    "positive_control": (
        "let ContainmentTime = datetime([TIME YOU RAN CONTAINMENT]);\n"
        "__SERVICE__\n| where TimeGenerated > ContainmentTime\n"
        "| summarize TotalRowsInWindow = count()"
    ),
    "validation": "[The query proving the specific containment worked.]",
    "recovery": "[What must be true before the account/resource returns to service.]",
    "prevention": "[One or two controls that would have stopped this, not a policy essay.]",
    # The cautionary example HAS to be plane-specific: a service principal is not a
    # thing an endpoint plane can contain, and the shared paragraph asserted one on
    # all six. That is the skeleton's own failure mode inverted — text that is true
    # in one place rendering everywhere.
    "undo_stakes": (
        "at 2am someone will contain the wrong thing — the wrong principal, the "
        "wrong resource, the wrong machine — and the undo is what makes that a "
        "delay instead of an outage."
    ),
    "escalation": (
        "- The actor reached data subject to a regulatory clock, or the blast radius "
        "extends beyond this subscription/tenant.\n"
        "- Containment failed twice, or the actor re-established access after it."
    ),
}
