"""System prompt assembly — port of lib/prompts/index.ts.

Builds the prompt for a given platform, service, and phase from the verbatim
assets extracted from the original app (assets/**/*.md).

Routing logic:
    Management Plane (arm)   -> arm assets
    Data Plane (dataplane)   -> dataplane assets + per-table context
    Entra ID (entra)         -> entra assets (AuditLogs)

The service parameter is the TABLE NAME for Data Plane and Entra
(e.g. "StorageBlobLogs", "AuditLogs"); for Management Plane it is the
resource type (e.g. "Key Vault").

Assets use replacement tokens instead of f-string braces (KQL/JSON content
is full of literal braces): __SERVICE__, __TARGET__, __QUERY_RULES__.
"""

import re
from importlib import resources

from .constants import (
    GRAPH_ACTIVITY_TABLE,
    LEGACY_GRAPH_TABLE,
    PHASES,
    PLATFORMS,
    SIGNIN_TABLES,
    Platform,
    ServiceDefinition,
    get_platform,
    canonical_service,
    is_known_service,
    normalise_platform,
    table_for_target,
)
from .shared import (
    ACTOR_IDENTITY_RULE,
    CONTAINMENT_CMD,
    LOG_SOURCE,
    PLAYBOOK_SKELETON,
    PLAYBOOK_SLOT_DEFAULTS,
    QUERY_RULES,
)

__all__ = [
    "ACTOR_IDENTITY_RULE",
    "CONTAINMENT_CMD",
    "LEGACY_GRAPH_TABLE",
    "LOG_SOURCE",
    "PHASES",
    "PLATFORMS",
    "QUERY_RULES",
    "SIGNIN_TABLES",
    "Platform",
    "ServiceDefinition",
    "build_resource_prompt",
    "build_system_prompt",
    "get_platform",
    "is_grounded_table",
    "is_known_service",
    "load_asset",
    "table_context",
    "table_rules",
]

_ASSETS = resources.files(__name__) / "assets"

# Data Plane table -> per-table context asset, injected alongside the generic
# dataplane context (port of serviceContextMap).
def _dataplane_tables() -> frozenset[str]:
    """Which data-plane tables get their own schema block appended.

    This was a literal set, which is the same fact the registry holds and a
    second place for it to go stale: remove a target and the set keeps its row,
    so a table nothing offers still gets grounding assembled for it.
    """
    from ..services import tables_for, targets

    return frozenset(
        table
        for target in targets().values()
        if target.resource_type                      # Entra is not a data plane
        for table in tables_for(target.key)
        if table != "AzureActivity"                  # nor is the control plane
    )

# Platform-specific KQL rule bullets (port of the platform_rules section).
_KQL_RULES: dict[str, str] = {
    "arm": """- KQL: filter on OperationNameValue using =~ for case-insensitive matching — not OperationName
- KQL: filter ActivityStatusValue =~ "Success" for successful operations — not Result
- KQL: Caller and CallerIpAddress are plain strings — no tostring() parsing needed
- KQL: use parse_json() to extract nested fields from Properties and Authorization blobs
- KQL: no mv-expand needed — AzureActivity is a flat table
- KQL: time filter must be the FIRST operator after the table name
- KQL: end let-statement queries with a semicolon
- KQL: `Authorization` has exactly three keys — `scope`, `action`, `evidence`.
  There is NO top-level `role`. `tostring(Auth.role)` is always empty, so a
  query filtering on it matches nothing, ever, and reads as a quiet tenant
- KQL: `Authorization.evidence.role` is the role the CALLER held that permitted
  the action — NOT the role being granted. It is present on every row including
  resource group creates and deletes, so filtering on it fires on everything an
  Owner does
- KQL: `Properties.requestbody` is a JSON STRING nested inside the parsed
  Properties object, so it needs a SECOND parse. `parse_json(Properties).
  requestbody.properties.roleDefinitionId` returns "" — reach it with
  `parse_json(tostring(parse_json(Properties).requestbody))`. One parse silently
  yields empty and the detection matches nothing
- KQL: for a roleAssignments/write, the role being GRANTED is
  `Properties.requestbody.properties.roleDefinitionId` and that appears only on
  the `ActivityStatusValue == "Start"` row. The "Success" row carries the
  outcome and no requestbody, so a detection needing both the role and the
  outcome must join Start to Success on CorrelationId
- KQL: match a role by its roleDefinitionId GUID, not its display name. The
  built-in GUIDs, verified against Microsoft.Authorization/roleDefinitions:
    Owner                      8e3af657-a8ff-443c-a75c-2fe8c4bcb635
    User Access Administrator  18d7d88d-d35e-4fb5-a5c3-7773c20a72d9
    Contributor                b24988ac-6180-42a0-ab88-20f7382dd24c
    Reader                     acdd72a7-3385-48ef-bd42-f606fba81ae7
  Do not write a GUID from memory. One detection shipped with
  f1a07417-d97a-45cb-824c-7a7467783830 in a variable named UaaRoleId; that is
  Managed Identity Operator, so it searched for a different role than its own
  name
- KQL: `roleDefinitionId` in the request body is a FULL ARM PATH, not a bare
  GUID: `/subscriptions/<sub>/resourceGroups/<rg>/providers/
  Microsoft.Authorization/roleDefinitions/<role-guid>`. Three consequences, and
  a detection has hit all three in turn while looking identical each time —
  144 real grants, zero rows, a query that runs clean:
    * `where roleDefinitionId == "<guid>"` NEVER matches. Compare with
      `endswith` or `has` against the GUID
    * `extract(@"[0-9a-f-]{36}", 0, roleDefinitionId)` returns the
      SUBSCRIPTION, because the path begins /subscriptions/<guid>/ and that is
      the first match. Anchor it: `extract(@"([0-9a-f-]{36})$", 1, ...)`, or
      name the segment: `extract(@"/roleDefinitions/([0-9a-f-]{36})", 1, ...)`
    * the path's subscription and resource group are the SCOPE THE CALL WAS
      MADE AT, not the role. Do not read a role out of them
- KQL: `ResourceId` is EMPTY on every roleAssignments row — writes and deletes,
  Start and Success, 99 of 99 measured. A detection extracting the assignment
  id from it projects a blank column and any filter on it matches nothing. The
  id is in `Properties.entity`; `_ResourceId` (with the underscore, a different
  column) also carries it
- KQL: the role assignment GUID at the end of `entity` comes in BOTH shapes.
  Writes were dashed in every case measured; deletes were mixed, 17 of 23
  undashed. Accept both: `[0-9a-f-]{32,36}$`, or compare with `has` after
  stripping dashes from each side. A pattern written for one shape silently
  drops the other
- KQL: a roleAssignments DELETE carries NO roleDefinitionId — the delete is by
  assignment id, so the event does not say which role was removed. Naming the
  role in the detection's title and then not filtering on one is the failure
  here: it fires on every role removal in the tenant while claiming to watch
  one. Either join the delete back to the WRITE that created that assignment id
  (which only works while the grant is still in retention, and say so in the
  tuning guidance), or write the detection for privileged role removal as a
  class and title it that way
- KQL: AzureActivity is commonly ingested TWICE — an Activity Log export and a
  connector both writing to one workspace produce two rows per event sharing an
  EventDataId. A join then multiplies it: two Start rows against two Success
  rows is four alerts for one grant. Dedupe each leg with
  `| summarize take_any(*) by EventDataId` BEFORE joining
- KQL: PROJECT EventDataId in the final output. A responder with an alert and
  no event id cannot find the raw record, and the tooling cannot recover which
  rows a detection matched without it -- measured, 11 of 106 generated
  detections carried it, so nine in ten could not be traced back to their own
  evidence""",
    "dataplane": """- KQL: use the exact table name provided in the task — never substitute AzureDiagnostics
- KQL: identity field varies by service — use the correct field for the specific table
- KQL: always wrap dynamic field access in tostring()
- KQL: time filter must be the FIRST operator after the table name
- KQL: end let-statement queries with a semicolon
- KQL: project the table's row id (`Id` on the data-plane audit tables) in the
  final output, so an alert can be traced back to the record that raised it""",
    "entra": """- KQL: extract InitiatedBy fields BEFORE mv-expand
- KQL: always wrap dynamic field access in tostring()
- KQL: clean modifiedProperties with trim(@'[\\[\\]"\\s]', value)
- KQL: end let-statement queries with a semicolon
- KQL: time filter must be the FIRST operator after the table name
- KQL: filter Result == "success" — not ActivityStatusValue
- KQL: `TargetResources` is an ARRAY and a plain `mv-expand` over it emits ONE
  ALERT ROW PER ELEMENT. A directory role assignment carries six entries — the
  Role, the User, two Directory entries, a Request and an Other — so one grant
  pages a responder six times, four of them carrying nothing. Pull the entries
  you need onto the single row with `mv-apply ... on (summarize ...)` and
  `take_anyif(..., tostring(tr.type) =~ "Role")` instead of expanding
- KQL: `modifiedProperties[].displayName` holds the PORTAL's names, not the
  Microsoft Graph API's. Real values include "Included Updated Properties",
  "AppAddress", "ServicePrincipalName", "Role.DisplayName", "TemplateId". The
  API spellings — keyCredentials, passwordCredentials, appRoles,
  oauth2PermissionScopes, servicePrincipalNames, accountEnabled — NEVER appear,
  so a query filtering on them matches nothing. If you are unsure of a value,
  filter on OperationName instead of guessing a property name""",
}

# context asset appended (like the data-plane tables).

# ── Combined-bundle log-source routing ────────────────────────────────────────
# One routing block per bundle: the tables' official descriptions plus the
# decision rule the model applies to tag each attack vector with one table.

_ENTRA_ROUTING = """<log_source_routing>
Every attack vector here lands in AuditLogs. It is the canonical, richest record
of a change to a directory object, and it is the only Entra table this tool
grounds operation names against and validates queries for.

- A CHANGE to a directory object -> AuditLogs.
- A technique with a recon phase AND a change phase = TWO attack vectors, both
  in AuditLogs. A recon step this table cannot evidence is not a vector here.

Set each attack vector's log_table to AuditLogs.
</log_source_routing>"""

# Back-compat alias (old name referenced the two-table Graph routing block).
GRAPH_LOG_SOURCE_ROUTING = _ENTRA_ROUTING


# Table -> which platform's KQL rules apply (for resource-centric mode, where a
# single resource spans tables from different "platforms").
_TABLE_RULES_KEY: dict[str, str] = {
    "AzureActivity": "arm",
    "AZKVAuditLogs": "dataplane",
    "StorageBlobLogs": "dataplane",
    "StorageFileLogs": "dataplane",
    "StorageQueueLogs": "dataplane",
    "StorageTableLogs": "dataplane",
    "AuditLogs": "entra",
}

_GENERIC_TABLE_RULES = (
    "- KQL: every column must appear in <schema_reference>; if the one you need is\n"
    "  not there, omit the detection and name the missing column\n"
    "- KQL: time filter must be the FIRST operator after the table name"
)


def table_rules(table: str) -> str:
    """The platform-specific KQL rule bullets for a table, or generic rules when
    the table has no dedicated rule set."""
    key = _TABLE_RULES_KEY.get(table)
    return _KQL_RULES[key] if key else _GENERIC_TABLE_RULES


def is_grounded_table(table: str) -> bool:
    """True if we have both KQL rules and a schema asset for this table."""
    return table in _TABLE_RULES_KEY and bool(table_context(table))


def load_asset(relpath: str) -> str:
    """Read a verbatim prompt asset file (assets/<relpath>) as text."""
    return (_ASSETS / relpath).read_text(encoding="utf-8")


def table_context(table: str) -> str:
    """Per-table schema context (assets/tables/<Table>.md), '' if none."""
    path = _ASSETS / "tables" / f"{table}.md"
    return path.read_text(encoding="utf-8") if path.is_file() else ""


_SLOT = re.compile(r"<!--\s*SLOT:\s*(\w+)\s*-->\n(.*?)(?=<!--\s*SLOT:|\Z)", re.DOTALL)


_GUIDE = re.compile(r"[ \t]*<!-- GUIDE -->.*?<!-- /GUIDE -->[ \t]*\n?", re.DOTALL)


def strip_guides(text: str) -> str:
    """Remove the prompt-only regions, leaving the document.

    The playbook skeleton serves two readers. The model needs "produce the
    sections below, in this order" and "read the operation reference before
    writing this section"; the responder at 3am must never see either. Marking
    those regions keeps ONE skeleton instead of a prompt copy and a document copy
    that drift -- the failure this file has hit before with the six assets.
    """
    return _GUIDE.sub("", text)


def parse_slots(asset: str) -> dict[str, str]:
    """`<!-- SLOT: name -->` blocks from a playbook asset -> {name: markdown}.

    Anything before the first marker is the plane's TASK preamble and is kept
    under the reserved name "preamble"."""
    slots = {name: body.strip() for name, body in _SLOT.findall(asset)}
    first = _SLOT.search(asset)
    slots["preamble"] = (asset[: first.start()] if first else asset).strip()
    return slots


def render_playbook(asset: str, **overrides: str) -> str:
    """A plane's playbook asset -> the full task text, via PLAYBOOK_SKELETON.

    The six assets were ~70% identical with accidental differences, so a fix had
    to be repeated per file and sometimes was not — `\\$` survived in four of them.
    The structure now lives in one place; a plane fills only what differs, and an
    omitted slot falls back to a documented generic rather than vanishing.

    An asset with no slot markers is returned unchanged, so a plane that has not
    been converted still works.
    """
    if "<!-- SLOT:" not in asset:
        return asset
    slots = parse_slots(asset)
    # `overrides` is for a slot whose content is COMPUTED rather than written:
    # the cross-log pivots come from the correlation map, so no plane's asset can
    # carry them and the default is only the honest "none catalogued" fallback.
    filled = {k: overrides.get(k) or slots.get(k) or v
              for k, v in PLAYBOOK_SLOT_DEFAULTS.items()}
    body = PLAYBOOK_SKELETON.format(**filled)
    preamble = slots.get("preamble", "")
    return f"{preamble}\n\n{body}" if preamble else body


def _render(template: str, *, service: str, target: str | None, chain: str, platform_id: str) -> str:
    """Substitute an asset template's replacement tokens: __SERVICE__,
    __OPERATOR__, the chain/platform __QUERY_RULES__, and __TARGET__ (only when
    target is given).

    __OPERATOR__ exists because the playbook assets used to spell the comparison
    operator themselves, and the data-plane one said `=~` where
    `operation_match` says `==`. Two answers to one question, reaching the model
    in the detection and the playbook for the SAME operation. The operator is
    now read from `operation_match` at render time, so there is one store for it
    and the assets are readers.
    """
    from ..services import operation_match
    rendered = template.replace("__SERVICE__", service)
    rendered = rendered.replace("__OPERATOR__", operation_match(service)[0])
    query_rules = QUERY_RULES.get(chain, QUERY_RULES.get(platform_id, ""))
    if query_rules:
        query_rules += ACTOR_IDENTITY_RULE
    rendered = rendered.replace("__QUERY_RULES__", query_rules)
    if target is not None:
        rendered = rendered.replace("__TARGET__", target)
    return rendered


def _chain_for(platform_id: str, service: str) -> str:
    """Asset directory / rules chain for the (platform, service) pair.

    One chain per platform now. The `signin` and `graph_activity` chains were
    removed with the tables they served: no target can select a sign-in table or
    a Graph API access table, so those branches could not be reached and their
    assets could not be validated against a run.
    """
    return normalise_platform(platform_id)


# The role and the boilerplate rules are ONE definition, not five. There are
# five prompt builders -- generic, combined-bundle, M365, AzureDiagnostics and
# resource mode -- and each used to carry its own copy. Editing the generic one
# and believing the prompt had changed is exactly the failure this prevents:
# four builders kept the old text and every test still passed, because the
# tests only exercised the path that was edited.


def _role(subject: str) -> str:
    """The judgement the model makes on every query, not a job title.

    "Expert detection engineer" shapes no output. The precision/recall call
    does, and it is the same call whichever builder assembled the prompt, so
    only the subject varies.
    """
    # The subject lands mid-sentence, so it must be a bare noun phrase. A comma
    # starts a clause that detaches "that a SOC will deploy unmodified" from its
    # subject, and the sentence then reads as though the SOC deploys whatever
    # the clause described -- which is what the AzureDiagnostics subject did.
    # Measured: the five healthy subjects run 9-65 characters with no comma;
    # the broken one was 121. Checked here rather than in a test because every
    # builder calls this, so every prompt any test builds is covered, while a
    # test only covers the builders someone remembered to list.
    if "," in subject or len(subject) > 80:
        raise ValueError(f"role subject must be a bare noun phrase, got {subject!r}")
    return f"""<role>
You write Sentinel detections for {subject} that a SOC will deploy unmodified.
Two failures cost more than writing nothing: a query that returns no rows on a real
tenant because it references a field or value that does not exist, and a query that
fires on routine automation. Prefer a narrower detection you can defend to a broader
one you cannot.
</role>"""


# Each rule names what to do when it cannot be followed. "Do not hallucinate"
# describes a failure without giving a procedure, and the moment a model needs
# the rule is the moment it has no field to use -- so each carries its own exit.
# These name the sections in prose rather than by their XML tag on purpose: the
# tags are structural, and tests count them to assert a prompt carries exactly
# one schema block, or none of a technique block. A rule that quotes a tag
# breaks those assertions and, worse, points the model at a section that some
# phases do not include.
FIELD_RULE = (
    "- Every field you reference must appear in the schema reference above. If a\n"
    "  detection needs a field that is not there, omit that detection and name the\n"
    "  missing field."
)
CLAIM_RULE = (
    "- Every claim about API or log behaviour must be supported by this prompt. Where\n"
    "  the prompt does not settle it, say what you checked and what was missing."
)
UNMAPPED = "unmapped"
"""What a model writes when no technique in the prompt fits the vector.

A refusal, and asked for by name in MITRE_RULE below. Anything that screens
technique IDs has to know this string, or it reads an honest "I will not guess"
as a fabrication and substitutes a mapping nobody made.
"""

MITRE_RULE = (
    "- Do not supply a MITRE id from memory. Use only ids given in this prompt; if\n"
    f'  none of them fits the vector, write "{UNMAPPED}".'
)
OUTPUT_RULE = (
    "- Output must be copy-paste ready: no placeholders left in the query, no bracketed\n"
    "  text that a reader would have to fill in."
)

# Phase 1 said only "enumerate attack vectors across this surface", which sets no
# bar at all -- and a model met it with ONE vector for a Key Vault holding 78
# documented operations and nine mapped techniques. Everything downstream is
# capped by that number, so a thin Phase 1 is the cheapest possible way to make
# the whole tool look empty.
#
# The floor is tied to the grounding already in the prompt rather than to a
# count. "Produce at least 15" would be met by padding, and padding here means
# invented operations -- the one failure this pipeline cannot detect, because a
# fabricated vector still yields valid KQL against a real column and simply
# never fires.
COVERAGE_RULE = (
    "- Cover the surface, do not sample it. Work through the operation reference and the\n"
    "  curated technique mappings above, and account for every distinct behaviour they\n"
    "  describe. A technique listed there that this log can evidence must appear as at\n"
    "  least one attack vector.\n"
    "- One vector per distinct behaviour, not one per table. Reading material and\n"
    "  destroying it are different vectors. A recon phase and the change that follows it\n"
    "  are two vectors, not one.\n"
    "- Do not merge unrelated operations into one broad vector to keep the list short. A\n"
    "  vector naming five unrelated operations detects none of them well.\n"
    "- Stopping early is the failure mode here, but length is not the goal: padding the\n"
    "  list with operations that are not in the reference above is worse than stopping."
)


def _build_azure_diagnostics_prompt(
    phase_id: str,
    playbook_target: str | None,
    provider: str = "",
    categories: tuple[str, ...] = (),
    samples: tuple[str, ...] = (),
) -> str:
    """Generic AzureDiagnostics prompt for the dynamic-routing fallback: a
    resource type with no resource-specific table, routed to the shared
    AzureDiagnostics table (resolver.py). Unlike the data-plane assets — which
    hard-forbid AzureDiagnostics — this path NAMES AzureDiagnostics as the
    intended table and scopes it by ResourceProvider + Category so the shared
    table stays selective.

    Two grounding anchors fight the generic path's run-to-run variance (measured
    at 0% core coverage): the real emitted `categories` become the enumeration
    axis (systematic per-category coverage, not free association), and any
    provider-scoped `samples` (documented AzureDiagnostics KQL for this provider)
    give the model the real OperationName vocabulary. Samples are empty for
    providers the queries doc doesn't cover, so category anchoring is the floor."""
    provider = (provider or "").strip()
    provider_label = provider or "this Azure resource provider"
    provider_scope = provider.upper() if provider else "MICROSOFT.<PROVIDER>"
    cats = [c for c in categories if c and c.strip()]
    cat_hint = "; ".join(cats) if cats else "the resource's diagnostic log categories"
    # The categories come off the resolver as one comma-joined string per surface;
    # split back out so the model gets a real enumeration axis.
    cat_axis = [c.strip() for c in ", ".join(cats).split(",") if c.strip()]
    sample_block = ""
    if samples:
        joined = "\n\n".join(s for s in samples)
        sample_block = (
            "\n\nDocumented AzureDiagnostics queries for this provider (real "
            "OperationName / column vocabulary — prefer these values and shapes):\n"
            f"```\n{joined}\n```"
        )

    rules_block = (
        QUERY_RULES["azure-diagnostics"].replace("<PROVIDER>", provider_scope)
        + ACTOR_IDENTITY_RULE
    )

    # Not provider_label: its fallback is the words "this Azure resource
    # provider", which read correctly in the rules below but doubled the phrase
    # here. The AzureDiagnostics routing fact lives in <platform_rules>, so the
    # role needs only the noun phrase.
    role = _role(f"the Azure resource provider {provider}" if provider
                 else "an Azure resource provider with no resource-specific table")

    rules = f"""<platform_rules>
{FIELD_RULE}
- Log source: AzureDiagnostics (the shared/legacy Azure Monitor diagnostic table).
  {provider_label} does NOT publish a resource-specific table, so AzureDiagnostics
  IS the correct and intended table for every query here — never invent a
  per-resource table name.
{rules_block}
{CLAIM_RULE}
{MITRE_RULE}
- Map every technique to the MITRE ATT&CK CLOUD matrix (IaaS / Identity Provider /
  Office Suite). Never use host/endpoint techniques for a cloud operation.
{OUTPUT_RULE}
</platform_rules>"""

    schema = f"""
<schema_reference>
AzureDiagnostics is a shared table spanning many Azure services. Scope EVERY query
to this resource:
- ResourceProvider == "{provider_scope}"
- Category — this resource emits: {cat_hint}
Resource-specific fields are stored as type-suffixed dynamic columns (_s string,
_d double, _g guid, _b bool) — e.g. httpStatusCode_d, identity_claim_upn_s. Use the
suffixed names. Live AzureDiagnostics column documentation is appended below when
available — prefer those exact names over memory.{sample_block}
</schema_reference>"""

    if phase_id == "threat":
        # Anchor enumeration to the resource's real emitted categories so the set
        # is reproducible across runs, instead of free-associating a new set each
        # time (the measured 0%-core-coverage failure mode).
        if cat_axis:
            axis = "\n".join(f"  - {c}" for c in cat_axis)
            anchor = (
                "Work category by category — this resource emits these log "
                f"categories, and every attack vector must map to exactly one:\n{axis}\n"
                "Cover each category that carries security-relevant operations; do "
                "not invent categories beyond this list.\n\n"
            )
        else:
            anchor = ""
        task = f"""Phase 1 — Threat Analysis for {provider_label} via AzureDiagnostics.

{anchor}Enumerate real, documented attack vectors for this resource type. For EACH vector
set Log Table to AzureDiagnostics and give the exact OperationName plus the
Category it is logged under.

Rules:
- Only real, documented operations for this resource. No statistics, no attack
  chains, no APT attribution.
- Every detection scopes ResourceProvider == "{provider_scope}" and the relevant
  Category — this generic path is lower fidelity than a curated table, so be
  conservative and omit anything you are unsure is logged.
- Reason through the resource's data-access surface systematically, category by
  category, before answering.
{COVERAGE_RULE}"""
    elif phase_id == "detection":
        task = f"""Phase 2 — Detection Queries. You will be given ONE attack vector from a
completed Phase 1 threat analysis. Build ONE production-ready KQL detection over
the AzureDiagnostics table that:
- starts with AzureDiagnostics, time-filters first,
- scopes ResourceProvider == "{provider_scope}" and the vector's Category,
- filters the exact OperationName, and surfaces identity/resource fields using the
  correct _s/_d/_g/_b suffixed columns.

If the user message contains validator errors from a previous attempt, fix every
listed error."""
    else:
        task = f"""Phase 3 — IR Playbook. Build ONE focused incident-response playbook for the
detection named below: triage, investigation, containment. Use exact AzureDiagnostics
field names from the Phase 2 detection. Every command must be copy-paste ready.
Containment: {CONTAINMENT_CMD["azure-diagnostics"]}

Target: <target>{playbook_target}</target>"""

    techniques = technique_reference("AzureDiagnostics", phase_id)
    return f"{role}\n\n{rules}{schema}{techniques}\n\n<task>\n{task}\n</task>"


def build_resource_prompt(
    resource_type: str,
    phase_id: str,
    surfaces,
    playbook_target: str | None = None,
) -> str:
    """Resource-centric prompt: the model routes each attack vector across ALL
    of a resource's log surfaces. Generalizes combined Graph mode using the
    catalog. `surfaces` is a list of objects with .table/.covers/.note/.volume
    and a .prerequisite() method (catalog.LogSurface)."""
    if phase_id not in PHASES:
        raise ValueError(f"Unknown phase: {phase_id}")
    if phase_id == "playbook" and not playbook_target:
        raise ValueError("playbook_target is required when phase_id is 'playbook'")

    tables = [s.table for s in surfaces]

    role = _role(f"the Azure resource type {resource_type}")

    rule_blocks = "\n".join(
        f"- {s.table} KQL rules:\n{table_rules(s.table)}" for s in surfaces
    )
    rules = f"""<platform_rules>
{FIELD_RULE}
- This resource writes to multiple tables; follow the routing guidance below and
  each query must state its table on the first line and follow THAT table's rules.
{rule_blocks}
{CLAIM_RULE}
{MITRE_RULE}
{OUTPUT_RULE}
- Map every technique to the MITRE ATT&CK CLOUD matrix (platforms: IaaS, Identity
  Provider, Office Suite). Never use host/endpoint techniques for a cloud
  operation — e.g., do NOT use T1140 (Deobfuscate/Decode) or T1553 (Subvert Trust
  Controls) for a cloud key/secret/certificate action.
- For access to a cloud secrets/key/certificate store — reading, listing, backing
  up, importing, or using secrets, keys, OR certificates — use T1555.006 (Cloud
  Secrets Management Stores) consistently across all three object types.
</platform_rules>"""

    schema_blocks = []
    for s in surfaces:
        ctx = table_context(s.table)
        schema_blocks.append(f"## {s.table}\n{ctx}" if ctx else f"## {s.table}\n(schema not grounded — use only well-documented columns)")
    schema = "\n<schema_reference>\n" + "\n\n".join(schema_blocks) + "\n</schema_reference>"

    routing_lines = [
        "<log_source_routing>",
        "This resource writes to multiple tables. Route every attack vector to exactly one:",
        "",
    ]
    for s in surfaces:
        covers = "/".join(s.covers) if s.covers else "coverage not established"
        routing_lines.append(
            f"{s.table} — covers {covers}; {s.note} "
            f"(requires: {s.prerequisite()})"
        )
    routing_lines += [
        "",
        "Decision rule:",
        "- READ / enumeration / access-volume technique -> the table that covers 'read'.",
        "- CHANGE to the resource (create/modify/delete) -> the control-plane / admin table.",
        "- Prefer the tightest table that still covers the technique.",
        "- A technique with both a recon phase and a change phase = TWO attack vectors.",
        f"Set each attack vector's log_table to EXACTLY one of: {', '.join(tables)}.",
        "</log_source_routing>",
    ]
    routing = "\n".join(routing_lines)

    # The two blocks that ground a CHOICE, both threat-phase only for the same
    # reason: phase 1 picks the technique and the operation, and phase 2 is handed
    # both on the attack vector. Paying for them once per detection was measured
    # at ~2,600 tokens x 16 calls on a fifteen-vector run.
    #
    # Their absence here was a real regression. When the command line moved to
    # resource mode, every ARM and data-plane run stopped receiving the curated
    # ATT&CK vocabulary it had been getting -- 25.8k of prompt became 10.7k, and
    # the model went back to recalling techniques instead of choosing from a list.
    # The operation vocabulary is new: a resource type is only a target because
    # every one of its operations has a verdict, so there is now a definitive list
    # to hand over, and "only real, documented operations" stops being a bare
    # negative constraint.
    grounding = ""
    if phase_id == "threat":
        for s in surfaces:
            grounding += technique_reference(s.table, phase_id)
            grounding += operation_reference(resource_type, s.table, phase_id)

    if phase_id == "threat":
        task = f"""Phase 1 — Threat Analysis for {resource_type}.

Enumerate attack vectors across this resource's full surface (control-plane
changes and data-plane access). For EACH attack vector, set its log_table field
to the correct table per the routing rule above.

Rules:
- Only real, documented operations. No statistics, no attack chains, no APT attribution.
- Reason through the full surface systematically before answering.
{COVERAGE_RULE}"""
    elif phase_id == "detection":
        task = """Phase 2 — Detection Queries. You will be given ONE attack vector from a
completed Phase 1 threat analysis, including the log_table it was routed to.
Build ONE production-ready KQL detection that queries THAT table and follows
THAT table's rules. Use only fields documented for that table.

If the user message contains validator errors from a previous attempt, fix
every listed error."""
    else:
        task = f"""Phase 3 — IR Playbook. Build ONE focused incident-response playbook for the
detection named below: triage, investigation, containment. Use exact field
names from the Phase 2 detection provided. Every command must be copy-paste
ready.

Target: <target>{playbook_target}</target>"""

    return (f"{role}\n\n{rules}{schema}{grounding}\n\n{routing}\n\n"
            f"<task>\n{task}\n</task>")


# Chains whose table is fixed regardless of the service asked for. Everywhere
# else the service IS the table (dataplane tables, SigninLogs, Device* tables),
# so `service` is the fallback rather than a special case per chain.
_CHAIN_TABLE: dict[str, str] = {
    "arm": "AzureActivity",
    "azure-diagnostics": "AzureDiagnostics",
    "entra": "AuditLogs",
}


def entra_activity_reference(chain: str, phase_id: str,
                            category: str = "") -> str:
    """The documented AuditLogs OperationName vocabulary, as a prompt section.

    The Entra chain's rules said "Every OperationName must be the exact string
    that appears in AuditLogs" and gave one example — a negative constraint with
    nothing positive behind it, the same asymmetry that had the model recalling
    ATT&CK techniques instead of choosing them. Worse here, because nothing
    checked the result either: an Entra run's "operation warnings: 0" meant the
    check never ran, not that the operations were real.
    """
    # THREAT ONLY. Phase 1 chooses the operation; phase 2 is handed it on the
    # attack vector and writes a query around it. Injecting the vocabulary into
    # both meant paying for it once per detection — ~2,600 tokens x 16 calls on a
    # 15-vector run, against a run whose entire input was 44,000. Ground where the
    # choice is MADE; check where it is used (validation/operation.py).
    if chain != "entra" or phase_id != "threat":
        return ""
    from ..entra_audit_activities import render_for_prompt

    # Scoped to one Category when the target is a slice of the directory.
    #
    # Measured: a whole-directory run named 33 vectors out of 922 activities and
    # never looked at 34 of the 48 categories. Handing the model everything is
    # what produced a 3.6% sample that reads like a complete answer, so a sliced
    # target gets its own slice and nothing else -- the same narrowing that lets
    # Key Vault name 55 of 97.
    body = render_for_prompt((category,) if category else ())
    if not body:
        return ""
    head = ""
    if category:
        head = (f"This run covers the {category} category ONLY. Every activity it "
                f"can log is below, and there are no others in scope. Begin every "
                f"query with `| where Category =~ \"{category}\"` — the column "
                f"exists and it is what narrows a table carrying every directory "
                f"event in the tenant.\n")
    return f"\n<operation_reference>\n{head}{body}\n</operation_reference>"


def operation_reference(resource_type: str, table: str, phase_id: str) -> str:
    """The operations `table` can carry for `resource_type`, as a prompt section.

    A resource type is only offered because every operation behind it has a
    verdict -- mapped to a technique, or rejected in writing. That is what makes
    a definitive list possible: "these are the operations, there are no others."
    Without it the rule "only real, documented operations" is a negative
    constraint with nothing positive behind it, which is the same asymmetry that
    had the model recalling ATT&CK IDs instead of choosing them.

    Threat phase only. Phase 1 chooses the operation; phase 2 is handed it.
    """
    if phase_id != "threat":
        return ""
    from ..services import operation_column, operation_match, operation_vocabulary

    vocab = operation_vocabulary(resource_type, table)
    if not vocab:
        return ""
    operator, why = operation_match(table)
    head = (f"Every operation {table} can log for {resource_type}. Use one of "
            f"these strings verbatim; there are no others. Filter with "
            f"`{operation_column(table)} {operator} \"...\"`"
            + (f" ({why})" if why else "") + ".")
    body = "\n".join(f"- {name}" for name in vocab)
    return f"\n<operation_reference>\n{head}\n{body}\n</operation_reference>"


def technique_reference(table: str, phase_id: str) -> str:
    """The curated ATT&CK vocabulary for `table`, as a prompt section.

    Grounds the one thing generation left to recall. The platform rules say only
    "do not fabricate MITRE mappings" — a negative constraint — while handing the
    model a fully documented OPERATION vocabulary. So techniques were guessed, and
    a real-but-wrong ID survives every check: verify_mitre_ids confirms an ID is in
    the ATT&CK bundle, not that it describes the behaviour.

    Empty for the playbook phase (it responds to a technique, it does not choose
    one) and for any table the index has no opinion about — adding an empty
    section would assert that a table supports no techniques, which is a claim the
    index deliberately does not make.
    """
    # Threat phase only, for the same reason as the operation vocabulary: the
    # attack vector carries its technique into phase 2, which does not re-choose
    # it. verify_mitre_ids and the technique checker still cover the output.
    if phase_id != "threat":
        return ""
    from ..catalog.table_techniques import render_for_prompt

    body = render_for_prompt(table)
    return f"\n<technique_reference>\n{body}\n</technique_reference>" if body else ""


def _technique_reference_for(platform_id: str, service: str, chain: str, phase_id: str) -> str:
    """technique_reference for whichever table this (platform, service) queries."""
    return technique_reference(_CHAIN_TABLE.get(chain) or service, phase_id)


def build_system_prompt(
    platform_id: str,
    service: str,
    phase_id: str,
    playbook_target: str | None = None,
    *,
    az_provider: str = "",
    az_categories: tuple[str, ...] = (),
    az_samples: tuple[str, ...] = (),
    entra_category: str = "",
) -> str:
    """Assemble the detection system prompt for a (platform, service, phase),
    dispatching to the AzureDiagnostics, combined-bundle, or M365 builders when
    applicable and otherwise composing the role, platform KQL rules, per-table
    schema reference, and the phase task from the verbatim assets. Raises on an
    unknown phase or a playbook phase missing its target."""
    platform = get_platform(platform_id)

    if phase_id not in PHASES:
        raise ValueError(f"Unknown phase: {phase_id}")
    if phase_id == "playbook" and not playbook_target:
        raise ValueError("playbook_target is required when phase_id is 'playbook'")

    # Dynamic-routing generic path: a resource with no resource-specific table,
    # routed to the shared AzureDiagnostics table. Its own scoped prompt — the
    # data-plane assets forbid AzureDiagnostics, so they can't serve this path.
    if platform_id == "dataplane" and service == "AzureDiagnostics":
        return _build_azure_diagnostics_prompt(
            phase_id, playbook_target, az_provider, tuple(az_categories), tuple(az_samples)
        )

    # Past the AzureDiagnostics dispatch, everything here is keyed by table: the task asset
    # substitutes __SERVICE__ as the log table, and the schema and technique
    # blocks are both looked up by table name. A label resolves; anything else
    # passes through so an unknown name still fails where it is handled.
    service = canonical_service(platform_id, service)

    chain = _chain_for(platform_id, service)
    log_source = LOG_SOURCE.get(chain, LOG_SOURCE.get(platform_id, ""))

    # The role states the judgement the output needs, not a job title. "Expert
    # detection engineer" shapes nothing; the precision/recall tradeoff below
    # is the actual decision the model makes on every query it writes.
    role = f"""<role>
You write Sentinel detections for {platform.label} that a SOC will deploy unmodified.
Two failures cost more than writing nothing: a query that returns no rows on a real
tenant because it references a field or value that does not exist, and a query that
fires on routine automation. Prefer a narrower detection you can defend to a broader
one you cannot.
</role>"""

    # Every rule names what to do when the model cannot comply. "Do not
    # hallucinate" describes a failure without giving a procedure, and the
    # moment a model needs the rule is exactly the moment it has no field to
    # use -- so each one carries its own exit.
    rules = f"""<platform_rules>
{FIELD_RULE}
- Log source for this platform: {log_source}
{_KQL_RULES[chain]}
{CLAIM_RULE}
{MITRE_RULE}
{OUTPUT_RULE}
</platform_rules>"""

    # The chain's context.md carries what is true across the platform; the
    # per-table asset carries the columns. Data plane is the one platform whose
    # tables differ enough from each other to need both.
    schema_parts = [load_asset(f"{chain}/context.md")]
    if platform_id == "dataplane" and service in _dataplane_tables():
        schema_parts.append(table_context(service))
    schema = f"\n<schema_reference>{chr(10).join(schema_parts)}</schema_reference>"

    _asset = load_asset(f"{chain}/{phase_id}.md")
    if phase_id == "playbook":
        _asset = render_playbook(_asset)
    task = _render(
        _asset,
        service=service,
        target=playbook_target,
        chain=chain,
        platform_id=platform_id,
    )

    techniques = _technique_reference_for(platform_id, service, chain, phase_id)
    operations = entra_activity_reference(chain, phase_id, entra_category)
    return (f"{role}\n\n{rules}{schema}{operations}{techniques}"
            f"\n\n<task>\n{task}\n</task>")
