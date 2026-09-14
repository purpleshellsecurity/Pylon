"""Assemble the IR playbook in code, and ask the model only for what is left.

Three runs of the same vector produced three structurally different documents.
None used the fourteen sections. The cause was not a weak rule; it was that the
whole document was a REQUEST. Phase 3 handed the model a nearly-complete template
and asked it to "produce exactly the structure below", and a model handed a
document to reproduce rewrites it.

Measured on the rendered data-plane template: 336 lines, 21 bracketed blanks.
Sorted, they are

  9   the RESPONDER fills at 3am from the alert row (AlertTime, AlertActor, the
      correlation id, the containment timestamp). These must survive into the
      output as brackets -- filling them would be inventing alert data.
  6   PYLON ALREADY KNOWS (the detection name, its severity, its technique, its
      false-positive notes, the operation, and the read/write operation lists
      from the data-plane catalogue). Asking for these is how they drift: one
      run re-mapped T1485 to "unmapped (host/endpoint)" against the catalogue
      that maps it to Key Vault purge.
  3   genuinely need a model.

So the model is asked for four fields and Pylon renders the rest. What the
document looks like stops being a thing that can vary.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator


# A sentence ends where a terminator meets whitespace or the end of the string.
# Counting the characters instead -- `sum(v.count(c) for c in ".!?")` -- counts
# the dot in every dotted identifier, and the ARM plane writes them constantly.
# An attack_context naming `Microsoft.Authorization/roleAssignments` twice
# scored five sentences for three and the whole playbook was discarded before it
# ever rendered, on every ARM run, deterministically. No identifier's dot is
# followed by whitespace, so the lookahead is the whole fix.
_TERMINATOR = re.compile(r"[.!?]+(?=\s|$)")


def _sentences(text: str) -> int:
    """How many sentences a one-line string holds."""
    return len(_TERMINATOR.findall(text))

# The blank exactly as it appears in the rendered template -> where it comes
# from. "responder" means it stays a bracket: the value is on the alert row, in
# front of the person reading, and nowhere else.
RESPONDER_BLANKS: tuple[str, ...] = (
    "[FROM ALERT: TimeGenerated]",
    "[FROM ALERT: ActorUpn or ActorId]",
    "[FROM ALERT: ActorUpn]",
    "[FROM ALERT: ActorId]",
    "[FROM ALERT: SrcIp]",
    "[FROM ALERT: TargetResource]",
    "[FROM ALERT: CorrelationId]",
    # Storage-specific, and it earns its place: AccountName is the
    # StorageLogs contract's declared `scope` field and is projected by every
    # one of its recipes, so it is on the alert row in front of the reader --
    # which is what this list means. `current_state` needs the account NAME,
    # not its id: `az storage container-rm --storage-account` takes a name,
    # and TargetResource on a blob detection is the ObjectKey.
    "[FROM ALERT: AccountName]",
    "[TIME YOU RAN CONTAINMENT]",
    "[the resource from the alert]",
    "[the resource id]",
    "[THE WINDOW THE DETECTION AGGREGATES OVER, e.g. 1h / 24h / 7d]",
    # The cross-log pivots carry their own lets rather than reading the prelude.
    # Deliberate: a pivot is pasted on its own, into a different table's query,
    # often hours later, and a self-contained query survives that.
    "[object ID from the alert]",
    # AzureActivity.Caller holds a UPN for a user and an object id for a service
    # principal, so a pivot over it takes both and matches on whichever the
    # responder has. See pivot._predicate.
    "[actor UPN from the alert]",
    "[resource ID from the alert]",
    "[source IP from the alert]",
)


class PlaybookFill(BaseModel):
    """The only four things a playbook needs a model for.

    Everything else in the document is either a fact Pylon holds or text the
    responder supplies from the alert. Kept this small deliberately: each field
    here is a thing that can come back wrong, and the list is the whole surface.
    """

    what_happened: str = Field(
        description="ONE sentence naming what the actor achieved by this "
                    "operation. Not what the operation is; what it got them."
    )
    attack_context: str = Field(
        description="TWO OR THREE sentences: what the attacker achieved, and why "
                    "it matters on this specific resource. No generic prose."
    )
    why_it_matters: list[str] = Field(
        min_length=2, max_length=4,
        description="Two to four bullets on why this matters for THIS resource. "
                    "One clause each, no leading dash."
    )
    true_positive_indicators: list[str] = Field(
        min_length=2, max_length=4,
        description="Two to four things that, if the responder sees them, make "
                    "this REAL rather than routine. Specific to this operation "
                    "and this resource -- not 'outside business hours'. One "
                    "clause each, no leading dash or tick.",
    )
    containment_role: str = Field(
        description="The exact Azure RBAC role or access-policy permission that "
                    "grants this operation, as Azure names it (for example "
                    "'Key Vault Secrets Officer'). Removing it is the reversible "
                    "containment step."
    )

    @field_validator("what_happened")
    @classmethod
    def _one_sentence(cls, v: str) -> str:
        # A count in a prompt is a suggestion; a count on a field is a check.
        v = " ".join(v.split())
        if not v:
            raise ValueError("what_happened is empty")
        found = _sentences(v)
        if found > 2:
            raise ValueError(
                f"what_happened must be one sentence, found {found}")
        return v

    @field_validator("attack_context")
    @classmethod
    def _two_or_three_sentences(cls, v: str) -> str:
        v = " ".join(v.split())
        # The prompt asks for two or three; the bound keeps the slack it always
        # had. The message now states the bound it actually enforces -- the old
        # one said "two or three" while accepting one through four, which made a
        # rejection impossible to read against the rule it broke.
        found = _sentences(v)
        if not 1 <= found <= 4:
            raise ValueError(
                "attack_context must be between one and four sentences, "
                f"found {found}")
        return v

    @field_validator("why_it_matters")
    @classmethod
    def _clauses_not_paragraphs(cls, v: list[str]) -> list[str]:
        out = [" ".join(b.split()).lstrip("-• ").strip() for b in v]
        if any(not b for b in out):
            raise ValueError("why_it_matters has an empty bullet")
        if any(len(b.split()) > 30 for b in out):
            raise ValueError("why_it_matters bullets must be one clause each")
        return out

    @field_validator("true_positive_indicators")
    @classmethod
    def _indicators_not_prose(cls, v: list[str]) -> list[str]:
        # Same bound as why_it_matters: this is the other half of the
        # false-positive list, which Pylon already renders from the detection,
        # and the two are read side by side. A paragraph on one side of that
        # pair is unreadable next to a clause on the other.
        out = [" ".join(b.split()).lstrip("-•✓✗ ").strip() for b in v]
        if any(not b for b in out):
            raise ValueError("true_positive_indicators has an empty entry")
        if any(len(b.split()) > 30 for b in out):
            raise ValueError("true_positive_indicators must be one clause each")
        return out

    @field_validator("containment_role")
    @classmethod
    def _a_role_not_a_paragraph(cls, v: str) -> str:
        v = " ".join(v.split()).strip(" .")
        if not v or len(v.split()) > 8:
            raise ValueError("containment_role must be a role name, not prose")
        return v


def operation_lists(table: str) -> tuple[str, str]:
    """(reads, writes) for `table`, as KQL string lists, from the catalogue.

    The template asks the model for "the read operations for this table" inside a
    `has_any (...)`. The catalogue tags every operation with a verb, so this is a
    lookup, not a recall -- and a recalled list is a list of plausible operation
    names, which is the exact failure the operation vocabulary exists to stop.
    """
    from . import data_plane_operations as dp

    block = dp._tables().get(table) or {}
    ops = block.get("operations") or {}
    reads, writes = [], []
    for name, meta in ops.items():
        verb = (meta or {}).get("verb", "")
        if verb in ("read", "list"):
            reads.append(name)
        elif verb in ("write", "delete"):
            writes.append(name)
    fmt = lambda names: ", ".join(f'"{n}"' for n in sorted(names))
    return fmt(reads), fmt(writes)


# The per-table normalisation the data-plane queries open with. The asset used to
# carry BOTH lines with "keep one and delete the other" — a choice the model made
# and Pylon now has to make, because nobody is reading the instruction any more.
# Shipped as-was, a Key Vault playbook read RequesterUpn and StatusCode, which are
# Storage columns: every query in it returned an error instead of rows, and the
# checker passed it because `validate_kql` does not flag a missing column on the
# right of an `extend`.
# Hand-written shapes for the tables whose answer is NOT a bare contract column:
# Key Vault's principal is a claim bag and its outcome is a numeric status, and
# the storage family shares one vocabulary. Every other table -- including every
# table added from here on -- is derived from its own contract by
# `_contract_normalisation`. There is deliberately no "_storage" default any
# more: it silently applied storage's columns to three App Service tables and
# broke every query in the first half of their playbooks.
_NORMALISE: dict[str, dict[str, str]] = {
    "identity": {
        "AZKVAuditLogs": "tostring(Identity.claim.upn)",
        "StorageBlobLogs": "RequesterUpn",
        "StorageFileLogs": "RequesterUpn",
        "StorageQueueLogs": "RequesterUpn",
        "StorageTableLogs": "RequesterUpn",
    },
    "actor_id": {
        "AZKVAuditLogs": "tostring(Identity.claim.oid)",
        "StorageBlobLogs": "RequesterObjectId",
        "StorageFileLogs": "RequesterObjectId",
        "StorageQueueLogs": "RequesterObjectId",
        "StorageTableLogs": "RequesterObjectId",
    },
    "failure": {
        "AZKVAuditLogs": "HttpStatusCode >= 300",
        "StorageBlobLogs": 'StatusCode != "200"',
        "StorageFileLogs": 'StatusCode != "200"',
        "StorageQueueLogs": 'StatusCode != "200"',
        "StorageTableLogs": 'StatusCode != "200"',
    },
    "agent": {
        "AZKVAuditLogs": "ClientInfo",
        "StorageBlobLogs": "UserAgentHeader",
        "StorageFileLogs": "UserAgentHeader",
        "StorageQueueLogs": "UserAgentHeader",
        "StorageTableLogs": "UserAgentHeader",
    },
}


def _operation_column(table: str, section: str = "") -> str:
    """The column this table filters an operation on.

    `OperationName` was spelled into the data-plane asset six times. It is the
    right column on Key Vault, the four storage tables and AzureDiagnostics, and
    it does not exist on the other two: an IP-restriction row's verb is `Result`
    and a Function App host line's is `Category`. Measured against the
    workspace, four of each table's queries failed to resolve it.

    The contract has said which column this is all along; the asset was simply
    not asking.
    """
    from . import contracts

    c = contracts.for_table(table) or {}
    return (c.get("operation") or {}).get("column") or "OperationName"


def _src_ip(table: str) -> str:
    """The column holding the source address on `table`, or a literal empty
    string when it has none.

    The data-plane asset spelled `CallerIpAddress` in three places. Key Vault
    and the four storage tables have that column, so it was right for five of
    the eight tables on the asset and a HARD ERROR on the other three -- the
    App Service pair carry UserAddress and CIp, and the Function App host log
    carries no address at all. Measured against the workspace: the query fails
    to resolve the column and returns nothing, so a responder pasting it at 3am
    gets an error rather than an answer.

    `""` is deliberate for a table with no address. `make_set("", 50)` is valid
    KQL and renders an empty set, which is the true answer; leaving the column
    name in place renders an error.
    """
    from . import correlation as _co

    ip = _co.ip_field(table) or {}
    return ip.get("extract") or ip.get("field") or '""'


def _contract_normalisation(table: str) -> dict[str, str]:
    """The normalise shapes for a table with a contract and no hand-written entry.

    The fallback used to be the STORAGE shapes -- RequesterUpn, RequesterObjectId,
    StatusCode, UserAgentHeader -- for any table `_NORMALISE` did not name. That
    was right for the four storage tables it was written from and a hard error on
    every table added since: measured against the workspace, the playbooks for
    AppServiceAuditLogs, AppServiceIPSecAuditLogs and FunctionAppLogs each failed
    four or five of their own queries with "Failed to resolve scalar expression
    named 'RequesterUpn'". Three tables, shipping, every query in the first half
    of the document.

    A default that is silently wrong for everything outside the set it was
    written from is worse than no default: the queries parse in review and fail
    at 3am.
    """
    from . import contracts

    r = contracts.roles(table)
    actor = _actor_reference(table) or '""'
    oid = r.get("who_id") or ""
    oid = oid.split("--")[0].strip() if _is_column(oid) else actor
    outcome = r.get("outcome") or r.get("outcome_code") or ""
    outcome = outcome.split("--")[0].strip() if _is_column(outcome) else ""
    # An outcome column is compared to its OWN measured values, not to a number
    # and not to a borrowed vocabulary. The storage default compared to "200",
    # which is a storage status code and means nothing on a publishing logon.
    measured, _complete = contracts.vocabulary(table)
    good = [v for v in (measured.get(outcome) or [])
            if str(v).lower() in ("success", "succeeded", "completed", "allowed",
                                  "ok", "information", "true", "200")]
    if outcome and good:
        # Double quotes: KQL takes either, and every other string literal this
        # module emits is double-quoted. Python's repr picks single.
        fail = f"""{outcome} !in ({', '.join(f'"{v}"' for v in good)})"""
    elif outcome:
        fail = f'{outcome} !in ("Success", "Succeeded", "Completed", "Allowed")'
    else:
        fail = "false"
    agent = r.get("client") or r.get("agent") or ""
    agent = agent.split("--")[0].strip() if _is_column(agent) else '""'
    return {"identity": actor, "actor_id": oid, "failure": fail, "agent": agent}


def _correlated_query(table: str, section: str = "") -> str:
    """The "everything in the same operation" query, or the honest replacement.

    Three of the tables on the data-plane asset have no correlation column at
    all, and the query was emitted for them anyway: "Failed to resolve column
    or scalar expression named 'CorrelationId'", measured. A responder cannot
    act on a query that does not run, and telling them the table cannot answer
    this question is worth more than handing them one that errors.
    """
    from . import contracts

    r = contracts.roles(table, section)
    column = r.get("correlate") or ""
    column = column.split("--")[0].strip() if _is_column(column) else ""
    if not column and table not in ("AzureActivity", "AuditLogs"):
        c = contracts.for_table(table) or {}
        section_cols = ((c.get("services") or {}).get(section) or {}).get("columns") or []
        if "CorrelationId" in section_cols or "CorrelationId" in (c.get("typing") or {}):
            column = "CorrelationId"
    if not column:
        return (f"**Query 1 — Everything in the same correlated operation:** "
                f"not available on this table. `{table}` records no correlation "
                f"id, so there is no key that groups one operation's rows. Use "
                f"the actor and the time window below instead.")
    # Read the role directly rather than calling back into the normalisation
    # builder: that builder calls THIS function, and the round trip was an
    # immediate RecursionError on the shared table.
    if section:
        addr = r.get("from_where") or ""
        src = addr.split("--")[0].strip() if _is_column(addr) else '""'
    else:
        src = _src_ip(table)
    # The shared table narrows to its own service FIRST, here as everywhere
    # else. This query was the one place it did not, so a correlation lookup on
    # AzureDiagnostics returned every service in the tenant that shares a
    # correlation id -- which is the contract's defining warning about this
    # table, in the one query a responder runs to find out what else happened.
    from . import correlation as _co

    scoped = _co.scope(f"AzureDiagnostics/{section}") if section else ""
    lead = f"| where {scoped}\n" if scoped else ""
    # An empty address column is dropped rather than projected as "". A column
    # of empty strings implies the address was absent on the event; leaving it
    # out says the table does not record one.
    cols = [c for c in ("TimeGenerated", _operation_column(table, section), src,
                        "_ResourceId") if c and c != '""']
    return f"""**Query 1 — Everything in the same correlated operation:**
```kql
let AlertCorrelationId = "[FROM ALERT: CorrelationId]";
{table}
{lead}| where TimeGenerated between (AlertTime - 1h .. AlertTime + 1h)
// {column} is what joins this action to the ARM change in AzureActivity that
// enabled it.
| where {column} == AlertCorrelationId
| project {', '.join(cols)};
```"""


def _norm(part: str, table: str) -> str:
    named = _NORMALISE[part].get(table)
    return named if named else _contract_normalisation(table)[part]


def _shared_normalisation(section: str) -> dict[str, str]:
    """The same three shapes for one service of the shared table.

    Built from the contract's per-service roles rather than from a table-level
    map, because on AzureDiagnostics there IS no table-level answer: the caller
    is clientInfo_ObjectId_g on an Automation audit event, Caller_s on a job
    log, and server_principal_name_s on a SQL audit event. Falling through to
    the storage default gave all three `RequesterUpn`, a column no row in this
    table has ever carried -- valid KQL, zero rows, forever.

    The scope predicate leads. Without it the query reads every service in the
    tenant that writes here, which is the contract's defining warning about
    this table and not a detail.
    """
    from . import contracts

    r = contracts.roles("AzureDiagnostics", section)
    who = r.get("who") or ""
    who = who.split("--")[0].strip() if _is_column(who) else '""'
    ip = r.get("from_where") or ""
    ip = ip.split("--")[0].strip() if _is_column(ip) else '""'
    outcome = r.get("outcome") or ""
    outcome = outcome.split("--")[0].strip() if _is_column(outcome) else ""
    what = r.get("what") or ""
    what = what.split("--")[0].strip() if _is_column(what) else "OperationName"
    target = r.get("target") or ""
    target = target.split("--")[0].strip() if _is_column(target) else "_ResourceId"

    key = f"AzureDiagnostics/{section}"
    from . import correlation as _co
    scope = _co.scope(key)
    lead = f"| where {scope}\n" if scope else ""
    # An outcome column here is a STRING holding "true"/"false" or a result
    # word, never a number -- the contract says every AzureDiagnostics column is
    # typed string whatever its suffix says. `succeeded_s == false` does not
    # compile; the comparison has to be textual.
    fail = f'{outcome} !in ("Completed", "Success", "true")' if outcome else "false"
    return {
        "__NORMALISE_FULL__": (
            f"{lead}| extend ActorUpn = {who}, ActorId = {who},\n"
            f"         IsFailure = {fail}, UserAgent = \"\""),
        "__NORMALISE_ACTOR_FAIL__": f"{lead}| extend ActorUpn = {who}, IsFailure = {fail}",
        "__NORMALISE_ACTOR__": f"{lead}| extend ActorUpn = {who}",
        "__NORMALISE_CONTEXT__": (
            f"| extend SrcIp = {ip}, Operation = {what}, TargetResource = {target}"),
        "__SRC_IP__": ip,
        "__OPERATION_COLUMN__": what,
        "__CORRELATED_QUERY__": _correlated_query("AzureDiagnostics", section),
    }


def _gated(expr: str, table: str) -> str:
    """`expr`, or an iff that yields it only when the row actually names anybody.

    Measured on the storage family: of 196 rows, 38 authenticate with OAuth and
    carry a principal, and the other 158 -- TrustedAccess, SAS, anonymous --
    carry none. Projecting RequesterObjectId flat renders an empty column on
    four rows in five and reads as "nobody did this" rather than "this row
    cannot say". The contract has carried that gate and its consequence since it
    was written; the playbook projected the column flat anyway, and the
    contract checker said so every time anyone asked it.

    An `iff` rather than a `where`, deliberately: filtering the triage query to
    OAuth would hide the SAS and anonymous rows entirely, and those are the ones
    worth seeing on a storage incident.
    """
    from . import contracts

    gate = (contracts.for_table(table) or {}).get("attribution", {}).get("gate")
    return f'iff({gate}, {expr}, "")' if gate else expr


def normalisation(table: str, section: str = "") -> dict[str, str]:
    """The shapes the data-plane asset asks for, written for `table`."""
    if table == "AzureDiagnostics" and section:
        return _shared_normalisation(section)
    upn = _gated(_norm("identity", table), table)
    oid = _gated(_norm("actor_id", table), table)
    fail, agent = _norm("failure", table), _norm("agent", table)
    return {
        "__NORMALISE_FULL__": (
            f"| extend ActorUpn = {upn}, ActorId = {oid},\n"
            f"         IsFailure = {fail}, UserAgent = {agent}"),
        "__NORMALISE_ACTOR_FAIL__": f"| extend ActorUpn = {upn}, IsFailure = {fail}",
        "__NORMALISE_ACTOR__": f"| extend ActorUpn = {upn}",
        # The data-plane asset used to spell these three inline, which is fine
        # for a table with one answer and wrong for the shared one.
        "__NORMALISE_CONTEXT__": (
            f"| extend SrcIp = {_src_ip(table)}, "
            f"Operation = {_operation_column(table)}, "
            "TargetResource = _ResourceId"),
        "__SRC_IP__": _src_ip(table),
        "__OPERATION_COLUMN__": _operation_column(table),
        "__CORRELATED_QUERY__": _correlated_query(table),
    }


def reverse_sentence(table: str, operation: str) -> str:
    """What undoes this operation, for the responder — or plainly that nothing
    catalogued does.

    The graph asset used to tell the MODEL to "use the grounded containment
    reverse supplied with this prompt", which is an instruction, not a playbook
    step. Pylon holds the reverse, so it writes the sentence.
    """
    from . import operation_grounding

    ref = operation_grounding.reference(table, operation) or {}
    rev = ref.get("reverse") or {}
    name = rev.get("operation") or rev.get("action") or ""
    if name:
        desc = rev.get("description", "")
        return (f"Reverse it with **{name}**"
                + (f" — {desc}" if desc else "")
                + "\nRun it against the same object the alert names.")
    if (ref.get("recovery") or "") == "none":
        return ("This operation destroys permanently. Nothing reverses it, so "
                "containment here means stopping the next one, not undoing this "
                "one.")
    return ("No reverse operation is catalogued for this one. Identify the real "
            "inverse before acting, and record it here — do not guess at a "
            "command under time pressure.")


def facts(target, table: str) -> dict[str, str]:
    """The blanks Pylon can fill from what it already holds.

    Keyed by the blank's literal text in the rendered template, so a template
    edit that renames a blank shows up as an unfilled blank rather than as
    silently missing content.
    """
    reads, writes = operation_lists(table)
    det = target.detection
    return {
        "[Detection name from Phase 2]": det.vector_name,
        "[from Phase 2]": getattr(target, "priority", "") or "unstated",
        "[technique ID and name]": det.mitre_technique,
        "[common false positives]": (
            det.false_positive_notes or "application service accounts, backup jobs, CI/CD"
        ),
        "[the operation from Phase 2]": target.operation or det.vector_name,
        "[the reverse operation]": reverse_sentence(table, target.operation or ""),
        "[the read operations for this table]": reads or '"<no read operations catalogued>"',
        "[the write operations for this table]": writes or '"<no write operations catalogued>"',
    }


def render(template: str, target, table: str, fill: PlaybookFill,
           section: str = "") -> str:
    """The finished playbook: Pylon's facts, the model's five fields, and every
    responder blank left as a blank."""
    out = template
    for token, value in normalisation(table, section).items():
        out = out.replace(token, value)
    for blank, value in facts(target, table).items():
        out = out.replace(blank, value)
    for blank, value in (
        ("[1 sentence]", fill.what_happened),
        ("[2–3 sentences: what the attacker achieved, and why it matters here.]",
         fill.attack_context),
        ("[the role that grants this operation]", fill.containment_role),
        ("[why it matters]", "\n".join(f"- {b}" for b in fill.why_it_matters)),
        ("[true positive indicators]",
         "\n".join(f"- ✗ {b}" for b in fill.true_positive_indicators)),
    ):
        out = out.replace(blank, value)
    return out


def unfilled(document: str) -> list[str]:
    """Blanks left in a finished playbook that are NOT the responder's to fill.

    A blank nobody filled is a blank the responder cannot fill either, because
    the template never said where its value comes from. Reported rather than
    shipped.
    """
    import re

    return [
        f"[{m}]"
        for m in dict.fromkeys(re.findall(r"\[([^\]\[\n]{3,120})\]", document))
        # A quoted string in brackets is KQL indexing a dynamic column
        # (Claims["http://schemas..."]), not a blank anyone fills.
        if not m.lstrip().startswith(('"', "'"))
        and f"[{m}]" not in RESPONDER_BLANKS
    ]


FILL_TASK = """## Task: the five fields this playbook needs from you

Pylon assembles the document. It already holds the detection name, its severity,
its MITRE technique, its false-positive notes, the operation, and this table's
read and write operation lists — do not restate any of them, and do not re-map
the technique.

Return exactly these five fields:

- `what_happened` — ONE sentence naming what the actor ACHIEVED by this
  operation. Not what the operation is; what it got them.
- `attack_context` — TWO OR THREE sentences on what the attacker achieved and why
  it matters on this specific resource. Ground it in the operation reference
  supplied above, including whether the operation can be undone.
- `why_it_matters` — two to four bullets on why this matters for THIS resource.
  One clause each.
- `true_positive_indicators` — two to four things that, seen together with the
  alert, make this REAL rather than routine. The false-positive side is already
  held and rendered; this is the other half of that pair, so do not repeat it.
  Specific to this operation on this resource — "outside business hours" is true
  of every alert ever written and tells a responder nothing.
- `containment_role` — the exact Azure RBAC role or access-policy permission that
  grants this operation, as Azure names it. This is the thing a responder removes
  as the reversible containment step, so it must be a real role name.

Nothing else. No markdown document, no headings, no queries."""


def fill_prompt(playbook_prompt: str) -> str:
    """The Phase 3 prompt, with its "produce this whole document" task swapped for
    the three-field one.

    Everything BEFORE <task> is the grounding — the role, the KQL rules, the table
    schema, the operation vocabulary and the technique reference — and all of it
    still applies to writing three sentences about this operation. Only the task
    changes, so there is one grounding and not a second copy to drift from it.
    """
    head, sep, _rest = playbook_prompt.partition("<task>")
    if not sep:
        return f"{playbook_prompt}\n\n<task>\n{FILL_TASK}\n</task>"
    return f"{head}<task>\n{FILL_TASK}\n</task>"


def pivot_markdown(table: str) -> str:
    """The grounded cross-log pivots as document markdown, or '' when none exist.

    `pivot.render_pivot_block` is written for a prompt: bracketed labels, no
    fences. A responder needs headings and fenced queries, and the checker needs
    the fences to see the KQL at all.
    """
    from . import pivot

    plan = pivot.pivot_plan(table)
    if not plan:
        return ""
    out = []
    for hop in plan:
        out.append(f"**{hop['label']}**\n\n```kql\n{hop['kql'].strip()}\n```")
    return "\n\n".join(out)


def document_template(platform_id: str, service: str, target_label: str, *,
                      operation: str = "", technique: str = "",
                      az_provider: str = "") -> str:
    """The playbook as a DOCUMENT: skeleton assembled, prompt-only regions gone,
    every template token substituted, every blank still a blank.

    Same skeleton the prompt uses. `strip_guides` is the only difference, so the
    structure a run produces cannot diverge from the structure the prompt
    describes -- there is nothing to diverge from.
    """
    from .prompts import (_TABLE_RULES_KEY, _chain_for, _render, load_asset,
                          parse_slots, render_playbook, strip_guides)

    # The TABLE decides the chain. Deriving it from the request handed an
    # AZKVAuditLogs playbook the ARM asset, because the request's platform is not
    # the table's plane -- and the ARM asset's blanks are different ones, so the
    # document shipped with holes nobody could fill.
    chain = _TABLE_RULES_KEY.get(service) or _chain_for(platform_id, service)
    # The contract-rendered sections. Computed here rather than written into a
    # plane's asset because they differ per TABLE, and a plane serves several --
    # the data-plane asset covers Key Vault, four storage tables and three App
    # Service ones, whose actor columns are four different things.
    #
    # `containment_role` is passed as the blank the model fills later, not as a
    # value: this function builds the template, and `render()` substitutes the
    # fill afterwards. Passing the blank through keeps the PIM row in the policy
    # table without inventing a role name here.
    asset = load_asset(f"{chain}/playbook.md")
    # The plane's own prevention bullets are KEPT, not replaced. They carry
    # things no technique-level countermeasure does -- a private endpoint on the
    # data plane, Conditional Access on the directory -- and overriding the slot
    # outright silently dropped all three planes' specialities the first time
    # this was wired up.
    plane_prevention = (parse_slots(asset).get("prevention") or "").strip()
    computed = prevention(service, technique,
                          "[the role that grants this operation]",
                          operation, az_provider)
    if plane_prevention:
        computed = (f"{computed}\n\n**Also, specific to this plane**\n\n{plane_prevention}"
                    if computed else plane_prevention)

    assembled = render_playbook(
        asset,
        # Same composite key the engine's pivot block uses. Passing the bare
        # table here and the composite there would put one service's pivots in
        # the prompt and another's in the document.
        pivots=pivot_markdown(f"{service}/{az_provider}" if az_provider else service),
        attack_diagram=attack_diagram(service, operation, technique),
        assessment_questions=assessment_questions(service, az_provider),
        escalation_matrix=escalation_matrix(service, technique, az_provider),
        current_state=current_state(service),
        prevention=computed,
    )
    document = _render(
        strip_guides(assembled),
        service=service,
        target=target_label,
        chain=chain,
        platform_id=platform_id,
    )
    # Every asset opens with a <!-- GUIDE --> region, and stripping it leaves the
    # newline that followed. The title landed on line two on all three planes, so
    # a reader opening the file saw a blank before the heading and nothing here
    # asserted otherwise. The document starts at its title.
    return document.lstrip("\n")


# ── Sections rendered from the contract ───────────────────────────────────────
#
# Everything below is ASSEMBLED, not asked for. The contract already records
# which column holds the actor, which holds the address, which values were
# measured and which columns cannot be relied on -- per table, and per service
# on the shared table. A model asked for the same content produces a different
# answer per run and cannot be checked against anything; rendered, it is the
# contract restated in the responder's language.

# A role in the contract, the question a responder asks at 3am, and why it
# decides anything. Ordered: this is the order the questions appear, and it is
# the order an incident is actually triaged in.
# Each question takes the FIRST role the contract actually defines, because the
# contracts name the same concept differently where the tables do: the object
# acted on is `target` on Key Vault, `target_host` on an IP-restriction
# decision, `function` on a Function App host log. One key per question would
# silently drop the row on two tables out of three.
_ROLE_QUESTIONS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("who", "who_id"), "Who did this?",
     "Separates a human from an automation principal, which is the single "
     "call that ends most alerts on this table."),
    (("from_where",), "Where did it come from?",
     "An address outside the actor's own baseline is the strongest signal "
     "available before any other pivot."),
    (("what",), "What exactly did they do?",
     "The alert names one operation; the row may carry a narrower verb that "
     "changes what was actually reached."),
    (("outcome", "outcome_code"), "Did it succeed?",
     "A failed attempt is a different incident from a completed one, and the "
     "containment clock differs."),
    (("target", "target_host", "function", "target_kind"), "What did it touch?",
     "Scopes the blast radius to an object rather than to the resource."),
)

# A role whose value is prose rather than a column name. The contracts say so
# in words -- "see identity recipe -- NOT a column", "none -- clientInfo_
# IpAddress_s is redacted the same way" -- because the honest answer to "which
# column holds the caller" is sometimes that none does. Rendering that prose as
# though it were a column name produces a query nobody can run.
_NOT_A_COLUMN = ("none", "see ", "not a column", "nobody", "n/a")


def _is_column(value: str) -> bool:
    """Whether a role's value names a column, or explains why it cannot."""
    v = value.strip()
    if not v or " " in v.split("--")[0].strip():
        return False
    return not any(v.lower().startswith(m) or m in v.lower() for m in _NOT_A_COLUMN)


def _actor_reference(table: str, service: str = "") -> str:
    """How a responder names the actor on this table, or "" when it has none.

    ONE answer, used by the triage questions, the diagram and the monitoring
    notes. The contract and the correlation map disagree about Key Vault on
    purpose: the contract says "see identity recipe -- NOT a column", which is
    true, and the map carries the expression that digs the principal out of the
    claim bag. Reading only the contract rendered Key Vault as actor-less in
    three separate places -- no baseline, no triage question, and a diagram that
    opened on "source address" for a table that names the caller on every row.
    """
    from . import contracts, correlation as _co
    from .pivot import _actor_expr

    # A per-service section of a shared table has its own actor column and the
    # correlation map is keyed by table, so the contract wins there.
    if service:
        who = (contracts.roles(table, service).get("who")
               or contracts.roles(table, service).get("who_id") or "")
        return who.split("--")[0].strip() if _is_column(who) else ""
    fields = _co.actor_fields(table)
    if fields:
        preferred = next((f for f in fields if f["kind"] == "oid"), fields[0])
        return _actor_expr(preferred)
    who = contracts.roles(table).get("who") or contracts.roles(table).get("who_id") or ""
    return who.split("--")[0].strip() if _is_column(who) else ""


def assessment_questions(table: str, service: str = "") -> str:
    """The triage table: the questions a responder answers first, each pointing
    at the column on THIS table that answers it. '' when there is no contract.

    Five at most, and fewer when the table genuinely cannot answer one. An
    Automation audit event has no usable source address -- the column exists
    and holds "{scrubbed}" -- so the question is rendered with that as its
    answer rather than omitted, because a responder who does not know the field
    is redacted will go looking for it.
    """
    from . import contracts

    r = contracts.roles(table, service)
    if not r:
        return ""
    unusable = contracts.unusable(table, service)
    actor = _actor_reference(table, service)
    rows = []
    for keys, question, why in _ROLE_QUESTIONS:
        value = next((r[k] for k in keys if r.get(k)), "")
        # The contract's prose about the caller is a note for whoever writes the
        # query, not an answer for whoever reads the alert at 3am. When there is
        # a usable expression, show that instead.
        if keys[0] == "who" and actor:
            value = actor
        if not value:
            continue
        if _is_column(value):
            column = value.split("--")[0].strip()
            where = f"`{column}`"
            if column in unusable:
                where = f"`{column}` — {unusable[column]}"
                why = "Not answerable from this table. " + why
        else:
            # The contract's own words. It explains why there is no column,
            # which is the thing the responder needs.
            where = value.strip()
            why = "Not a single column. " + why
        rows.append(f"| {question} | {where} | {why} |")
    if not rows:
        return ""
    return "\n".join(
        ["| Question | Where to find it | Why it matters |",
         "|---|---|---|"] + rows)


def escalation_matrix(table: str, technique: str = "", service: str = "") -> str:
    """Condition / risk / action, three tiers, ordered most severe first.

    The tier of the mapped technique decides the top row, and it decides it
    from ATT&CK's own tactics rather than from an opinion about what is worth
    waking someone for. A discovery technique does not get an IMMEDIATE row: it
    is how an attacker learns what is there, and treating enumeration as a
    page is how a rota stops reading the pages.
    """
    from . import contracts, knowledge

    r = contracts.roles(table, service)
    outcome = r.get("outcome") or r.get("outcome_code") or ""
    outcome_ref = f"`{outcome.split('--')[0].strip()}`" if _is_column(outcome) else "the outcome"

    tier = ""
    if technique:
        tid = technique.split()[0].strip()
        tactics = (knowledge._techniques().get(tid) or {}).get("tactics") or []
        names = set(tactics)
        if {"reconnaissance", "discovery", "resource-development"} & names:
            tier = "early"
        elif {"impact", "exfiltration", "credential-access"} & names:
            tier = "late"
        elif names:
            tier = "mid"

    rows: list[tuple[str, str, str]] = []
    if tier == "late":
        rows.append((
            f"{outcome_ref} shows it completed, and the actor is not in `AllowedActors`",
            "🔴 IMMEDIATE ESCALATION",
            "Contain now. Every resource in the blast-radius query is in scope until shown otherwise."))
    elif tier:
        rows.append((
            f"{outcome_ref} shows it completed, and the actor is not in `AllowedActors`",
            "🟡 STANDARD INVESTIGATION",
            "Work the investigation queries in order before containing; this is not yet an impact event."))

    # True on every plane and every table, and the reason it leads regardless of
    # tier: an actor working on the logging rather than on the resource has
    # changed what the rest of this playbook can prove.
    rows.append((
        "The same actor also changed diagnostic settings, activity-log alerts or log profiles in the window",
        "🔴 IMMEDIATE ESCALATION",
        "Treat visibility as compromised for the whole window, not just this resource. Escalate before continuing."))
    rows.append((
        "The blast-radius query returns more than one subscription, or reaches a production data plane",
        "🔴 IMMEDIATE ESCALATION",
        "This is no longer a single-resource incident. Hand to incident command."))
    rows.append((
        f"{outcome_ref} shows only failed attempts",
        "🟡 STANDARD INVESTIGATION",
        "Still work it — a failure means the attempt happened and the next one may not fail. Check what access was missing."))
    rows.append((
        "The actor is in `AllowedActors` and the change matches a known window",
        "🟢 MONITORING",
        "Record and close. Confirm the entry in `AllowedActors` is still justified at the next quarterly review."))
    if tier == "early":
        rows.append((
            "Enumeration only, with no subsequent write by the same actor",
            "🟢 MONITORING",
            "ATT&CK places this technique in the discovery phase. Track the actor; do not page on the read alone."))

    return "\n".join(
        ["| Condition | Risk | Action |", "|---|---|---|"]
        + [f"| {c} | {r_} | {a} |" for c, r_, a in rows])


def attack_diagram(table: str, operation: str, technique: str = "") -> str:
    """Where this incident's evidence lives, as a picture.

    Not the attack script's steps -- Pylon has no script at playbook time and
    drawing one from the operation alone would be invention. What it does have,
    and what a responder at 3am actually needs, is the chain from the actor to
    the row to the technique, and which other tables carry the rest of the
    story. Every box is a fact already in this document.
    """
    from . import contracts
    from .pivot import pivot_plan

    c = contracts.for_table(table) or {}
    op_col = (c.get("operation") or {}).get("column") or "OperationName"
    op_operator = (c.get("operation") or {}).get("operator") or "=="
    # Falls back to the blank `facts()` already fills from the target, rather
    # than inventing a new one: a blank this module coins is a blank nobody
    # fills, which `unfilled()` reports and a responder cannot act on.
    shown = operation or "[the operation from Phase 2]"

    onward = [h["table"] for h in pivot_plan(table) if h["table"] != table]
    onward = list(dict.fromkeys(onward))

    # A table with no actor column starts from an address, not a person. Drawing
    # "actor" at the top of an IP-restriction decision states the one thing the
    # contract says that row cannot carry.
    origin = "actor" if _actor_reference(table) else "source address"

    lines = [
        "```",
        f"   {origin}",
        "     │",
        "     ▼",
        f"   {shown}",
        "     │  recorded as one row",
        "     ▼",
        f"   {table}   {op_col} {op_operator} \"{shown}\"",
    ]
    if technique:
        lines += ["     │  mapped to", "     ▼", f"   {technique}"]
    if onward:
        lines += ["     │  the rest of the story is in", "     ▼",
                  "   " + ", ".join(onward)]
    lines.append("```")
    # HEADED, so it can be found. It rendered as a bare fence between the
    # metadata block and the first `---`, with no heading of its own, and round
    # nine reported the section absent from five playbooks it was present in --
    # nothing scanning the document's structure could see it, which for a
    # section is the same as not being there.
    #
    # The heading is returned WITH the diagram rather than written into the
    # skeleton, because the slot's default is the empty string: a heading in the
    # skeleton would stand alone over nothing whenever the diagram is empty.
    return "## Attack Sequence\n\n" + "\n".join(lines)


def prevention(table: str, technique: str = "", containment_role: str = "",
               operation: str = "", service: str = "") -> str:
    """Policies to enable, then what to monitor. Two sources, kept apart.

    The Control column is ATT&CK's own countermeasure name and the rest is
    Pylon's. They are separated because they are not the same kind of claim:
    "Data Backup" is published and generic, "enable purge protection on the
    vault" is a judgement about this resource, and a reader deciding what to
    argue for in a change meeting needs to know which is which.

    ATT&CK publishes no countermeasure for most discovery techniques -- it says
    so on the grounds that preventing enumeration breaks the service -- so the
    policy table is skipped rather than padded when the list comes back empty.
    """
    from . import contracts, knowledge

    out: list[str] = []
    tid = technique.split()[0].strip() if technique else ""
    published = (knowledge._techniques().get(tid) or {}).get("mitigations") or []

    if published:
        rows = []
        for name in published:
            how, reduction = _CONTROL_GUIDANCE.get(name, ("", ""))
            if not how:
                continue
            rows.append(f"| {name} | {how} | {reduction} |")
        if containment_role:
            rows.append(
                f"| Privileged Account Management | Move `{containment_role}` to PIM so it is "
                f"requested and time-bound rather than standing | Removes the standing grant "
                f"this operation needed |")
        if rows:
            out += ["**Policies to enable**", "",
                    "| Control | How to configure | Risk reduction |", "|---|---|---|"]
            out += rows
            out += ["", "Control names are ATT&CK's published countermeasures for "
                    f"{tid}; the configuration and the risk reduction are this playbook's.", ""]

    notes = monitoring(table, service)
    if notes:
        out += ["**Monitoring to configure**", ""] + [f"- {n}" for n in notes]
    return "\n".join(out).strip()


# ATT&CK names the countermeasure; this says what it means on Azure. Only the
# categories that reach a cloud technique are here -- a control with no entry is
# dropped from the table rather than rendered with an empty How column, because
# a row that does not say what to configure is not a recommendation.
_CONTROL_GUIDANCE: dict[str, tuple[str, str]] = {
    "Multi-factor Authentication": (
        "Conditional Access policy requiring phishing-resistant MFA for the role that grants this operation",
        "Stops a replayed or stolen credential reaching the operation at all"),
    "Privileged Account Management": (
        "PIM for the role rather than a standing assignment; approval required to activate",
        "Shrinks the window in which the grant exists to the minutes it is used"),
    "User Account Management": (
        "Scope the role assignment to the resource rather than the resource group or subscription",
        "An actor who gains the identity reaches one object instead of the whole scope"),
    "Data Backup": (
        "Enable the resource's own recovery feature and confirm it covers this object type",
        "Makes the destructive operation reversible, which changes the incident's severity"),
    "Network Segmentation": (
        "Private endpoint or service firewall so the data plane is not reachable from the public internet",
        "Removes the path this came in on"),
    "Filter Network Traffic": (
        "Resource firewall rules allowing only the addresses that legitimately reach it",
        "Turns an anonymous attempt into one that must come from a known network"),
    "Restrict File and Directory Permissions": (
        "RBAC scoped to the object rather than to the whole account or resource",
        "Narrows what a compromised identity can reach once inside"),
    "Encrypt Sensitive Information": (
        "Customer-managed keys, and TLS enforced on the data plane",
        "The data is unusable to an actor who reaches the storage layer alone"),
    "Audit": (
        "Confirm the diagnostic setting for this category is present and flowing, and alert on its removal",
        "This detection stops working silently if the setting is deleted"),
    "Account Use Policies": (
        "Sign-in risk and location conditions on the role, with session lifetime limits",
        "Reduces how long a stolen session stays usable"),
    "Active Directory Configuration": (
        "Review directory role assignments for the actor and remove ones not justified by a current duty",
        "Removes the standing access the operation depended on"),
    "Password Policies": (
        "Ban weak and breached passwords, and require passwordless for privileged accounts",
        "Closes the credential-guessing path to this identity"),
    "User Training": (
        "Brief the owning team on the consent and phishing shapes that lead to this operation",
        "The initial access step is the one control that is not technical"),
    "Operating System Configuration": (
        "Where the operation runs code — runbooks, function apps, VM extensions — restrict what that "
        "identity may execute",
        "Limits what the actor can do with the execution surface they reached"),
    "Disable or Remove Feature or Program": (
        "Turn off the publishing or management endpoint if the workload does not use it (FTP, SCM, "
        "remote debugging)",
        "Removes the surface rather than monitoring it"),
    "Limit Access to Resource Over Network": (
        "Restrict management endpoints to a bastion or named network",
        "The control plane stops being reachable from anywhere"),
}


def monitoring(table: str, service: str = "") -> list[str]:
    """What to baseline and what an absence proves, from the contract.

    Every line is a measured property of this table, not general advice. The
    interesting ones are the negative claims: which columns cannot be watched,
    whether a value nobody has seen before means anything, and how long a query
    has to look back before "no rows" is evidence of anything at all.
    """
    from . import contracts

    c = contracts.for_table(table)
    if not c:
        return []
    r = contracts.roles(table, service)
    out: list[str] = []

    # "Does this table name an actor" has one authoritative answer and it is the
    # correlation map, not the contract's prose. Key Vault's contract says "see
    # identity recipe -- NOT a column", which is true and does NOT mean the
    # table is actor-less: the principal is a claim bag, and the map carries the
    # expression that extracts it. Deciding from the contract string alone
    # rendered Key Vault as having no principal to baseline, which is wrong in
    # the quiet direction -- the responder simply never gets the line.
    from . import correlation as _co

    actor = _actor_reference(table, service)
    if actor:
        out.append(f"Baseline `{actor}` per resource over 30 days, and alert on a "
                   f"principal appearing for the first time.")
    from_where = r.get("from_where") or ""
    if _is_column(from_where):
        column = from_where.split("--")[0].strip()
        # Two corrections the correlation map already carries. The address is
        # not always the raw column -- AppServiceIPSecAuditLogs.CIp is
        # "address:ephemeral port", a different port every row, so a baseline
        # of raw values never repeats and every request looks new. And a table
        # with no actor has no principal to group by; the baseline is per
        # resource there, not per principal.
        ip = _co.ip_field(table) or {}
        expr = ip.get("extract") if ip.get("field") == column else ""
        ref = f"`{expr}`" if expr else f"`{column}`"
        per = "principal" if actor else "resource"
        out.append(f"Baseline the set of {ref} values per {per}; a new address "
                   f"for a known {per} is the cheapest signal this table offers.")
    elif from_where:
        out.append(f"Do not build an address baseline on this table: {from_where.strip()}.")

    # Capped. Key Vault has seventeen never-populated columns and listing all of
    # them buries the two that matter in a wall a responder skips. The reasons
    # are grouped because "redacted" and "always empty" have different fixes:
    # an empty column may fill, a scrubbed one never will.
    unusable = contracts.unusable(table, service)
    if unusable:
        redacted = sorted(k for k, v in unusable.items() if v.startswith("redacted"))
        empty = sorted(k for k in unusable if k not in redacted)
        if redacted:
            out.append("Never build a rule on "
                       + ", ".join(f"`{k}`" for k in redacted)
                       + ": these hold a literal placeholder, so a query on one returns "
                         "rows and names nobody.")
        if empty:
            shown = ", ".join(f"`{k}`" for k in empty[:5])
            more = f", and {len(empty) - 5} others" if len(empty) > 5 else ""
            out.append(f"Measured empty on this table, so a filter matches nothing: "
                       f"{shown}{more}.")

    measured, complete = contracts.vocabulary(table)
    for column in sorted(measured):
        if column in complete:
            out.append(f"`{column}` has a COMPLETE measured value set, so a value outside "
                       f"it is genuinely anomalous and worth alerting on first-seen.")
    open_sets = sorted(set(measured) - set(complete))
    if open_sets:
        out.append("Do not alert on first-seen values for "
                   + ", ".join(f"`{c_}`" for c_ in open_sets)
                   + ": the measured sets are incomplete, so an unseen value means "
                     "unexercised rather than anomalous.")

    ing = contracts.ingestion(table)
    if ing:
        lesson = ing.get("lesson") or ""
        pairs = "; ".join(f"{k.replace('_', ' ')} {v}" for k, v in ing.items() if k != "lesson")
        out.append(f"Ingestion delay on this table is uneven ({pairs}). "
                   + (lesson or "Size any absence-based rule's window accordingly."))
    return out


# What a service's present state looks like, beyond the two questions every
# resource answers. Keyed by the CONTRACT'S table, because that is what the
# playbook builder has in hand.
#
# EVERY COMMAND AND EVERY PROPERTY NAME HERE WAS RESOLVED AGAINST THE LIVE API
# BEFORE IT WAS WRITTEN, not recalled. `az storage container-rm list` is the ARM
# route rather than `az storage container list`: the data-plane one needs
# data-plane auth and returns XML, and the control-plane one answers the same
# question in JSON from the same credentials as the line above it.
_SERVICE_STATE: dict[str, tuple[str, str]] = {
    "StorageBlobLogs": (
        "Is any container public, and can it be?",
        r"""
az storage account show --ids "[FROM ALERT: TargetResource]" \
    --query "{allowBlobPublicAccess:allowBlobPublicAccess, \
              publicNetworkAccess:publicNetworkAccess, \
              defaultAction:networkRuleSet.defaultAction, \
              allowSharedKeyAccess:allowSharedKeyAccess}" -o jsonc

# Which containers are public RIGHT NOW, and what still protects them.
az storage container-rm list --storage-account "[FROM ALERT: AccountName]" \
    --query "[].{name:name, publicAccess:publicAccess, \
                 hasLegalHold:hasLegalHold, \
                 hasImmutabilityPolicy:hasImmutabilityPolicy}" -o table
        """),
}


def current_state(table: str = "") -> str:
    """What the resource and the actor look like NOW, as opposed to what the
    logs recorded happening.

    The queries above read history; these commands read the present, and they
    answer a question no log can: a row saying a role assignment was created
    does not say whether it is still there.

    The first two are generic on purpose. `az resource show --ids` and
    `az role assignment list --assignee` work for every resource type and every
    principal Pylon targets, so neither needs a per-service cmdlet resolved
    before it can be emitted, and every table gets them.

    A SERVICE THAT CAN ANSWER MORE, DOES. Round nine read a blob playbook whose
    Attack Context said the actor had been checking "for publicly exposed
    containers", and whose current-state block never asked whether a container
    was public -- it would have read identically for Key Vault. Generic is the
    right floor and it was being used as the ceiling.

    Per-table, and only where the commands have been resolved against the live
    API. A table with no entry gets the two generic commands, which is what
    every table got before.
    """
    generic = """```bash
# What does the resource look like right now? (Not what the logs say happened.)
az resource show --ids "[FROM ALERT: TargetResource]" -o jsonc

# What access does the actor still hold, anywhere in the tenant?
az role assignment list --assignee "[FROM ALERT: ActorUpn or ActorId]" --all -o table
```
A log row says a change happened. These say whether it is still in place, which
is the question containment actually turns on."""
    extra = _SERVICE_STATE.get(table)
    if not extra:
        return generic
    question, commands = extra
    return f"{generic}\n\n**{question}**\n```bash\n{commands.strip()}\n```"
