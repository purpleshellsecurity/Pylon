"""What a detection is allowed to assume about a table, written once.

Three validation gates already ask whether a query is well formed, whether the
engine accepts it, and whether it matches real events. None of them asks the
question that actually broke things: does this query read the table correctly.

A generated detection compared `StatusCode < 300` on a column typed string, so
it did not run. Another filtered `OperationName` on AzureActivity, where that
column exists and is never populated, so it ran and matched nothing. A third
projected `RequesterObjectId` without filtering on OAuth, so it ran, matched,
and named nobody in 158 of 196 rows. Each is a fact about one table that no
schema page states and that a model cannot reason its way to.

So each table gets a contract: the columns that carry each role, the ones that
are present and always empty, the typing that is not guessable from the values,
and KQL recipes that have been EXECUTED against a real workspace. One object
with two consumers -- rendered into the prompt, and asserted by `conforms()` --
because a rule written once for the model and again for the test is a rule that
drifts, and every defect this module exists to catch was exactly that drift.
"""

from __future__ import annotations

import functools
import re
from importlib import resources
from typing import Any

import yaml

_DIR = "catalog/contracts"


@functools.lru_cache(maxsize=1)
def _all() -> dict[str, dict[str, Any]]:
    """Every contract, keyed by the table it governs.

    A contract may govern several tables -- the four Storage tables share one
    schema family and one set of rules -- so a file either names a `table` or
    lists `tables`, and both spellings land here as one entry per table.
    """
    out: dict[str, dict[str, Any]] = {}
    root = resources.files("pylon") / _DIR
    if not root.is_dir():
        return out
    for entry in sorted(root.iterdir()):
        if not entry.name.endswith(".yaml"):
            continue
        doc = yaml.safe_load(entry.read_text(encoding="utf-8")) or {}
        names = doc.get("tables") or ([doc["table"]] if doc.get("table") else [])
        for name in names:
            out[name] = doc
    return out


def tables() -> frozenset[str]:
    """Tables with a contract."""
    return frozenset(_all())


def for_table(table: str) -> dict[str, Any] | None:
    return _all().get(table)


def _lines(prefix: str, values) -> list[str]:
    return [f"{prefix}{v}" for v in values]


def render(table: str) -> str:
    """The contract as prompt text, or "" when the table has none.

    Deliberately assembled from the same keys `conforms()` reads. A fact that
    reaches the model and not the check, or the check and not the model, is the
    shape of every defect in this module's docstring.
    """
    c = for_table(table)
    if not c:
        return ""
    out: list[str] = []
    op = c.get("operation") or {}
    if op.get("column"):
        out.append(f"- filter the operation on `{op['column']}` with `{op.get('operator', '==')}`")
    if op.get("never_use"):
        out.append(f"- NEVER filter on `{op['never_use']}`: {op.get('never_use_reason', 'it does not work here')}")

    never = c.get("never_populated") or []
    if never:
        out.append("- these columns exist in the schema and are ALWAYS empty, so a filter on "
                   "one matches nothing and projecting one implies a value that was never "
                   f"there: {', '.join(never)}")

    # A column that is populated so rarely it cannot be relied on, with the
    # count. Distinct from never_populated: the gate does NOT reject it, because
    # the claim "always empty" is false and a gate enforcing a false claim
    # rejects correct queries. The model still has to be told, or it reaches for
    # a column that is empty on 99.96% of rows and the detection looks fine.
    for column, detail in (c.get("effectively_empty") or {}).items():
        rows, of = detail.get("rows"), detail.get("of")
        only = detail.get("only_on")
        out.append(
            f"- `{column}` is populated on {rows} of {of} measured rows"
            + (f", all of them {only}" if only else "")
            + f". {str(detail.get('guidance', '')).strip()}")

    for column, cast in (c.get("typing") or {}).items():
        out.append(f"- `{column}` is typed {cast}")
    if (c.get("roles") or {}).get("outcome_cast"):
        out.append(f"- compare the outcome as `{c['roles']['outcome_cast']}`; "
                   "the raw column is a string and a numeric comparison does not run")

    for column, why in (c.get("casing_traps") or {}).items():
        out.append(f"- the column is spelled `{column}` exactly: {why.strip()}")

    gate = (c.get("attribution") or {}).get("gate")
    if gate:
        out.append(f"- a row only names a principal when `{gate}`; "
                   f"{(c['attribution'].get('consequence') or '').strip()}")

    payload = c.get("payload") or {}
    if payload.get("consequence"):
        out.append(f"- {payload['consequence'].strip()}")
    if payload.get("double_parse_required"):
        out.append(f"- {payload['double_parse_required'].strip()}")

    for key in ("null_row", "dual_shape"):
        text = (c.get("array_handling") or {}).get(key)
        if text:
            out.append(f"- {text.strip()}")
    jm = c.get("json_matching") or {}
    for text in jm.values():
        out.append(f"- {str(text).strip()}")

    out += _lines("- ", c.get("shape") or [])

    scoping = c.get("scoping") or {}
    if scoping.get("required"):
        out.append(f"- this table is SHARED by every service that writes to it, so "
                   f"filter {' and '.join('`' + r + '`' for r in scoping['required'])} "
                   f"before anything else: {(scoping.get('why') or '').strip()}")
    if c.get("column_existence"):
        out.append(f"- {str(c['column_existence']).strip()}")

    for key, section in (c.get("services") or {}).items():
        roles = ", ".join(f"{r} is `{col}`" for r, col in (section.get("roles") or {}).items()
                          if isinstance(col, str) and not col.startswith("none"))
        out.append(f"\n{key} -- {str(section.get('what','')).strip()}")
        if roles:
            out.append(f"  {roles}")
        if section.get("note"):
            out.append(f"  {str(section['note']).strip()}")
        # The VALUES, not just the column names. Naming `targetResources_Resource_s`
        # without saying it holds "Credential" sent a model to guess at
        # `AdditionalFields has "automationAccounts/credentials"` instead, which
        # matched nothing. These fed `conforms()` and not the prompt, which is
        # the exact drift this object exists to prevent.
        for column, values in (section.get("observed_values") or {}).items():
            if column.endswith("_note") or not isinstance(values, list):
                continue
            out.append(f"  `{column}` was measured to hold: "
                       + ", ".join(f'"{v}"' for v in values))
        for column, note in (section.get("observed_values") or {}).items():
            if column.endswith("_note"):
                out.append(f"  {str(note).strip()}")
        if section.get("redacted"):
            out.append(f"  REDACTED, always the literal \"{{scrubbed}}\": "
                       + ", ".join(section["redacted"]))
        if section.get("resource_id_note"):
            out.append(f"  {str(section['resource_id_note']).strip()}")
        if section.get("columns"):
            out.append(f"  the only columns this service sends: "
                       + ", ".join(map(str, section["columns"])))

    recipes = c.get("recipes") or {}
    if recipes:
        out.append("")
        out.append("Query shapes that have been RUN against a real workspace. Adapt one "
                   "rather than composing from scratch:")
        for name, body in recipes.items():
            out.append(f"\n{name}:\n{body.rstrip()}")
    return "\n".join(out)


# `//` to end of line, and both string forms, so a column named only inside a
# comment or a literal is not mistaken for one the query reads.
_COMMENT = re.compile(r"//[^\n]*")
_STRING = re.compile(r"@?\"(?:\"\"|[^\"])*\"|@?'(?:''|[^'])*'")


def _code(kql: str) -> str:
    return _STRING.sub(" ", _COMMENT.sub(" ", kql))


def conforms(kql: str, table: str) -> list[str]:
    """Every way this query contradicts its table's contract.

    Empty means it agrees, or that the table has no contract -- which is not the
    same thing and callers that report a verdict must say which.
    """
    c = for_table(table)
    if not c:
        return []
    code = _code(kql)
    # Comments gone, string literals KEPT. `code` blanks strings so a column
    # named inside one is not mistaken for a read; the operation-literal check
    # below needs the opposite, because the literal IS the thing being checked.
    literals = _COMMENT.sub(" ", kql)
    problems: list[str] = []

    def used(name: str) -> bool:
        return re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", code) is not None

    never_use = (c.get("operation") or {}).get("never_use")
    if never_use and used(never_use):
        problems.append(
            f"reads `{never_use}` on {table}: "
            f"{(c['operation'].get('never_use_reason') or '').strip()}")

    for column in c.get("never_populated") or []:
        if column == never_use:
            continue
        if used(column):
            problems.append(
                f"reads `{column}` on {table}, which exists in the schema and is "
                f"never populated, so the query runs and this column is always empty")

    # A string column compared to a bare number is the defect that stops the
    # query running at all, so it is worth naming the operator that did it.
    for column, kind in (c.get("typing") or {}).items():
        if not str(kind).startswith("string"):
            continue
        hit = re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(column)}\s*(==|!=|<=|>=|<|>)\s*-?\d+(?![\d.])", code)
        if hit and hit.group(1) not in ("==", "!="):
            problems.append(
                f"compares `{column}` numerically with `{hit.group(1)}`; it is typed "
                f"string on {table} and the engine refuses the query")

    # An equality match against a name that carries typographic punctuation.
    # The catalogue transcribes an en dash as a hyphen and Entra emits the en
    # dash, so `=~` on the catalogue spelling runs and matches nothing forever.
    dashed = ((c.get("operation") or {}).get("dashed_names") or {})
    if dashed:
        for literal in re.findall(
                r"""\b(?:OperationName|ActivityDisplayName)\s*(?:==|=~)\s*["']([^"']+)["']""",
                literals):
            if "-" in literal or "\u2013" in literal or "\u2014" in literal:
                problems.append(
                    f"matches {literal!r} with an equality operator, and the name "
                    f"carries a dash. {dashed.get('at_risk', 'Many')} of the "
                    f"catalogued names do, the catalogue spells them with a "
                    f"hyphen and the directory emits an en dash, so this matches "
                    f"nothing. {dashed.get('rule', '').strip()}")

    # A literal compared against a column whose real values were measured.
    # A generated detection filtered OperationName == "JobStreams" on a table
    # where every JobStreams row carries OperationName "Job". It parsed, it ran,
    # and it matched nothing for ever.
    # Only the section this query actually scopes to. Checking every service's
    # vocabulary at once made SQL's values reject a correct Automation query,
    # which is the shared table's whole problem reappearing inside the checker.
    def _literal(column: str) -> str:
        hit = re.search(
            rf"""(?<![A-Za-z0-9_]){re.escape(column)}\s*(?:==|=~)\s*["']([^"']+)["']""",
            literals)
        return hit.group(1) if hit else ""

    scoped_to = ""
    provider, category = _literal("ResourceProvider"), _literal("Category")
    if provider and category:
        for key in (c.get("services") or {}):
            if key.casefold() == f"{provider}/{category}".casefold():
                scoped_to = key
                break

    for _key, section in (c.get("services") or {}).items():
        if scoped_to and _key != scoped_to:
            continue
        if not scoped_to:
            break          # cannot tell which service; the scoping check covers it
        for column, values in (section.get("observed_values") or {}).items():
            if column.endswith("_note") or not isinstance(values, list):
                continue
            for literal in re.findall(
                    rf"""(?<![A-Za-z0-9_]){re.escape(column)}\s*(?:==|=~)\s*["']([^"']+)["']""",
                    literals):
                if literal.casefold() not in {str(v).casefold() for v in values}:
                    problems.append(
                        f"matches `{column}` against {literal!r}, which is not a "
                        f"value it was measured to hold. Observed: "
                        f"{', '.join(map(str, values))}")

    # A type-suffixed column the scoped service does not have. On a shared
    # table these are per-service, so a generated detection read
    # `identity_claim_upn_s` -- a column no provider in this workspace sends --
    # and the query ran with that field empty on every row.
    if scoped_to:
        known = {str(x) for x in ((c["services"][scoped_to].get("columns")) or [])}
        known |= set(c.get("envelope") or [])
        for name in set(re.findall(r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9_]*_[sgdb])(?![A-Za-z0-9_])", code)):
            if name not in known:
                problems.append(
                    f"reads `{name}`, which {scoped_to} does not send. On a shared "
                    f"table the type-suffixed columns belong to whichever service "
                    f"wrote the row, so this resolves to nothing")

    # A shared table read without narrowing to one service returns every
    # service in the tenant. Measured: 50 rows, 4 categories, 2 providers, and
    # a workspace column count that is a property of who is sending rather than
    # of any one service.
    for required in ((c.get("scoping") or {}).get("required") or []):
        if not used(required):
            problems.append(
                f"reads {table} without filtering `{required}`. This table is "
                f"shared by every service that writes to it, so the query "
                f"returns other services' events as well as the ones it means")

    # Naming a principal that the row does not carry unless the gate is applied.
    attribution = c.get("attribution") or {}
    gate = attribution.get("gate")
    who = (c.get("roles") or {}).get("who")
    if gate and who and used(who):
        gate_column = gate.split()[0]
        if not used(gate_column):
            problems.append(
                f"projects `{who}` without filtering on `{gate_column}`; on {table} "
                f"that column is only populated when {gate}, so most rows name nobody")
    return problems


# --- the plan half ---------------------------------------------------------
#
# Everything above governs how a detection READS a table. This governs what may
# be proposed in the first place, which is the other half of the same problem.
#
# Microsoft.Insights/diagnosticSettings has two operations in AzureActivity,
# Write and Delete, and one technique. The honest plan is two vectors. Phase 1
# produced five, because it is told to cover the surface exhaustively and is
# never shown how big the surface is -- so the only way to be thorough on a
# two-operation surface is to subdivide Write by request-body fields, and four
# of the five differed from each other by fields nobody had measured. One asked
# for a write where every destination is empty, which cannot happen: workspaceId
# is present on 31 of 31 observed writes and the other three destinations are
# never present at all.

def _observed_count(table: str, operation: str) -> int:
    payloads = (for_table(table) or {}).get("operation_payloads") or {}
    entry = payloads.get(operation) or payloads.get(operation.upper()) or {}
    return int(entry.get("observed_events") or 0)


def payload_fields(table: str, operation: str) -> dict[str, dict] | None:
    """Measured request-body fields for one operation, or None if unmeasured.

    None and {} are different answers. Nobody looked, versus looked and found
    nothing, and a caller reporting a verdict has to be able to say which.
    """
    payloads = (for_table(table) or {}).get("operation_payloads") or {}
    entry = payloads.get(operation) or payloads.get(operation.upper())
    if entry is None:
        return None
    # Nested measurements count. `retentionPolicy` is real -- 21 of 63 entries
    # inside `logs` carry it -- and it is not a top-level property, so reading
    # only the top level would report a measured field as never observed.
    fields = dict(entry.get("fields") or {})
    for key, nested in entry.items():
        if key.endswith("_entry") and isinstance(nested, dict):
            for name, detail in nested.items():
                if name.endswith("_note"):
                    continue
                fields.setdefault(name, detail if isinstance(detail, dict) else {})
    return fields


def _attr(vector, name: str) -> object:
    """Vectors reach here as pydantic models from the engine and as dicts from a
    saved plan.json. Both are real callers, so both are read."""
    if isinstance(vector, dict):
        return vector.get(name)
    return getattr(vector, name, None)


def plan_problems(vectors: list, table: str, vocabulary=()) -> dict[int, list[str]]:
    """Per-vector problems, keyed by the vector's index in the plan.

    Two questions. Is the operation one this table records, and -- when several
    vectors claim the same operation -- is each one told apart by a field that
    has actually been observed in that operation's request body.

    Deliberately silent when only one vector uses an operation. One detection
    per operation is the shape this is trying to get back to, and it needs no
    justification.
    """
    known = {str(v).lower() for v in vocabulary}
    out: dict[int, list[str]] = {}

    def add(i: int, msg: str) -> None:
        out.setdefault(i, []).append(msg)

    by_operation: dict[str, list[int]] = {}
    for i, vector in enumerate(vectors):
        operation = str(_attr(vector, "operation") or "")
        if known and operation.lower() not in known:
            add(i, f"operation {operation!r} is not one this table records. "
                   f"The {len(known)} known for this target are the only ones "
                   f"a detection here can filter on")
        by_operation.setdefault(operation.lower(), []).append(i)

    for operation, indexes in by_operation.items():
        if len(indexes) < 2:
            continue
        measured = payload_fields(table, operation.upper())
        for i in indexes:
            claimed = [str(f) for f in (_attr(vectors[i], "distinguishing_fields") or [])]
            if not claimed:
                add(i, f"{len(indexes)} vectors use {operation} and this one "
                       f"names no request-body field that tells it apart from "
                       f"them, so there is nothing to show they describe "
                       f"different events")
                continue
            if measured is None:
                add(i, f"{len(indexes)} vectors use {operation} and nothing has "
                       f"measured what its request body contains, so "
                       f"{', '.join(claimed)} cannot be confirmed to exist")
                continue
            unknown = [f for f in claimed if f not in measured]
            if unknown and len(unknown) == len(claimed):
                # Absence is tenant-local evidence and must be worded as such.
                # A lab with no storage-destination diagnostic settings has
                # never seen `storageAccountId`; that says nothing about anyone
                # else's tenant, and a shipped wheel asserting otherwise would
                # be the same overreach this whole module exists to stop.
                seen = _observed_count(table, operation)
                where = f" in the {seen} events measured here" if seen else " here"
                add(i, f"distinguished only by {', '.join(unknown)}, which was "
                       f"not seen{where} for {operation}. The fields that were "
                       f"seen are {', '.join(sorted(measured))}. If this field "
                       f"is real and simply quiet in this tenant, trigger it and "
                       f"re-measure rather than dropping the vector")
    return out


def vocabulary(table: str) -> tuple[dict[str, list], frozenset[str]]:
    """(measured values per column, which of those sets are COMPLETE).

    The values are evidence from a workspace. Completeness is a separate claim
    and a much stronger one: it says the table writes nothing else, which is
    true of an access-restriction outcome and false of a publishing protocol
    nobody has exercised. Conflating them would reject a correct FTP detection
    for naming a value this lab never produced.
    """
    c = for_table(table) or {}
    values = {k: v for k, v in (c.get("observed_values") or {}).items()
              if isinstance(v, list)}
    for section in (c.get("services") or {}).values():
        for k, v in (section.get("observed_values") or {}).items():
            if isinstance(v, list):
                values.setdefault(k, v)
    return values, frozenset(c.get("vocabulary_complete") or ())


def _section(c: dict, service: str) -> dict:
    """The per-service section of a shared contract, or {} for a normal table.

    AzureDiagnostics is every service's table, so "which column holds the
    caller" has one answer per provider and category -- clientInfo_ObjectId_g
    on an Automation audit event, Caller_s on a job log, server_principal_name_s
    on a SQL audit event. A single table-level answer would be wrong for at
    least two of the three, which is why this takes the service rather than
    guessing.

    Matched case-insensitively and by prefix, because the caller has the ARM
    provider ("Microsoft.Automation") and the section is keyed by provider and
    category ("MICROSOFT.AUTOMATION/AuditEvent"). A prefix match with more than
    one hit is ambiguous and returns nothing rather than picking one.
    """
    sections = c.get("services") or {}
    if not sections or not service:
        return {}
    want = service.strip().lower()
    exact = next((v for k, v in sections.items() if k.lower() == want), None)
    if exact is not None:
        return exact
    hits = [v for k, v in sections.items() if k.lower().startswith(want + "/")]
    return hits[0] if len(hits) == 1 else {}


def roles(table: str, service: str = "") -> dict[str, str]:
    """{role: the column that carries it} for one table, or one service of a
    shared table. Empty when the table has no contract.

    The roles block is the contract's answer to "which column holds the actor,
    the address, the outcome". It is what makes a rendered triage question
    specific to the table instead of specific to nothing.
    """
    c = for_table(table)
    if not c:
        return {}
    section = _section(c, service)
    base = dict(c.get("roles") or {})
    base.update(section.get("roles") or {})
    # `scope` is a list in every contract. str() on a list renders the Python
    # repr -- "['_ResourceId']" -- straight into the document, brackets and
    # quotes included.
    return {k: ", ".join(map(str, v)) if isinstance(v, list) else str(v)
            for k, v in base.items()}


def unusable(table: str, service: str = "") -> dict[str, str]:
    """{column: why it cannot be relied on} -- never-populated and redacted.

    Two different reasons with the same consequence. A never-populated column
    was measured empty; a redacted one holds a literal placeholder, which is
    worse, because a query filtering it runs, returns rows, and names nobody.
    Measured: Automation's clientInfo_PrincipalName_s is "{scrubbed}" on every
    audit event in the tenant.
    """
    c = for_table(table)
    if not c:
        return {}
    section = _section(c, service)
    out = {str(col): "always empty in the measured window"
           for col in (c.get("never_populated") or [])}
    for col in (section.get("redacted") or []) + (c.get("redacted") or []):
        out[str(col)] = "redacted -- holds a placeholder, not a value"
    return out


def ingestion(table: str) -> dict[str, str]:
    """How long before an absence in this table means anything, if measured.

    Only FunctionAppLogs carries this so far, and it carries it because an
    emptiness claim written from a too-short window was wrong and the verifier
    caught it: host lifecycle rows land in about a minute, invocation rows
    materially slower, so "no rows" measured over a host start proves nothing.
    """
    c = for_table(table) or {}
    return {str(k): str(v).strip() for k, v in (c.get("ingestion") or {}).items()}


def section_for(table: str, provider: str, operation: str = "") -> str:
    """The per-service section key of a shared table: "PROVIDER/Category", or "".

    A single AzureDiagnostics surface spans every category a provider writes --
    Automation's is one surface covering AuditEvent, DscNodeStatus, JobLogs and
    JobStreams -- so the provider alone does not say which section a detection
    reads. The operation does, because each section records its own measured
    values and they do not overlap: "Create" is an audit event and "Job" is a
    job log.

    Returns "" rather than guessing when the operation matches more than one
    section or none, and the caller then degrades to the table-level contract.
    A wrong section is worse than no section: it would name another service's
    actor column with full confidence.
    """
    c = for_table(table)
    if not c:
        return ""
    want = provider.strip().lower()
    keys = [k for k in (c.get("services") or {}) if k.lower().startswith(want + "/")]
    if len(keys) == 1:
        return keys[0]
    if not keys or not operation:
        return ""
    op = operation.strip().lower()
    hits = [k for k in keys
            if op in {str(v).lower()
                      for v in ((c["services"][k].get("observed_values") or {})
                                .get("OperationName") or [])}]
    return hits[0] if len(hits) == 1 else ""
