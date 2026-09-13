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
