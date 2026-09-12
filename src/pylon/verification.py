"""Does a detection match the events it claims to detect?

Every check that ran before this one asked whether a query was well FORMED.
The static validator reads its text, the offline engine resolves its columns,
and the workspace confirms it executes. A detection can pass all three and be
incapable of ever firing, which is not a hypothetical:

  * an ARM detection filtered `Authorization.role`, a field that does not exist
    on AzureActivity -- the role lives under `evidence`, and the one that was
    GRANTED is only on the Start row. Valid KQL, correct table, zero rows,
    forever.
  * an Entra detection filtered `modifiedProperties` display names against the
    Graph API's schema names -- `keyCredentials`, `passwordCredentials` --
    where the log writes `Included Updated Properties` and `AppAddress`. Thirty
    real events, zero alerts.

Neither is visible in the query text, because neither is a fact ABOUT the query.
They are facts about the data, and the only instrument that sees them is the one
that compares what a detection returns against what actually happened.

So: count the operation in the raw table, count what the detection returns over
the same window, and compare. Two numbers from two independent sources.

The comparison is asymmetric, deliberately. Returning FEWER rows than there are
events is often correct -- these detections exclude failed operations and known
Microsoft service principals on purpose. Returning MORE is never correct: no
filter can produce more matches than there are events of the operation it
filters. So over-matching is a defect and under-matching is a question.
"""

from __future__ import annotations

from collections.abc import Callable

import re

from .models import DetectionVerification

# A detection carries its own time bound, almost always an hour. The workspace
# window can narrow that, never widen it, so a detection is invisible to this
# comparison unless the attack happened in the last hour. Verification widens
# the bound to the window being asked about -- and says so, because the query
# being measured is then not byte-for-byte the query that ships.
_AGO = re.compile(r"\bago\s*\(\s*\d+\s*[smhd]\s*\)", re.IGNORECASE)
# Most generated detections do not write the duration inside `ago(...)`. They
# bind it first -- `let lookback = 1h;` then `ago(lookback)` -- and rewriting
# only the literal form silently left those queries on their own one-hour bound.
# They then matched nothing, and "nothing" is indistinguishable from a detection
# that cannot fire, which is the confusion this whole module exists to remove.
# Six of seven Key Vault detections read `dead` for exactly this reason.
_LET_DURATION = re.compile(r"\b(let\s+(\w+)\s*=\s*)(\d+[smhd])(\s*;)", re.IGNORECASE)
_AGO_NAME = r"\bago\s*\(\s*{}\s*\)"


def widen(kql: str, window: str) -> tuple[str, bool]:
    """`kql` with its own time bounds replaced by `window`.

    Returns (query, whether anything was widened). A False here means the
    comparison ran against the detection's OWN window, so an empty result says
    nothing about whether the detection works -- the caller must not read it as
    a verdict.
    """
    out, changed = _AGO.subn(f"ago({window})", kql)

    # A bound bound to a name: rewrite the binding, but only when that name is
    # actually used as a time bound. `let threshold = 5;` is not a window.
    def _rebind(m: re.Match) -> str:
        nonlocal changed
        name = m.group(2)
        if not re.search(_AGO_NAME.format(re.escape(name)), out, re.IGNORECASE):
            return m.group(0)
        changed += 1
        return f"{m.group(1)}{window}{m.group(4)}"

    out = _LET_DURATION.sub(_rebind, out)
    return out, bool(changed)


# A detection that groups its rows returns GROUPS, not events, so comparing its
# output count against a raw operation count is a category error -- and one that
# reads as a defect. Two Key Vault detections were reported `dead` for requiring
# five writes by one caller inside ten minutes, which is correct behaviour on
# benign traffic and is the entire point of a threshold rule. Two more were
# reported `under` for collapsing six events into one group.
#
# Such a detection is not verifiable by counting. It needs a case that exceeds
# its threshold, which is either data that already does or an emulated one.
_AGGREGATES = re.compile(r"\|\s*(?:summarize|make-series)\b", re.IGNORECASE)
# `summarize take_any(*) by EventDataId` is a DEDUPE, not an aggregation. It
# collapses duplicate ingestion -- AzureActivity is commonly written twice by an
# export and a connector sharing an EventDataId -- and leaves one row per real
# event, which is exactly what an event count should be compared against.
# Reading it as a grouping made a correct ARM detection unmeasurable.
# `summarize take_any(*) by <one key>` collapses duplicates; it does not group.
# This matched `by EventDataId` ALONE, so the same idiom on CorrelationId -- the
# join key this codebase's own prompt rules tell the model to dedupe on -- was
# read as an aggregation. A detection using it then short-circuited to
# `aggregates` and could never be reported `dead` or `no-match`, however many
# real events it failed to match. One did: 0 groups from 110 events, counted as
# a valid detection.
#
# Any SINGLE key is a dedupe. Two or more is a grouping, because the output row
# no longer corresponds to one input row.
_DEDUPE = re.compile(
    r"\|\s*summarize\s+take_any\s*\(\s*\*\s*\)\s+by\s+"
    r"[A-Za-z_][A-Za-z0-9_]*\s*(?=\||;|$)", re.IGNORECASE | re.MULTILINE)


def aggregates(kql: str) -> bool:
    """True when the query groups rows, so its output is not event-comparable."""
    without_dedupe = _DEDUPE.sub("", kql)
    return bool(_AGGREGATES.search(without_dedupe))


# What a query filters on BEYOND the operation, the time bound and the outcome.
# Those three are the frame every detection shares; anything else narrows within
# the operation, and that is what decides whether an empty result accuses the
# query or describes the tenant.
_FRAME = re.compile(
    r"TimeGenerated|ago\s*\(|between\s*\(|OperationName|OperationNameValue"
    r"|ActivityStatusValue|ResultType|ResultSignature|\bResult\b|HttpStatusCode",
    re.IGNORECASE)


def narrows(kql: str) -> bool:
    """Whether `kql` filters on anything past the operation, time and outcome.

    An empty result means two different things and the tool could only say one
    of them. A query filtering ONLY the operation and returning nothing is
    damning: the events are right there and it matched none. A query that also
    requires a particular shape -- a diagnostic setting write that disables
    every category, a role assignment granting one specific role -- returning
    nothing may simply mean nobody did that here.

    Measured on a real tenant: 110 DiagnosticSettings/Write events, none of them
    disabling all categories, and a detection written for the all-disabled case
    reported as `dead`, marked invalid, printed BAD, counted as a generation
    failure, and told in its own .kql header that "the fault is in what it
    MATCHES". None of that was established. The operation count is the wrong
    denominator for a behaviour-scoped query, which is a limit this codebase
    had already named for `under` and then built a gate on top of anyway.
    """
    body = _blank(kql)
    for clause in re.findall(r"\|\s*where\s+([^|]+)", body, re.IGNORECASE):
        if not _FRAME.search(clause):
            return True
    # A `let` holding a value the query compares against is the other shape:
    # `let OwnerRoleGuid = "..."` narrows without a bare where-clause doing it.
    return bool(re.search(r"^\s*let\s+\w+\s*=\s*[\"']", body, re.MULTILINE))


def _blank(kql: str) -> str:
    """`kql` with line comments removed, so a comment cannot read as a filter."""
    return re.sub(r"//[^\n]*", "", kql)


def verdict(expected: int | None, observed: int | None, *,
            groups: bool = False, narrowed: bool = False) -> tuple[str, str]:
    """(verdict, one line saying what it means).

    `narrowed` says the query filters past the operation, which changes what an
    empty result is allowed to mean. See `narrows`.
    """
    if observed is None:
        return "error", "the detection did not run"
    if expected is None:
        return "error", "the operation could not be counted"
    if expected == 0:
        return "no-ground-truth", "no events of this operation in the window"
    if groups:
        return "aggregates", (
            f"{observed} group(s) from {expected} events -- this detection "
            "summarizes, so its rows are not comparable to an event count"
            + (". Zero groups from real events may be a threshold nobody "
               "crossed, which is a rule working, or a query that matches "
               "nothing -- grouping hides which" if observed == 0 else "."))
    if observed == 0:
        if narrowed:
            # Not a defect and not a pass. The query asks for a shape inside
            # the operation and no event had it, which is a statement about the
            # tenant that this measurement cannot separate from a broken
            # filter. Saying either would be a claim the evidence does not
            # carry.
            return "no-match", (
                f"{expected} events of this operation, none matching what the "
                "query asks for beyond it. The query filters on more than the "
                "operation, so this is either an attack that did not happen "
                "here or a filter that is wrong, and counting the operation "
                "cannot tell them apart")
        return "dead", (
            f"{expected} real events and the detection matched none, while "
            "filtering on nothing beyond the operation itself")
    if observed > expected:
        return "over", (f"{observed} rows for {expected} events "
                        f"(x{observed / expected:.2f}) -- no filter can add rows")
    if observed < expected:
        return "under", (f"{observed} rows for {expected} events "
                         f"(x{observed / expected:.2f}) -- may be filtering on purpose")
    return "exact", f"{observed} rows for {expected} events"


def measure(kql: str, table: str, operation: str, window: str,
            count: "Callable[[str], int | None]") -> "DetectionVerification":
    """Grade one detection against real events. `count` runs a query and
    returns a row count, or None when the query did not run.

    Lives here rather than in the CLI because generation needs it too. The
    workspace is the third gate, after the regexes and the KQL engine, and the
    only one that can answer the question the other two cannot ask: does this
    query match anything that actually happened. A detection can be valid KQL,
    accepted by the engine, and still return nothing against 144 real events --
    which is exactly what shipped three times in one session while the run
    printed "100% produced a valid detection".

    Ground truth is counted from the RAW TABLE, which the detection cannot
    influence. The operation column differs by table -- AuditLogs and the
    data-plane tables carry OperationName, AzureActivity carries
    OperationNameValue and leaves OperationName empty -- so it is resolved per
    table rather than hardcoded.
    """
    from .models import DetectionVerification
    from .services import operation_column
    from .validate import _pipeable

    column = operation_column(table)
    expected = count(f'{table} | where {column} =~ "{operation}"')
    widened, was_widened = widen(kql, window)
    observed = count(_pipeable(widened))
    call, detail = verdict(expected, observed, groups=aggregates(kql),
                           narrowed=narrows(kql))
    return DetectionVerification(
        vector_name="", operation=operation, expected=expected,
        observed=observed, verdict=call, detail=detail, widened=was_widened)


# The verdicts that mean something is wrong, as opposed to unproven.
# `aggregates` and `no-ground-truth` are neither: both mean the question was not
# answered, which is reported separately and never counted as a pass.
# Every verdict `verdict()` can return. One list, because the CLI tally typed
# six of the eight out by hand and two were simply never printed -- a detection
# that summarised vanished from the count while sitting in the table above it.
VERDICTS = ("exact", "under", "over", "dead", "no-match", "aggregates",
            "no-ground-truth", "error")

DEFECTS = ("dead", "over", "error")
UNPROVEN = ("no-ground-truth", "aggregates", "no-match")


def summarise(results: list[DetectionVerification]) -> dict[str, int]:
    """How many detections landed on each verdict."""
    out: dict[str, int] = {}
    for r in results:
        out[r.verdict] = out.get(r.verdict, 0) + 1
    return out


# `operation_for` lived here. It took a detection's vector name and matched it
# back to the plan entry that asked for it, through an exact match, then the
# part before the parenthesis, then a longest-prefix fallback.
#
# Every one of those was added after a rewrite defeated the last: a new
# subtitle, then the operation appended, then `VaultPatch (patch vault
# configuration)` coming back as `Key Vault configuration patched (VaultPatch)`
# with no leading word in common. Four Key Vault detections went unmeasured on
# the run that settled it, reported as `error` and sitting in the coverage line
# as defects nobody could act on.
#
# The name was never a key. `models.ThreatAnalysis` says so in its own
# docstring. `ValidatedDetection.operation` is stamped by code at generation,
# where the vector is known for certain, and `design verify` reads that.

# --- playbook queries -------------------------------------------------------
#
# A playbook carries six to ten queries a responder pastes at 3am, and nothing
# had ever run one. They are NOT independent: the first fenced block is a
# prelude of `let` statements and every later block reads it, so extracting them
# one at a time reports failures on a document that is fine. That mistake was
# made twice before this existed.
#
# They also carry responder blanks by design -- `[FROM ALERT: ActorUpn]` is a
# value from the alert row, not a defect. Filling them from a REAL event means a
# query that runs is also a query that could return something.

_BLOCK = re.compile(r"```kql\n(.*?)```", re.S)

# The blank as the template writes it -> the field on a real row that fills it.
# `[TIME YOU RAN CONTAINMENT]` takes a BARE timestamp: the template already
# wraps it in `datetime(...)`, and substituting `datetime(...)` there produces
# `datetime(datetime(...))` and a parse error that reads as a playbook bug.
RESPONDER_FILLS: dict[str, str] = {
    "[FROM ALERT: TimeGenerated]": "time",
    "[FROM ALERT: ActorUpn or ActorId]": "actor",
    "[FROM ALERT: ActorUpn]": "actor",
    "[FROM ALERT: ActorId]": "actor_id",
    "[FROM ALERT: SrcIp]": "src_ip",
    "[FROM ALERT: TargetResource]": "target",
    "[FROM ALERT: CorrelationId]": "correlation_id",
    "[TIME YOU RAN CONTAINMENT]": "time",
    "[the resource from the alert]": "target",
    "[the resource id]": "target",
    "[object ID from the alert]": "actor_id",
    "[resource ID from the alert]": "target",
    "[THE WINDOW THE DETECTION AGGREGATES OVER, e.g. 1h / 24h / 7d]": "window",
}


def blocks(document: str) -> list[str]:
    """Every ```kql block in a playbook, prelude first."""
    return _BLOCK.findall(document)


def runnable(document: str, values: dict[str, str]) -> list[str]:
    """Each query as a responder would actually run it: the prelude prepended,
    the blanks filled, Sentinel-only functions swapped for their fallbacks.

    The prelude itself is excluded -- it is only `let` statements and cannot run
    alone, so reporting it as a failure says nothing.
    """
    from .kusto_offline import substitute_sentinel_functions

    found = blocks(document)
    if len(found) < 2:
        return []

    def fill(text: str) -> str:
        for blank, key in RESPONDER_FILLS.items():
            text = text.replace(blank, str(values.get(key, "")))
        return substitute_sentinel_functions(text)

    prelude = fill(found[0]).rstrip().rstrip(";")
    out = []
    for raw in found[1:]:
        query = fill(raw)
        out.append(f"{prelude};\n{query}" if "let " in prelude else query)
    return out
