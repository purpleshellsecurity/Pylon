"""KQL validation — full port of lib/validation/validateKQL.ts.

Checks AI-generated detection queries against known table schemas and flags
common hallucination patterns. Pure code, no LLM. The engine feeds errors
back to the detection agent for a self-correction retry.
"""

import re
from dataclasses import dataclass, field
from functools import lru_cache

from .. import column_values, kqltext, roles
from .operation import validate_operation
from .schemas import FLAT_TABLES, PLAIN_STRING_FIELDS, TABLE_SCHEMAS


@lru_cache(maxsize=1)
def _known_tables() -> frozenset[str]:
    """Every real Azure Monitor table name we know: the schema'd set plus every
    table in the grounding catalog. Used to tell a hallucinated table (total
    silence before F2) from a real one we simply lack a column schema for."""
    known = set(TABLE_SCHEMAS)
    known.update(("AzureActivity", "AzureDiagnostics", "AzureMetrics"))
    try:  # catalog is the source of truth for real table names; optional at runtime.
        from pylon.catalog import service_files

        for svc in service_files().values():
            known.update(svc.get("tables", {}))
    except (ImportError, OSError, ValueError):
        pass  # catalog unavailable → schema'd set only; still a valid guard
    return frozenset(known)


# The AzureDiagnostics dynamic-column convention: a resource-log property name
# plus a type suffix. Documented at
# https://learn.microsoft.com/azure/azure-monitor/reference/tables/azurediagnostics
# — "If a resource log includes a column that doesn't already exist in the
# AzureDiagnostics table, that column is added the first time that data is
# collected." Names like identity_s, httpStatusCode_d and activityId_g are that
# table's, never a dedicated table's.
_AZDIAG_SUFFIXED = re.compile(r"\b([A-Za-z][A-Za-z0-9_]*_(?:s|d|g|b|t|i))\b")


# Non-KQL / SQL tokens that must never appear in a Sentinel KQL detection.
_NON_KQL = re.compile(
    r"\b(?:drop\s+table|delete\s+from|insert\s+into|truncate\s+table|"
    r"union\s+select|xp_cmdshell)\b|;\s*--",
    re.IGNORECASE,
)


# Bracketed prose left over from the prompt's own worked example -- the
# detection templates are written as fill-in skeletons ("[Name]", "[exact
# OperationNameValue from Phase 1]") and a model that copies the shape can copy
# the placeholder with it. Scanned on the RAW query, not the comment/string-
# blanked copy, because the likeliest place for one to survive is inside a
# string literal that `_blank_strings_and_comments` erases.
#
# Requires a leading letter and forbids quotes and nested brackets inside, which
# is what separates prose from KQL's own bracket uses: dynamic([]), an index
# like arr[0] or split(u,"/")[3], and a lookup like Props["key"] all pass. Checked
# against every detection template (6 of 6 flagged) and 265 KQL lines from the
# test suite (0 flagged).
_PLACEHOLDER = re.compile(r"\[[A-Za-z][^\[\]\"'\n]{2,60}\]")


# An empty collection bound by `let` and then tested. Every predicate over an
# empty set has a constant answer, so the clause does not filter -- it is a
# clause the detection's own description promises and the query cannot deliver.
#
# Seen twice in shipped detections, both times as an allowlist:
#     let AllowedSinks = dynamic([]);
#     | extend allowlistConfigured = array_length(AllowedSinks) > 0
#     | where crossSubscription or (allowlistConfigured and not(inAllowlist))
# `allowlistConfigured` is false forever, so the right half of that `or` never
# runs. The query is valid KQL, the engine accepts it, and it matches real
# events -- so all three existing gates pass it. Only reading the boolean
# algebra catches it.
#
# Deliberately restricted to `let` bindings. An inline `coalesce(x, dynamic([]))`
# is a legitimate default and is not this.
_EMPTY_LET = re.compile(
    r"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:dynamic\s*\(\s*(?:\[\s*\]|\{\s*\})\s*\)|pack_array\s*\(\s*\))\s*;",
    re.IGNORECASE)

# Tests whose answer is fixed once the collection is known to be empty, with the
# value they are fixed at.
_CONSTANT_OVER_EMPTY: tuple[tuple[str, bool], ...] = (
    (r"array_length\s*\(\s*{name}\s*\)\s*(?:>\s*0|>=\s*1|!=\s*0)", False),
    (r"array_length\s*\(\s*{name}\s*\)\s*(?:==\s*0|<=\s*0|<\s*1)", True),
    (r"array_index_of\s*\(\s*{name}\s*,[^)]*\)\s*(?:!=\s*-1|>=\s*0|>\s*-1)", False),
    (r"array_index_of\s*\(\s*{name}\s*,[^)]*\)\s*==\s*-1", True),
    (r"set_has_element\s*\(\s*{name}\s*,", False),
    (r"\bin~?\s*\(\s*{name}\s*\)", False),
)


# A watchlist is the same defect wearing a different hat. Measured: on a tenant
# with no watchlist called ApprovedAutomation,
#     let A = _GetWatchlist('ApprovedAutomation') | project SearchKey;
#     ... | where clientInfo_ObjectId_g !in (A)
# does NOT error. It returns empty and the `!in` passes all 8 rows, so the
# detection's own description promises an allowlist it does not apply. The
# generator reaches for this shape on its own; it was never in a prompt.
_WATCHLIST_LET = re.compile(
    r"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*_GetWatchlist\s*\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE)


def _unverified_watchlists(kql: str) -> list[str]:
    """Filters that silently pass everything when the watchlist is absent."""
    bare = _blank_strings_and_comments(kql)
    raw = kqltext.strip_comments(kql)          # keep the literal name readable
    problems: list[str] = []
    for hit in _WATCHLIST_LET.finditer(raw):
        name, watchlist = hit.group(1), hit.group(2)
        if not re.search(rf"\bin~?\s*\(\s*{re.escape(name)}\s*\)", bare, re.IGNORECASE):
            continue
        problems.append(
            f"filters on the watchlist {watchlist!r} through `{name}`. A watchlist "
            f"that does not exist returns EMPTY rather than failing, so `in` "
            f"matches nothing and `!in` matches everything -- either way the "
            f"clause does not filter and the detection describes behaviour it "
            f"does not have. Confirm the watchlist exists in the target tenant, "
            f"or drop the clause and say so.")
    return problems


def _dead_empty_collections(kql: str) -> list[str]:
    """Clauses that cannot change what the query returns, because they test an
    empty collection -- directly, or through a name extended from one."""
    bare = _blank_strings_and_comments(kql)
    problems: list[str] = []
    for binding in _EMPTY_LET.finditer(bare):
        name = binding.group(1)
        # Directly, and through one level of `extend alias = <constant test>`,
        # which is how both real cases were written.
        constants: dict[str, bool] = {}
        for pattern, value in _CONSTANT_OVER_EMPTY:
            rx = re.compile(pattern.format(name=re.escape(name)), re.IGNORECASE)
            for alias in re.finditer(
                    r"\bextend\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^|\n]+)", bare):
                if rx.search(alias.group(2)):
                    constants[alias.group(1)] = value
            if rx.search(bare):
                constants.setdefault(name, value)

        used = [alias for alias in constants
                if re.search(rf"\|\s*where\b[^|]*(?<![A-Za-z0-9_]){re.escape(alias)}"
                             rf"(?![A-Za-z0-9_])", bare, re.IGNORECASE)]
        if not used:
            continue
        fixed = ", ".join(f"`{a}` is always {str(constants[a]).lower()}" for a in sorted(used))
        problems.append(
            f"`{name}` is bound to an empty collection, so {fixed}. That clause "
            f"cannot change what this query returns, and the detection describes "
            f"behaviour it therefore does not have. Either fill the list in, or "
            f"remove the clause and say so.")
    return problems


def _structural_issues(kql: str, *, allow_placeholders: bool = False,
                       context: str = "detection") -> tuple[list[str], list[str]]:
    """Query-SHAPE checks independent of any table schema: an empty query, a
    guaranteed-empty result (``take 0`` / ``where false``), a non-KQL/SQL payload,
    or a missing time filter. These catch 'dead' queries that a column-only
    validator waves through — syntactically plausible, but never a detection.

    `allow_placeholders` drops the fill-in check for a caller whose artefact is
    meant to be filled in. See `validate_kql`."""
    if not kql.strip():
        return ["Empty query — there is nothing to run."], []
    errors: list[str] = []
    warnings: list[str] = []
    bare = _blank_strings_and_comments(kql)  # don't scan inside string values
    if _NON_KQL.search(bare):
        errors.append(
            "Query contains non-KQL/SQL syntax — Sentinel analytics rules are KQL only."
        )
    if re.search(r"\|\s*(?:take|limit)\s+0\b", bare, re.IGNORECASE):
        errors.append(
            "Query returns no rows (`take 0`/`limit 0`) — the rule can never fire."
        )
    if re.search(r"\|\s*where\s+(?:false\b|1\s*==\s*0|0\s*==\s*1)", bare, re.IGNORECASE):
        errors.append(
            "Query has a contradictory predicate (`where false`) — it can never match."
        )
    errors.extend(_dead_empty_collections(kql))
    errors.extend(_unverified_watchlists(kql))
    # The rules whose severity means "do not ship this" -- a Sentinel analytics
    # rule that cannot be CREATED (union/search), or one that deploys and cannot
    # do what it claims. Stated to the model from the same file, so a detection
    # is never rejected for a rule it was not shown.
    from . import kql_rules

    errors.extend(kql_rules.fatal(kql, context))
    left = [] if allow_placeholders else list(
        dict.fromkeys(m.group(0) for m in _PLACEHOLDER.finditer(kql))
    )
    if left:
        errors.append(
            "Query still contains fill-in placeholders from the template: "
            + ", ".join(left[:4])
            + " — a detection with a placeholder cannot be deployed."
        )
    if "ago(" not in bare and not re.search(r"\b(?:TimeGenerated|Timestamp)\b", bare):
        warnings.append(
            "No time filter — a scheduled detection must scope time "
            "(e.g. `| where TimeGenerated > ago(1h)`) or it scans the full retention window."
        )
    return errors, warnings


@dataclass
class ValidationResult:
    """Result of validating a KQL query: overall validity plus errors and warnings."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# String literals and line comments, so identifier scans can blank them out.
# A column-lookalike inside a value ("MICROSOFT.AUTHORIZATION/...") or a comment
# is not a column reference and must not be graded as one.


def _blank_comments(kql: str) -> str:
    """Line comments removed, string literals KEPT.

    Most per-table checks match a column name or an operator and must not see a
    comment. But several read what is INSIDE the quotes -- `OperationName ==
    "..."`, `LoggedByService == "..."` -- so they cannot run on a source whose
    strings have been emptied. This is the version for those.

    A gate that fires on correct output is worse than no gate: it gets ignored,
    and then it is ignored when it is right. A query carrying
    `// there is no UserPrincipalName on this table` was rejected for naming the
    column it was warning against, and the corrective retry told the model to
    fix a query that was already correct.
    """
    return kqltext.strip_comments(kql)


def _blank_strings_and_comments(kql: str) -> str:
    """Replace string-literal *contents* and line comments with empty text,
    keeping the surrounding clause shape. Used only where a check inspects
    identifier *positions* (e.g. the column-case scan); value-based checks that
    read inside quotes must run on the raw query."""
    return kqltext.blank(kql)


# Names bound by a `let` statement. A query may legitimately open on one of
# these instead of a table -- `let recent = OfficeActivity | ...; recent | ...`
# is ordinary KQL -- so the leading identifier is only a table claim when it is
# not something the query itself defined.
_LET_BINDING = re.compile(r"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", re.IGNORECASE)


def let_bindings(kql: str) -> set[str]:
    """Every name the query binds with `let`."""
    return set(_LET_BINDING.findall(_blank_strings_and_comments(kql)))


def extract_query_table(kql: str) -> str | None:
    """Table name at the start of a KQL query — handles `let ...;` prefixes.

    Blanks string literals and comments first, so a ';' or '//' inside a value
    (e.g. `let x = "a;b";`) can't split the query at the wrong place — the table
    name is an identifier, unaffected by the blanking.

    Resolves THROUGH a let binding rather than reporting it. Taking the first
    identifier after the last `;` is right only when the query opens on a table;
    when it opens on a name the query defined, that identifier is not a table
    claim at all. Reporting it as one produced a live false positive -- a valid
    Exchange detection was rejected as targeting a hallucinated table named
    "recent", failed its retry, and shipped marked INVALID.
    """
    cleaned = _blank_strings_and_comments(kql)
    stripped = "\n".join(line for line in (raw.strip() for raw in cleaned.splitlines()) if line)
    after_lets = stripped[stripped.rfind(";") + 1:].strip() if ";" in stripped else stripped
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)", after_lets)
    if not m:
        return None

    name, bindings = m.group(1), let_bindings(cleaned)
    if name not in bindings:
        return name

    # Follow the binding to the table it reads. `let recent = OfficeActivity | ...`
    # is a claim about OfficeActivity; the alias is not a claim about anything.
    binding = re.search(
        rf"\blet\s+{re.escape(name)}\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", cleaned, re.IGNORECASE
    )
    if not binding:
        return None
    resolved = binding.group(1)
    # A chain of aliases, or a binding that opens on a function call, resolves to
    # nothing rather than to a wrong answer -- silence beats a false accusation.
    return None if resolved in bindings else resolved


def _validate_azure_diagnostics(kql: str, expected_provider: str = "") -> ValidationResult:
    """Intentional generic-path validation for the shared AzureDiagnostics table.

    The dynamic-routing resolver sends a resource that publishes no
    resource-specific table here, and the engine passes the resolved
    ResourceProvider. Two things differ from a resource-specific table:

    * We do NOT column-validate. AzureDiagnostics holds hundreds of open-ended,
      type-suffixed columns (``httpStatusCode_d`` ...), so a fixed column list
      would false-positive on every valid resource field.
    * We do NOT emit the "use the resource-specific table instead" penalty —
      AzureDiagnostics is the *correct* table here. Instead we enforce the
      ResourceProvider (and nudge Category) scoping that keeps the shared table
      selective, which is what actually drives generation quality on this path.
    """
    errors: list[str] = []
    warnings: list[str] = []

    detected = extract_query_table(kql)
    if detected and detected != "AzureDiagnostics":
        errors.append(
            f'Query must start with AzureDiagnostics for this generic-diagnostics path '
            f'(got "{detected}"). This resource publishes no resource-specific table — '
            "query AzureDiagnostics and scope it."
        )

    if not re.search(r"\bResourceProvider\s*(==|=~|!=|has\b|in\b)", kql, re.IGNORECASE):
        hint = f' (here: "{expected_provider.upper()}")' if expected_provider else ""
        errors.append(
            "AzureDiagnostics is a shared table — scope every query with "
            f'| where ResourceProvider == "<PROVIDER>"{hint}.'
        )
    elif expected_provider and not re.search(re.escape(expected_provider), kql, re.IGNORECASE):
        errors.append(
            f'AzureDiagnostics query must scope to ResourceProvider == '
            f'"{expected_provider.upper()}" — the provider resolved for this resource.'
        )

    if not re.search(r"\bCategory\s*(==|=~|!=|has\b|in\b)", kql, re.IGNORECASE):
        warnings.append(
            "AzureDiagnostics: consider scoping the log Category "
            '(| where Category == "...") to the resource\'s emitting category for a '
            "tighter, lower-noise detection."
        )

    unique_errors = list(dict.fromkeys(errors))
    unique_warnings = list(dict.fromkeys(warnings))
    return ValidationResult(valid=not unique_errors, warnings=unique_warnings, errors=unique_errors)



# ── Performance checks ──────────────────────────────────────────────
# A rule that times out does not alert and does not say so -- it keeps looking
# healthy in the portal. Sentinel bills on data scanned and stops a scheduled
# query at 5 minutes.
#
# WARNINGS, never errors. `valid` reads errors alone, so a warning never
# triggers a retry by itself; engine.py folds warnings into a correction prompt
# when one is already happening.
#
# Rules are quoted from Microsoft's KQL best practices:
# https://learn.microsoft.com/en-us/kusto/query/best-practices
#
# NOT implemented, deliberately: "Use ==. Don't use =~." The ARM prompt REQUIRES
# =~ on OperationNameValue, because Azure operation-name casing varies by
# provider. Warning here would instruct the model to undo what the prompt
# mandates.
#
# The rule text and the checks live in catalog/kql-rules.yaml, so the prompt and
# the validator cannot disagree. See validation/kql_rules.py.


def _performance_issues(kql: str, context: str = "detection") -> list[str]:
    """Documented KQL anti-patterns present in `kql`, as warnings.

    Sourced from `catalog/kql-rules.yaml` rather than from a list in this file.
    The four checks that used to live here quoted Microsoft verbatim and the
    prompt quoted Microsoft separately, so the same sentence existed twice with
    nothing holding the copies together -- which is how a rule and its checker
    came to contradict each other elsewhere in this module.
    """
    from . import kql_rules

    return kql_rules.advisory(kql, context)


def _operation_literals(kql: str, table: str) -> list[str]:
    """The exact operation values a query filters on.

    Only equality forms. `has`, `contains` and `startswith` take a FRAGMENT on
    purpose -- "Secret" is a legitimate prefix filter and is not a claim that any
    such operation exists -- so checking those would fail correct queries.
    """
    from ..services import operation_column

    column = operation_column(table)
    out: list[str] = []
    # Values live in the ORIGINAL text; the blanked copy only locates the clause.
    for m in re.finditer(
        rf"\b{re.escape(column)}\s*(?:==|=~)\s*[\"']([^\"']+)[\"']", kql):
        out.append(m.group(1))
    for m in re.finditer(rf"\b{re.escape(column)}\s+in~?\s*\(([^)]*)\)", kql):
        out.extend(re.findall(r"[\"']([^\"']+)[\"']", m.group(1)))
    return out


def _foreign_scope_names(kql: str, table_name: str) -> set[str]:
    """Identifiers that belong to a table OTHER than the one under validation.

    A KQL query is not confined to one table. The most common case here is
    mandated by the prompt itself:

        let AllowedActors = _GetWatchlist('ApprovedAutomation') | project SearchKey;

    `SearchKey` is a column of the WATCHLIST. The column check walked every
    identifier in the query and measured each against the target table's schema,
    so it read the exclusion scaffolding the prompt REQUIRES as a fabricated
    column -- and once that finding became an error it killed 16 of 19 detections
    in a live Entra run, all with the same message.

    A `let` binding whose body never names the target table is a foreign scope,
    and everything inside it is out of the target's reach. A binding that DOES
    read the target table stays in scope, which is where real fabrications live:

        let Baseline = AZKVAuditLogs | where ActorRiskScore > 5;   <- still checked
    """
    src = _blank_strings_and_comments(kql)
    names: set[str] = set()
    for m in re.finditer(r"\blet\s+[A-Za-z_][A-Za-z0-9_]*\s*=", src):
        end = src.find(";", m.end())
        body = src[m.end(): end if end != -1 else len(src)]
        if re.search(rf"\b{re.escape(table_name)}\b", body):
            continue
        names |= set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", body))
    return names


def _defined_names(kql: str) -> set[str]:
    """Identifiers the query CREATES, so referencing them is not a fabrication.

    `extend Risk = ...`, `let Window = ...`, `summarize N = count() by Caller`,
    `project-rename New = Old`, and the alias in a join or a mv-expand all put a
    name into scope that no table schema contains. Without this the unknown-column
    check would fail every correct query that computes anything.
    """
    src = _blank_strings_and_comments(kql)
    names = {m.group(1) for m in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)", src)}
    names |= {m.group(1) for m in re.finditer(
        r"\bmv-expand\s+([A-Za-z_][A-Za-z0-9_]*)", src, re.IGNORECASE)}
    # A member access reads a field INSIDE a dynamic column -- `Properties.Caller`,
    # `TargetResources[0].DisplayName`. The stem is the column; what follows is
    # not, and no schema lists it.
    names |= {m.group(1) for m in re.finditer(
        r"[.\]]\s*([A-Za-z_][A-Za-z0-9_]*)", src)}
    return names


def _top_level_split(text: str, sep: str) -> list[str]:
    """Split on `sep` outside brackets. Strings are already blanked by the
    caller, so only nesting has to be tracked."""
    out, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == sep and depth == 0:
            out.append(text[start:i])
            start = i + 1
    out.append(text[start:])
    return out


# A bare identifier: not a member access (`x.Foo`), not an index (`a[Foo]`), and
# not the left side of its own assignment.
_REFERENCE = re.compile(r"(?<![.\w])([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*=(?!=))")


def _extend_self_reference(kql: str) -> list[str]:
    """Names an `extend` uses that it only defines in the same operator.

    Returns one message per offending assignment. Deliberately narrow: only
    `extend`, only a reference to a name assigned EARLIER IN THE SAME operator,
    and only where the reference is a bare identifier. A name that was already
    in scope -- from the table, a `let`, or an earlier pipeline stage -- is
    reassigned rather than defined here and is not flagged, because reading the
    old value is legal and sometimes intended.
    """
    src = _blank_strings_and_comments(kql)
    out = []
    # `;` before `|`. A let-statement query is a sequence of statements and an
    # `extend` ends at the terminator, not at the next pipe -- the pipes inside
    # a following `toscalar(...)` are nested, so splitting on `|` alone ran an
    # extend body straight through every `let` after it and read their contents
    # as its own siblings. That flagged 56 playbook queries that run fine.
    seen_before = ""
    for statement in _top_level_split(src, ";"):
        for segment in _top_level_split(statement, "|"):
            head = segment.strip()
            if not re.match(r"extend\b", head, re.IGNORECASE):
                seen_before += segment
                continue
            body = head[len("extend"):]
            # Names already in scope when this operator starts. Anything
            # assigned in an EARLIER stage or statement is legal to read.
            outer = {m.group(1) for m in re.finditer(
                r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)", seen_before)}
            seen_before += segment
            out.extend(_extend_issues(body, outer))
        seen_before += ";"
    return out


def _extend_issues(body: str, outer: set[str]) -> list[str]:
    """One message per assignment in this `extend` that reads a sibling."""
    out: list[str] = []
    assigned: set[str] = set()
    for part in _top_level_split(body, ","):
        lhs, sep, rhs = part.partition("=")
        if not sep or rhs.startswith("="):
            continue
        name = lhs.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        for ref in _REFERENCE.findall(rhs):
            if ref in assigned and ref not in outer:
                out.append(
                    f'"{name}" reads "{ref}", which the same `extend` '
                    f'defines. KQL evaluates every assignment in one '
                    f'`extend` against the operator\'s input, so "{ref}" is '
                    f'not in scope yet and the workspace refuses the query: '
                    f"Failed to resolve scalar expression named '{ref}'. "
                    f'Split it into two `extend` statements.')
                break
        assigned.add(name)
    return out


def _role_guid_mismatches(kql: str) -> list[str]:
    """Role GUIDs that contradict the name of the binding holding them.

    A detection names a role and then writes its id as a string literal. A
    string literal is the one thing nothing else here can check: a parser sees
    text, a schema has no opinion, and the workspace runs the query happily and
    returns nothing forever. That is how a query called `UaaRoleId` shipped
    holding the GUID for Managed Identity Operator.

    Two checks, and only where the binding's NAME says it holds a role:

        MISMATCH   the GUID is a built-in role and it is a DIFFERENT one. This
                   is an error. It is exactly as wrong as filtering the wrong
                   operation, and equally invisible.

        UNKNOWN    the GUID is not a built-in role at all. A WARNING, because a
                   custom role definition is real and tenant-specific, and this
                   catalogue holds only built-ins. Calling that an error would
                   refuse correct detections in tenants that use custom roles.

    Silent for every binding whose name says nothing about a role, which is
    almost all of them. The alias list is deliberately small and unambiguous --
    a term that could mean two roles is absent rather than guessed.
    """
    if not roles.loaded():
        return []
    src = _blank_strings_and_comments(kql)
    out = []
    # A `let` binding, or an `extend` assignment, holding a single GUID. The
    # string was blanked above so the literal is read from the ORIGINAL text at
    # the same offset -- blanking is what keeps a GUID inside a comment from
    # counting.
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)\s*[\"']", src):
        want = roles.intended(m.group(1))
        if not want:
            continue
        literal = roles.GUID.search(kql[m.end() - 1:m.end() + 80])
        if not literal:
            continue
        got = roles.name_for(literal.group(0))
        if not got:
            out.append((
                f'WARNING: "{m.group(1)}" is named for the {want} role but '
                f'holds {literal.group(0)}, which is not an Azure built-in '
                f"role. If that is a custom role definition in this tenant, "
                f"ignore this; otherwise the detection is searching for a role "
                f"that does not exist."))
        elif got.lower() != want.lower():
            out.append((
                f'"{m.group(1)}" is named for the {want} role but holds the '
                f'GUID for {got}. The built-in id for {want} is '
                f'{roles.BY_NAME.get(want.lower(), "unknown")}. The query runs '
                f"and matches nothing, because it is searching for a different "
                f"role than the one it is named for."))
    return out


# A regex literal as KQL writes one: @"..." verbatim, or "..." with escapes.
_EXTRACT = re.compile(
    r"""extract\s*\(\s*(@?)(["'])(?P<pattern>(?:\\.|(?!\2).)*)\2\s*,"""
    r"""\s*\d+\s*,\s*(?P<source>[^,)]+)""", re.VERBOSE)

# The shapes a GUID pattern takes: a 36-character run, or the 8-4-4-4-12 groups
# spelled out.
_GUID_PATTERN = re.compile(r"\{36\}|\{8\}\s*-.*\{4\}.*\{12\}")

# Names that hold an ARM resource id, which always BEGINS /subscriptions/<guid>/.
_ARM_ID_NAME = re.compile(r"(?:^|_|\b)(?:.*id|scope|uri|url|path|entity|resource)$",
                          re.IGNORECASE)


def _without_comments(kql: str) -> str:
    """`kql` with `//` comments removed and string literals intact.

    `_blank_strings_and_comments` cannot be used here: the thing being examined
    IS a string literal -- the regex handed to `extract` -- and blanking it
    leaves nothing to read. Stripping comments naively cannot be used either,
    because `//` appears inside real KQL strings: `extract("https://([^.]+)\\.",
    1, Id)` is a query in this corpus.
    """
    out, i, n = [], 0, len(kql)
    while i < n:
        ch = kql[i]
        if ch == "@" and i + 1 < n and kql[i + 1] in "\"'":
            quote = kql[i + 1]
            end = kql.find(quote, i + 2)
            end = n if end < 0 else end + 1
            out.append(kql[i:end])
            i = end
        elif ch in "\"'":
            j = i + 1
            while j < n and kql[j] != ch:
                j += 2 if kql[j] == "\\" else 1
            out.append(kql[i:min(j + 1, n)])
            i = min(j + 1, n)
        elif ch == "/" and i + 1 < n and kql[i + 1] == "/":
            j = kql.find("\n", i)
            i = n if j < 0 else j
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _unpinned_guid_extractions(kql: str) -> list[str]:
    """`extract` calls that will return the subscription id, not the one wanted.

    An ARM resource id always begins `/subscriptions/<guid>/`, so the FIRST
    thing in it matching a GUID is the subscription. A pattern that does not
    pin where the GUID sits therefore returns the subscription on every row, in
    every tenant, forever:

        extract(@"[0-9a-f-]{36}", 0, roleDefinitionId)
          -> <the subscription's own guid, from the front of the path>
        extract(@"([0-9a-f-]{36})$", 1, roleDefinitionId)
          -> 8e3af657-a8ff-443c-a75c-2fe8c4bcb635   (Owner, the role asked for)

    Measured against a live workspace, both above, on the same rows.

    A detection then compares that subscription id to a role id and matches
    nothing. It is the second half of a pair: the version this replaced had a
    correctly anchored pattern holding the WRONG GUID, so the same detection was
    dead twice for opposite reasons and looked different each time.

    A pattern is PINNED by an anchor (`^`, `$`) or by literal text outside a
    character class (`/roleDefinitions/`, `providers/Microsoft.KeyVault/`).
    Across every detection on disk, nineteen of twenty `extract` calls pin
    themselves one of those two ways; this finds the twentieth.
    """
    out = []
    for m in _EXTRACT.finditer(_without_comments(kql)):
        pattern, source = m.group("pattern"), m.group("source").strip()
        if not _GUID_PATTERN.search(pattern):
            continue
        # Only where the source is an ARM path. A GUID column needs no extract
        # at all, so this narrows with nothing lost.
        bare = re.sub(r"^\w+\s*\(|\)+$", "", source).strip()
        if not _ARM_ID_NAME.search(bare):
            continue
        if "^" in pattern or "$" in pattern:
            continue
        # Literal text outside a character class pins it just as well.
        without_classes = re.sub(r"\[[^\]]*\]", "", pattern)
        if re.search(r"[A-Za-z/]", re.sub(r"\\.", "", without_classes)):
            continue
        out.append(
            f'extract(@"{pattern}", ..., {source}) is not anchored, and '
            f"{source} is an ARM resource id beginning /subscriptions/<guid>/. "
            f"The first match is the SUBSCRIPTION id, on every row. Anchor the "
            f'pattern with `$` or name the path segment before it, e.g. '
            f'extract(@"({pattern})$", 1, {source}).')
    return out


def _typed_columns(table: str) -> frozenset[str]:
    """The vendored reference columns for a table, or empty.

    Imported lazily and defensively: this module is imported by the report
    renderers, and a missing catalogue must narrow what can be checked rather
    than raise.
    """
    try:
        from ..kusto_offline import schema_for_table

        return frozenset(schema_for_table(table))
    except Exception:  # noqa: BLE001 - a catalogue gap is not a validation error
        return frozenset()


def validate_kql(kql: str, table_name: str, expected_provider: str = "",
                 *, allow_placeholders: bool = False,
                 documented: frozenset[str] | None = None,
                 context: str = "detection") -> ValidationResult:
    """Validate a generated KQL query against the table's known schema, returning a
    ValidationResult. Checks the query targets the expected table, catches per-table
    hallucination patterns (wrong/nonexistent fields, wrong types, wrong case,
    mv-expand on flat tables, malformed extractions), and skips column validation
    for unknown tables or the generic AzureDiagnostics path.

    `allow_placeholders=True` drops the fill-in check for an artefact that is MEANT
    to be filled in. A Phase 2 detection is deployed as generated, so a surviving
    `[...]` slot is a defect; a Phase 3 playbook is a runbook a responder completes
    at the console, and its own prompt skeleton hands the model
    `let AlertActor = "[FROM ALERT: ActorUpn or ActorId]";` to emit. Applying the
    detection rule there failed every playbook that followed the prompt correctly,
    and spent a corrective call telling the model to remove the slots the skeleton
    requires. Named rather than inferred from the table: the same query text is
    right in one phase and wrong in the other, so the caller has to say which."""
    # Query-shape checks first — dead/non-KQL queries fail regardless of table.
    errors, warnings = _structural_issues(kql, allow_placeholders=allow_placeholders,
                                          context=context)

    # EVERY PER-TABLE CHECK BELOW READS THIS, not `kql`. A comment is not a
    # defect, and 34 of the 38 regex checks in this function scanned the raw
    # query -- so a correct detection carrying
    # `// there is no UserPrincipalName on this table` was rejected for naming
    # the column it was warning against, and the corrective retry told the model
    # to fix something already right.
    #
    # Comments only. String literals are KEPT, because several checks read what
    # is inside the quotes.
    scan = _blank_comments(kql)

    # The query must target a table that actually exists. A query whose table is
    # neither the expected one nor any known Azure table is a hallucination — before
    # F2 this was total silence (only known-but-wrong tables warned).
    detected = extract_query_table(kql)
    if detected and detected != table_name and detected not in _known_tables():
        errors.append(
            f'Query targets unknown table "{detected}" — not a known Azure Monitor table '
            f'(expected "{table_name}"). This looks hallucinated.'
        )

    # Generic AzureDiagnostics path (dynamic routing): validate the scoping that
    # keeps the shared table selective rather than column-checking it, and don't
    # penalize it for being AzureDiagnostics — it is the intended table here.
    if table_name == "AzureDiagnostics":
        diag = _validate_azure_diagnostics(_blank_comments(kql), expected_provider)
        errors.extend(diag.errors)
        warnings.extend(diag.warnings)
        unique_errors = list(dict.fromkeys(errors))
        unique_warnings = list(dict.fromkeys(warnings))
        return ValidationResult(valid=not unique_errors, warnings=unique_warnings, errors=unique_errors)

    schema = TABLE_SCHEMAS.get(table_name)
    if schema is None:
        warnings.append(f'No known schema for table "{table_name}". Skipping column validation.')
        unique_errors = list(dict.fromkeys(errors))
        unique_warnings = list(dict.fromkeys(warnings))
        return ValidationResult(valid=not unique_errors, warnings=unique_warnings, errors=unique_errors)

    schema_set = set(schema)
    schema_lower = {col.lower(): col for col in schema}

    # --- Check 1: query references the expected table ---
    detected_table = extract_query_table(kql)
    if detected_table and detected_table != table_name:
        if detected_table == "AzureDiagnostics":
            errors.append(
                f'Query uses "AzureDiagnostics" instead of the resource-specific table '
                f'"{table_name}". Use {table_name} directly for better performance and '
                f"simpler queries."
            )
        elif detected_table in TABLE_SCHEMAS:
            warnings.append(
                f'Query references table "{detected_table}" but expected "{table_name}".'
            )

    # --- Check 2: AzureActivity-specific hallucinations ---
    if table_name == "AzureActivity":
        if re.search(r"\|\s*where\s+OperationName\s*(==|=~|!=|has|contains|startswith)", scan, re.IGNORECASE):
            errors.append(
                'AzureActivity: Filtering on "OperationName" — use "OperationNameValue" '
                "instead. OperationName is a display name and is unreliable for filtering."
            )
        if re.search(r"\|\s*where\s+Result\s*(==|=~|!=|has|contains)", scan, re.IGNORECASE):
            errors.append('AzureActivity: "Result" does not exist — use "ActivityStatusValue" instead.')
        if re.search(r"tostring\(\s*(Caller|CallerIpAddress)\s*\)", scan, re.IGNORECASE):
            warnings.append(
                "AzureActivity: Unnecessary tostring() on plain string field. "
                "Caller and CallerIpAddress are already strings."
            )
        if re.search(r"\bInitiatedBy\b", scan):
            errors.append(
                'AzureActivity: "InitiatedBy" does not exist — use "Caller" and '
                '"CallerIpAddress" directly.'
            )
        if re.search(r"\bTargetResources\b", scan):
            errors.append(
                'AzureActivity: "TargetResources" does not exist — use "ResourceId", '
                '"ResourceGroup", "SubscriptionId".'
            )
        if re.search(r"\bUserPrincipalName\b", scan):
            errors.append('AzureActivity: "UserPrincipalName" does not exist — use "Caller" directly.')

    # --- Check 3: AuditLogs-specific checks ---
    if table_name == "AuditLogs":
        if re.search(r"\bActivityStatusValue\b", scan):
            errors.append(
                'AuditLogs: "ActivityStatusValue" does not exist — use "Result" '
                '(lowercase values: "success"/"failure").'
            )
        # A Category value in a LoggedByService filter. Both columns exist, so this
        # parses, validates, deploys, runs clean and matches NOTHING for ever —
        # measured on a live tenant, where the same row carried
        # Category="ApplicationManagement" and LoggedByService="Core Directory".
        # One run shipped 25 of 25 detections with this filter; none could fire.
        # An ERROR, not a warning: the detection is dead on arrival.
        # Was eight names typed by hand, out of the forty-eight the reference
        # publishes. So LoggedByService == "EntitlementManagement" (or
        # KeyManagement, or Authentication, or thirty-seven others) sailed
        # straight through the one check that exists to stop it. Read the
        # vocabulary instead: every name in it is a Category value.
        from ..entra_audit_activities import categories as _categories

        _CATEGORY_VALUES = _categories()
        for _m in re.finditer(
            r'LoggedByService\s*(?:==|=~|in~?)\s*\(?\s*"([^"]+)"', scan
        ):
            if _m.group(1) in _CATEGORY_VALUES:
                errors.append(
                    f'AuditLogs: LoggedByService == "{_m.group(1)}" matches nothing — '
                    f'that is a Category value. LoggedByService holds the SERVICE '
                    f'("Core Directory", "Self-service Group Management", ...). '
                    f'Filter Category instead, or drop the filter: OperationName is '
                    f'already specific.'
                )
        # Case-sensitive OperationName matching. Microsoft's documented activity
        # names and what a tenant WRITES differ in case — measured: the reference
        # says "Delete Conditional Access policy", the tenant logged "Delete
        # conditional access policy". `==` is case-sensitive in KQL, so the query
        # parses, validates, executes and matches nothing for ever. AzureActivity
        # has had this rule for OperationNameValue all along; AuditLogs did not,
        # and 41 of 41 generated detections used `==`.
        for _m in re.finditer(r'OperationName\s*(==|!=)\s*"([^"]+)"', scan):
            errors.append(
                f'AuditLogs: OperationName {_m.group(1)} "{_m.group(2)}" is '
                f'CASE-SENSITIVE. Documented activity names and the casing a tenant '
                f'actually logs differ, so this can match nothing. Use '
                f'{"=~" if _m.group(1) == "==" else "!~"} instead.'
            )
        if re.search(r'\|\s*where\s+Result\s*(==|!=)\s*"(Success|Failure)"', scan):
            warnings.append(
                'AuditLogs: Result values are lowercase — use "success"/"failure", '
                'not "Success"/"Failure".'
            )
        # Ordering is judged on the CODE, never on the comments. Scanning raw text
        # meant the line `// Extract InitiatedBy BEFORE mv-expand` -- written by a
        # model that had followed the rule, and describing the very ordering this
        # checks -- put "mv-expand" ahead of the first real InitiatedBy access and
        # fired the warning on a correct query. A gate that fires on correct output
        # is worse than no gate: it gets ignored, and then it is ignored when it is
        # right. Every other rule in this file already scans the blanked source.
        bare_order = _blank_strings_and_comments(kql)
        mv_expand_idx = bare_order.find("mv-expand")
        initiated_by_idx = bare_order.find("InitiatedBy.")
        if (
            mv_expand_idx != -1
            and initiated_by_idx != -1
            and mv_expand_idx < initiated_by_idx
            and re.search(r"mv-expand\s+TargetResources", bare_order, re.IGNORECASE)
        ):
            warnings.append(
                "AuditLogs: InitiatedBy fields are extracted AFTER mv-expand TargetResources. "
                "Extract InitiatedBy fields BEFORE mv-expand to avoid empty values."
            )

    # --- Check 4: Azure Storage data-plane checks (blob/file/queue/table share
    # one schema — same StatusCode-is-STRING and CallerIpAddress-casing rules) ---
    if table_name in ("StorageBlobLogs", "StorageFileLogs", "StorageQueueLogs", "StorageTableLogs"):
        if re.search(r"\bCallerIPAddress\b", scan):
            errors.append(
                f'{table_name}: "CallerIPAddress" is wrong — use "CallerIpAddress" (lowercase p).'
            )
        if re.search(r"\|\s*where\s+StatusCode\s*(>=|<=|>|<)\s*\d+", scan):
            errors.append(
                f"{table_name}: StatusCode is a STRING — use string comparison "
                '(e.g. == "200"), not numeric.'
            )

    # --- Check 5: AZKVAuditLogs-specific checks ---
    # These were the wrong way round until a live run caught it. AZKVAuditLogs is
    # the DEDICATED Key Vault table: CallerIpAddress (lowercase p), and one
    # dynamic Identity column. `CallerIPAddress` and `identity_s` are what Key
    # Vault logs are called when they land in the shared AzureDiagnostics table,
    # and asserting them here taught the generator to write queries the workspace
    # then rejected with "Failed to resolve scalar expression named 'identity_s'".
    if table_name == "AZKVAuditLogs":
        if re.search(r"\bCallerIPAddress\b", scan):
            errors.append(
                'AZKVAuditLogs: "CallerIPAddress" is wrong — the dedicated table uses '
                '"CallerIpAddress" (lowercase p). The capital-IP spelling is '
                "AzureDiagnostics, and KQL column names are case-sensitive."
            )
        if re.search(r"parse_json\(\s*Identity\s*\)", scan):
            warnings.append(
                "AZKVAuditLogs: Identity is already dynamic — parse_json() around it is "
                "redundant. Index it directly: tostring(Identity.claim.upn)."
            )
        if re.search(r"\|\s*where\s+HttpStatusCode\s*(?:==|!=|>=|<=|>|<)\s*['\"]", scan):
            errors.append(
                "AZKVAuditLogs: HttpStatusCode is an INT — compare numerically "
                "(e.g. >= 300), not against a string."
            )

    # --- Check 5b: FunctionAppLogs — execution telemetry, not an audit table ---
    # It has no OperationName / CallerIpAddress / StatusCode / AuthenticationType
    # columns (those are data-plane audit fields); flag them as hallucinations.
    if table_name == "FunctionAppLogs":
        absent = re.search(
            r"\b(OperationName|CallerIpAddress|CallerIPAddress|StatusCode|AuthenticationType)\b",
            scan,
        )
        if absent:
            errors.append(
                f'FunctionAppLogs: "{absent.group(1)}" does not exist — FunctionAppLogs is '
                "host/execution telemetry, not an access-audit table. Filter with Category, "
                "FunctionName, Level, or ExceptionType instead."
            )

    # --- Check 5c: AppServiceAuditLogs — publishing-logon audit, no status field ---
    # It records successful logons only (no ResultType/ResultDescription/StatusCode)
    # and its source IP is UserAddress, not CallerIpAddress.
    if table_name == "AppServiceAuditLogs":
        absent = re.search(r"\b(ResultDescription|ResultType|StatusCode|CallerIpAddress|CallerIPAddress)\b", scan)
        if absent:
            col = absent.group(1)
            hint = (
                "source IP is UserAddress"
                if col.lower().startswith("callerip")
                else "this table logs successful logons only — there is no status/result column"
            )
            errors.append(f'AppServiceAuditLogs: "{col}" does not exist — {hint}.')

    # --- Check 5d: Azure Firewall — table-specific column absences + INT ports ---
    if table_name.startswith("AZFW"):
        # Ports/Severity are INT — quoting them is a type error.
        if re.search(r"\|\s*where\s+(SourcePort|DestinationPort|Severity)\s*(==|!=|>=|<=|>|<)\s*\"", scan):
            errors.append(
                f"{table_name}: SourcePort/DestinationPort/Severity are INT — use "
                "numeric comparison (e.g. == 443), not a quoted string."
            )
        if table_name == "AZFWApplicationRule" and re.search(r"\bDestinationIp\b", scan):
            errors.append(
                "AZFWApplicationRule: no DestinationIp column — application rules are "
                "FQDN/URL based. Use Fqdn (or TargetUrl for TLS-inspected requests)."
            )
        if table_name in ("AZFWNatRule", "AZFWDnsQuery") and re.search(r"\bAction\b", scan):
            errors.append(
                f"{table_name}: no Action column — this table is not a rule allow/deny "
                "match. Use TranslatedIp/Port (NAT) or ResponseCode/QueryName (DNS)."
            )
        if table_name == "AZFWDnsQuery" and re.search(r"\bDestinationIp\b", scan):
            errors.append(
                "AZFWDnsQuery: no DestinationIp column — the query target is QueryName; "
                "the client is SourceIp."
            )

    # --- Check 5e: Container Registry — DurationMs is a STRING, not int ---
    if table_name.startswith("ContainerRegistry") and re.search(
        r"\|\s*where\s+DurationMs\s*(>=|<=|>|<)\s*\d+", scan
    ):
        errors.append(
            f"{table_name}: DurationMs is a STRING — do not use numeric comparison."
        )

    # --- Check 6: Graph Activity (modern + legacy) — ResponseStatusCode is INT ---
    if table_name in ("MicrosoftGraphActivityLogs", "AADGraphActivityLogs") and re.search(
        r'\|\s*where\s+ResponseStatusCode\s*(==|!=)\s*"', scan
    ):
        errors.append(
            f"{table_name}: ResponseStatusCode is INT — use numeric "
            "comparison (e.g. == 200), not string."
        )

    # --- Check 6b: RequestUri is an ABSOLUTE URL, so `==` never matches -------
    # Measured on a live workspace: the column holds
    # "https://graph.microsoft.com/v1.0/users/delta", not "/v1.0/users". A
    # path-shaped equality therefore returns zero rows for ever, while the `has`
    # form on the same path returns hundreds. Both appeared in ONE generated run,
    # because the asset described the column as a "full URI" and then gave path
    # examples — the model followed each half in different detections.
    #
    # Only equality is flagged. `has`, `contains`, `startswith` and `endswith` all
    # work against the absolute URL and are what the asset already recommends.
    if table_name in ("MicrosoftGraphActivityLogs", "AADGraphActivityLogs"):
        for _m in re.finditer(
            r'\b(RequestUri|BasePath)\s*(==|!=)\s*"(/[^"]*)"', scan
        ):
            errors.append(
                f'{table_name}: {_m.group(1)} {_m.group(2)} "{_m.group(3)}" matches '
                f"nothing — the column holds an ABSOLUTE URL "
                f'("https://graph.microsoft.com{_m.group(3)}"), not a path. Use '
                f'`{_m.group(1)} has "{_m.group(3)}"`, which the host cannot break.'
            )

    # --- Check 6c: a literal outside a column's DOCUMENTED value set ---------
    #
    # The silent-death class: a wrong value parses, validates, executes and
    # matches nothing for ever. `ConditionalAccessStatus == "Success"` is the
    # shape — the documented value is lowercase `success`, so the rule is dead
    # and nothing says so.
    #
    # Only CLOSED sets ("Possible values:") are enforced. An illustrative set
    # is not a vocabulary: a live workspace returned RemoteIPType `LinkLocal`,
    # which the page's "for example" list does not contain, so rejecting on it
    # would fail a correct query.
    #
    # Two guards keep this from firing on something it does not understand. The
    # literal must be member-SHAPED — RiskEventTypes_V2 holds a serialized array
    # and `== "[]"` is a legitimate emptiness test, not a misspelled member. And
    # `=~`/`!~` compare case-insensitively, so a case-only difference is correct
    # there and is only a defect under `==`.
    _closed = column_values.enforceable(table_name)
    if _closed:
        _member = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
        for _m in re.finditer(
            r"\b(" + "|".join(map(re.escape, _closed)) + r")\s*(==|!=|=~|!~)\s*\"([^\"]*)\"",
            scan,
        ):
            _col, _op, _lit = _m.group(1), _m.group(2), _m.group(3)
            if not _member.match(_lit):
                continue
            _allowed = _closed[_col]
            _hit = (
                _lit in _allowed
                if _op in ("==", "!=")
                else _lit.lower() in {v.lower() for v in _allowed}
            )
            if not _hit:
                _near = [v for v in _allowed if v.lower() == _lit.lower()]
                _fix = (
                    f' — the documented value is "{_near[0]}" (case matters under {_op})'
                    if _near
                    else f" — documented values are: {', '.join(_allowed)}"
                )
                errors.append(
                    f'{table_name}: {_col} {_op} "{_lit}" matches nothing{_fix}.'
                )

    # --- Check 6a: Entra sign-in tables — ResultType is a STRING code ---
    _SIGNIN_TABLES = (
        "SigninLogs",
        "AADNonInteractiveUserSignInLogs",
        "AADServicePrincipalSignInLogs",
        "AADManagedIdentitySignInLogs",
    )
    if table_name in _SIGNIN_TABLES:
        if re.search(r"\|\s*where\s+ResultType\s*(==|!=)\s*\d+\b", scan) and not re.search(
            r'\|\s*where\s+ResultType\s*(==|!=)\s*"', scan
        ):
            errors.append(
                f'{table_name}: ResultType is a STRING code — compare to a quoted '
                'value (e.g. == "0" for success), not a bare number.'
            )
        if re.search(r"\bActivityStatusValue\b", scan):
            errors.append(
                f'{table_name}: "ActivityStatusValue" does not exist — use ResultType '
                '(string; "0" = success).'
            )

    # --- No time-column check on the Device* tables, and that is deliberate ---
    #
    # A check here rejected `TimeGenerated` because advanced hunting's time
    # column is `Timestamp`. True in advanced hunting, false here: the Log
    # Analytics copy carries BOTH, and they hold the same instant. Measured
    # 2026-08-28 across all five Device* tables -- 167 of 167 rows identical,
    # worst delta 0s -- so neither column is wrong and neither is an error.
    #
    # It marked all 15 detections of a defender-endpoint run FAILED VALIDATION,
    # each after a retry that could not succeed. Pick the authority that matches
    # the copy being queried.

    # --- Check 6d: AKSAuditAdmin excludes get/list (reads) ---
    if table_name == "AKSAuditAdmin" and re.search(r"\bVerb\b", scan) and re.search(
        r'"(get|list)"', scan, re.IGNORECASE
    ):
        errors.append(
            'AKSAuditAdmin excludes get/list verbs (reads) — those events are not in '
            "this table. Use AKSAudit for read/enumeration detections."
        )

    # --- Check 7: mv-expand on a flat table's own COLUMNS ---
    # "Flat" describes the schema, not the data. AzureActivity has no array
    # column, and it also carries Properties, inside which
    # requestbody.properties.logs is a real array that a correct detection must
    # expand -- measured: 16 group-shaped entries and 6 named ones on live
    # diagnostic-settings writes. AZKVAuditLogs is the same story with Identity.
    # Banning the operator outright rejected the only correct way to read those,
    # so the check now looks at what is being expanded: a bare top-level column
    # of the table is still wrong, and anything derived -- a dotted path into a
    # parsed payload, a locally extended name, a function result -- is allowed.
    if table_name in FLAT_TABLES:
        for operand in re.findall(
                r"\|\s*mv-expand\s+(?:\w+\s*=\s*)?([^|\n]+)", scan, re.IGNORECASE):
            target = operand.strip().split()[0].rstrip(",")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", target):
                continue          # dotted path, call, or expression: derived
            if target in (TABLE_SCHEMAS.get(table_name) or ()):
                errors.append(
                    f"{table_name}: mv-expand on `{target}`, a column of this flat "
                    f"table. No column here holds an array, so expanding one either "
                    f"fails or yields the key/value pairs of a JSON object rather "
                    f"than the rows you want. Parse first, then expand the path: "
                    f"`mv-expand entry = Body.properties.logs`.")

    # --- Check 8: AzureDiagnostics inline references ---
    if (
        re.search(r"\bAzureDiagnostics\b", scan)
        and table_name != "AzureDiagnostics"
        and detected_table != "AzureDiagnostics"
    ):
        warnings.append(
            'Query references "AzureDiagnostics" — consider using the resource-specific '
            f'table "{table_name}" instead.'
        )

    # --- Check 9: tostring() on plain string fields ---
    plain_strings = PLAIN_STRING_FIELDS.get(table_name)
    if plain_strings:
        for m in re.finditer(r"tostring\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", scan):
            if m.group(1) in plain_strings:
                warnings.append(
                    f'{table_name}: Unnecessary tostring({m.group(1)}) — "{m.group(1)}" '
                    f"is already a plain string."
                )

    # --- Check 10: column case check ---
    _LITERAL_WORDS = re.compile(
        r"^(Success|Failure|Start|Failed|Anonymous|SAS|OAuth|AccountKey|GET|POST|PUT|PATCH|DELETE)$"
    )
    # Scan with string literals and comments blanked out — a column-lookalike
    # inside a value (e.g. AUTHORIZATION in "MICROSOFT.AUTHORIZATION/...") is not
    # a column reference (F5). Also stops a `|` inside a string from being read
    # as a pipe when splitting clauses.
    case_scan_src = _blank_strings_and_comments(kql)
    for clause_match in re.finditer(
        r"\|\s*(?:where|extend|project|summarize|order\s+by|sort\s+by)\s+([^|]+)",
        case_scan_src,
        re.IGNORECASE,
    ):
        for ident in re.findall(r"\b([A-Z][A-Za-z0-9_]*)\b", clause_match.group(1)):
            if (
                ident in ("TimeGenerated", "Type")
                or ident in TABLE_SCHEMAS
                or _LITERAL_WORDS.match(ident)
                or ident in schema_set
            ):
                continue
            correct = schema_lower.get(ident.lower())
            if correct and correct != ident:
                warnings.append(f'{table_name}: Column "{ident}" has wrong case — use "{correct}".')
            elif (not correct and ident not in _defined_names(kql)
                  and ident not in _foreign_scope_names(kql, table_name)):
                # The half that was missing. This block compared CASE and did
                # nothing when the name was not in the schema at all -- so a
                # mis-typed real column was caught and a wholly invented one was
                # not, which is the worse of the two. `ActorRiskScore` on
                # AzureActivity passed every check and would fail against the
                # live workspace after deployment.
                #
                # `TABLE_SCHEMAS` is the wrong authority to REJECT on, though. It
                # is extracted from this repo's prompt assets -- the columns the
                # prompt teaches -- and AzureActivity lists sixteen there against
                # thirty-seven Microsoft documents. A live run rejected a correct
                # detection filtering on `OperationId` for exactly that reason.
                #
                # So three states, not two. `documented` is Microsoft's own list,
                # fetched for grounding and now read on this side too. A name in
                # it is real whatever the prompt taught. A name in neither is a
                # fabrication ONLY if the fetch succeeded; when it did not, the
                # question was never asked and a warning says so.
                if documented and ident in documented:
                    continue
                if documented is None or not documented:
                    warnings.append(
                        f'{table_name}: "{ident}" is not a column the prompt teaches. '
                        f"Microsoft's column list could not be fetched, so this was "
                        f"NOT checked against it -- verify the name before deploying."
                    )
                    continue
                errors.append(
                    f'{table_name}: "{ident}" is not a column on this table. The query '
                    f"parses and will fail to resolve against the live schema. Check the "
                    f"table's schema reference, or define it with extend/let first."
                )

    # --- Check 10a: the operation value the query filters on ---
    # The other half of the unknown-column bug, and the one that has actually
    # shipped repeatedly: a filter on an operation string the log never writes.
    # The DECLARED operation on the attack vector is already checked; the string
    # inside the KQL was not, so a real operation could be declared and a typo of
    # it queried. Same outcome as a phantom column -- parses, deploys, never
    # fires -- and harder to see, because the value looks like a plausible name.
    #
    # Error or warning depending on whether the table's vocabulary is CLOSED.
    #
    # This was warning-only, on the reasoning that `is_known` answers "not in this
    # snapshot" rather than "not real" -- true while a vocabulary might be a
    # partial sample. It stopped being true when a target began requiring a
    # complete partition: every name AZKVAuditLogs can write is either mapped to
    # a technique or rejected in writing, so a name in neither pile is wrong, and
    # a warning lets it ship. AzureActivity stays a warning because its
    # vocabulary is per resource type and the table alone cannot judge.
    from ..services import vocabulary_is_closed

    closed = vocabulary_is_closed(table_name)
    # `scan`, not `kql`: this reads operation names out of the query, and a
    # comment naming an operation is not a filter on one.
    for literal in _operation_literals(scan, table_name):
        # A playbook is a runbook the responder completes at the console, so the
        # operation it filters on is a slot the template hands over on purpose.
        # `allow_placeholders` already stands the structural fill-in check down
        # for that artefact; judging the same slot as an operation NAME is the
        # identical mistake one rule further on, and it costs a corrective retry
        # telling the model to remove a field the skeleton required.
        if allow_placeholders and _PLACEHOLDER.fullmatch(literal.strip()):
            continue
        for finding in validate_operation(literal, table_name, expected_provider or None):
            (errors if closed else warnings).append(f"operation filter: {finding}")

    # --- Check 10b: AzureDiagnostics column names on a dedicated table ---
    # A service that moved from the shared AzureDiagnostics table to its own
    # resource-specific one has two documented spellings for the same field, and
    # only one exists here. AzureDiagnostics flattens resource-log properties into
    # columns named property + a type suffix (identity_s, httpStatusCode_d,
    # activityId_g); the dedicated tables use plain names (Identity,
    # HttpStatusCode, ActivityId). Generation trained on AzureDiagnostics-era
    # examples reaches for the suffixed form, the query parses, and the workspace
    # refuses it. Nothing else in this validator catches it: the case check only
    # scans capitalised identifiers, so a lowercase fabrication is invisible.
    #
    # Only flagged when the query does not DEFINE the name itself — an extend or a
    # let may legitimately create `foo_s`.
    if table_name != "AzureDiagnostics":
        defined = {m.group(1) for m in re.finditer(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)", _blank_strings_and_comments(kql)
        )}
        # Judged against every column list available, not just the curated one.
        # `TABLE_SCHEMAS` holds the columns the PROMPT teaches -- sixteen of
        # AzureActivity's thirty-seven -- and AzureActivity really does have
        # `Authorization_d`, `Claims_d` and `Properties_d` as dynamic columns.
        # Checking only the short list flagged all three as fabrications and
        # rejected correct detections: a valid User Access Administrator query
        # was killed for `Authorization_d`, and a later run lost BOTH of its
        # attempts to `Properties_d` and shipped nothing.
        #
        # That is the worst direction for this check to fail in. A missed
        # fabrication is one bad detection; a false positive here burns the
        # retry and throws away work that was right.
        known = schema_set | set(documented or ()) | set(_typed_columns(table_name))
        for ident in dict.fromkeys(_AZDIAG_SUFFIXED.findall(_blank_strings_and_comments(kql))):
            if ident in known or ident in defined:
                continue
            stem = ident.rsplit("_", 1)[0]
            correct = schema_lower.get(stem.lower()) or schema_lower.get(
                stem.lower().replace("_", "")
            )
            fix = f' — use "{correct}"' if correct else ""
            errors.append(
                f'{table_name}: "{ident}" is an AzureDiagnostics column name{fix}. The '
                "resource-specific table does not have it, and the query will fail to "
                "resolve it against the live schema."
            )

    # --- Check 11: malformed tostring(split(...))[i] indexing ---
    # The ) closes tostring() BEFORE the [i], so the index is applied to the
    # stringified whole array instead of an element. BasePath (etc.) becomes
    # garbage and any downstream `matches`/`==` silently never fires — a false
    # negative that passes schema checks. Correct form: tostring(split(x, d)[i]).
    # The split(...) args may themselves contain one level of parens (a nested
    # call like tolower(x), or a delimiter of ")"), so match balanced-ish args
    # rather than [^)]* which would stop at the first inner ).
    if re.search(r"tostring\(\s*split\((?:[^()]|\([^()]*\))*\)\s*\)\s*\[", scan):
        errors.append(
            "Malformed extraction: tostring(split(...))[i] applies the index to the "
            "stringified array, not the element — downstream filters silently never "
            "match. Move the index inside tostring: tostring(split(x, delim)[i])."
        )

    # --- Check 12: an extend referencing a name defined beside it ---
    # KQL evaluates every assignment in one `extend` against the operator's
    # INPUT, so a sibling assignment is not in scope. This parses, passes every
    # schema check here, and the workspace refuses it:
    #
    #     | extend Auth = parse_json(Authorization), Scope = tostring(Auth.scope)
    #     'extend' operator: Failed to resolve scalar expression named 'Auth'
    #
    # Two generated detections shipped with it, on different targets and
    # different tables -- an ARM query reaching for `Auth.scope` and a Key Vault
    # query reaching for `CallerOID` -- and both reported `error` against the
    # live workspace with 144 and 6 real events behind them. Their own siblings
    # in the same directory split the same work across two `extend`s and ran
    # fine, which is the whole fix.
    #
    # `_defined_names` treats a name as defined the moment it is assigned
    # anywhere, which is right for the fabrication check above and blind here:
    # the question is not whether the name exists but whether it exists YET.
    for issue in _extend_self_reference(kql):
        errors.append(issue)

    # --- Check 13: a role GUID that contradicts its own variable name ---
    # See `_role_guid_mismatches`. A warning about an unknown GUID (possibly a
    # custom role) is separated from an error about a built-in role that is the
    # wrong one.
    for issue in _role_guid_mismatches(kql):
        if issue.startswith("WARNING: "):
            warnings.append(issue[len("WARNING: "):])
        else:
            errors.append(issue)

    # --- Check 14: a GUID extraction that will return the subscription id ---
    for issue in _unpinned_guid_extractions(scan):
        errors.append(issue)

    warnings.extend(_performance_issues(scan, context))

    unique_errors = list(dict.fromkeys(errors))
    unique_warnings = list(dict.fromkeys(warnings))
    return ValidationResult(valid=not unique_errors, warnings=unique_warnings, errors=unique_errors)
