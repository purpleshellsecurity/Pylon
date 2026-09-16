"""Schema-driven KQL validation from LIVE docs (flagged pipeline feature).

Keystone of docs/DESIGN-any-service.md. Instead of validating generated KQL only
against the hardcoded column lists in schemas.py, this fetches a table's REAL
column schema from the Azure Monitor docs (the same source grounding.py uses) and
validates against it. Wired into run_detection_phase behind `--dynamic-schema`
(EngineRequest.dynamic_schema); off by default.

It *augments* validate_kql (which keeps all its per-table quirk checks) with a
live column-existence check — pure upside for tables that have no hardcoded
schema (e.g. CDBDataPlaneRequests, in _GENERATION_ONLY_TABLES), where column
validation is otherwise skipped entirely.

Two runnable modes:
    python -m pylon.validation.live_schema CDBDataPlaneRequests   # demo
    python -m pylon.validation.live_schema compare                # vs schemas.py

The column extractor is a documented heuristic (strips comments, string
literals, query-defined aliases, KQL keywords, and function calls). A production
version would use a real KQL parser.
"""
from __future__ import annotations

import asyncio
import re
import sys

from ..grounding import DOCS_BASE, _fetch_cached
from .. import kqltext
from .validate_kql import ValidationResult

# ── Layer 3: fetch + parse the live table schema ──────────────────────────────


def parse_table_schema(md: str) -> dict[str, str]:
    """Parse an Azure Monitor table doc's '| Column | Type | Description |'
    table into {column_name: type}. Handles the doc's `\\_`-escaped names."""
    schema: dict[str, str] = {}
    start = md.find("| Column")
    if start == -1:
        return schema
    for line in md[start:].splitlines()[2:]:  # skip header row + |---| separator
        line = line.strip()
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2:
            continue
        name = cells[0].replace("\\", "").strip("`").strip()
        ctype = cells[1].replace("\\", "").strip("`").strip()
        if name:
            schema[name] = ctype
    return schema


async def fetch_table_schema(table: str) -> dict[str, str]:
    """Live column schema for a table, from the same docs source as grounding."""
    md = await _fetch_cached(f"{DOCS_BASE}/tables/{table.lower()}.md")
    return parse_table_schema(md)


# ── Extract column references from KQL (prototype heuristic) ───────────────────

_KQL_WORDS = {
    "where", "project", "project-away", "project-rename", "extend", "summarize",
    "by", "on", "order", "sort", "asc", "desc", "let", "join", "kind", "inner",
    "leftouter", "rightouter", "fullouter", "leftanti", "rightanti", "leftsemi",
    "union", "distinct", "count", "take", "top", "limit", "and", "or", "not",
    "has", "hasprefix", "hassuffix", "contains", "in", "startswith", "endswith",
    "between", "matches", "regex", "has_any", "has_all", "serialize", "mv-expand",
    "mvexpand", "parse", "evaluate", "render", "as", "step", "true", "false",
    "null", "typeof", "string", "int", "long", "real", "double", "bool",
    "datetime", "timespan", "dynamic", "guid", "decimal", "print",
}
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def referenced_columns(kql: str, table: str) -> set[str]:
    """Best-effort set of column names a query references."""
    # Blank string literals AND // comments in ONE left-to-right pass. Stripping
    # comments first (separately) would treat the `//` inside a URL string
    # literal ("http://", the regex flag "(?i)", "/i:") as the start of a
    # comment, delete the string's closing quote, and leak the scheme
    # (http/https/i) as a phantom column — a false "fabrication" error. The
    # combined pattern consumes a whole "..."/'...' span before any inner `//`
    # can match as a comment (same string-vs-comment precedence validate_kql
    # relies on).
    s = kqltext.blank(kql, string=" ", comment=" ")
    # Names the query itself defines (single '=' assignment, or '... as X').
    defined = set(re.findall(r"([A-Za-z_]\w*)\s*=(?![=~])", s))
    defined |= set(re.findall(r"\bas\s+([A-Za-z_]\w*)", s))

    refs: set[str] = set()
    for m in _IDENT.finditer(s):
        name = m.group()
        if m.start() > 0 and s[m.start() - 1].isdigit():   # timespan unit: 5m, 1h
            continue
        if s[m.end():m.end() + 1] == "(":                  # function call
            continue
        if name.lower() in _KQL_WORDS or name in defined or name == table:
            continue
        refs.add(name)
    return refs


# ── Validate KQL against the fetched schema ───────────────────────────────────


# Columns that are real but that the LA-centric docs sometimes omit from the
# column table, so we must not flag them as fabricated (measured false positives):
# universal Log Analytics columns + Defender advanced-hunting's native Timestamp.
_ALWAYS_VALID = {
    "TimeGenerated", "TenantId", "Type", "SourceSystem", "MG",
    "_ResourceId", "_SubscriptionId", "_BilledSize", "_IsBillable",
    "Timestamp",  # Defender Device* native time column; docs list TimeGenerated only
}


def validate_against_schema(kql: str, schema: dict[str, str], table: str) -> ValidationResult:
    """Same ValidationResult contract as validate_kql, but the schema is LIVE.

    Unknown column -> error (likely fabrication). Right name, wrong case ->
    warning. Empty schema (fetch failed) -> skip, so it degrades gracefully."""
    if not schema:
        return ValidationResult(
            valid=True, errors=[],
            warnings=[f"No live schema fetched for {table}; dynamic validation skipped."],
        )
    names = set(schema)
    lower = {n.lower(): n for n in schema}
    errors: list[str] = []
    warnings: list[str] = []
    for ref in sorted(referenced_columns(kql, table)):
        if ref in names or ref in _ALWAYS_VALID:
            continue
        if ref.lower() in lower:
            warnings.append(f'Column "{ref}" wrong case — use "{lower[ref.lower()]}".')
        else:
            errors.append(f'Column "{ref}" is not in the live {table} schema (possible fabrication).')
    return ValidationResult(valid=not errors, errors=errors, warnings=warnings)


def merge_results(a: ValidationResult, b: ValidationResult) -> ValidationResult:
    """Combine two validation results (used to layer live checks on validate_kql)."""
    return ValidationResult(
        valid=a.valid and b.valid,
        errors=list(dict.fromkeys(a.errors + b.errors)),
        warnings=list(dict.fromkeys(a.warnings + b.warnings)),
    )


# ── Measurement: live schema vs. hardcoded schemas.py (the curated set) ────────


async def compare_to_hardcoded(tables: list[str] | None = None) -> list[dict]:
    """For each hardcoded table, diff the live schema against schemas.py.

    `hardcoded_only` = columns schemas.py claims that the live docs DON'T list —
    i.e. stale/phantom entries the current validator would wave through (the
    class). `live_only` = columns the live docs have that schemas.py lacks
    (hardcoded is a curated subset)."""
    from .schemas import TABLE_SCHEMAS

    tables = tables or sorted(TABLE_SCHEMAS)
    rows: list[dict] = []
    for t in tables:
        hard = set(TABLE_SCHEMAS[t])
        live = set(await fetch_table_schema(t))
        rows.append({
            "table": t,
            "hardcoded": len(hard),
            "live": len(live),
            "agree": len(hard & live),
            "hardcoded_only": sorted(hard - live),
            "live_only": len(live - hard),
        })
    return rows


# ── Runnable modes ────────────────────────────────────────────────────────────

_DEMO_GOOD = """CDBDataPlaneRequests
| where TimeGenerated > ago(1h)
| where OperationName == "Query"
| where StatusCode == "200"
| project TimeGenerated, AccountName, OperationName, StatusCode, RequestCharge"""

_DEMO_FABRICATED = """CDBDataPlaneRequests
| where TimeGenerated > ago(1h)
| where OperationName == "Query"
| project TimeGenerated, AccountName, ResourceId, ThreatScore"""


async def _demo(table: str) -> None:
    """CLI demo mode: fetch a table's live schema and validate a good and a
    fabricated-column sample query against it, printing the results."""
    print(f"Fetching live schema for {table} ...")
    schema = await fetch_table_schema(table)
    if not schema:
        print("  (no schema fetched — network/doc issue)")
        return
    print(f"  {len(schema)} columns fetched, e.g. {', '.join(list(schema)[:8])} ...\n")
    for label, q in (("GOOD query", _DEMO_GOOD), ("FABRICATED-column query", _DEMO_FABRICATED)):
        res = validate_against_schema(q, schema, table)
        print(f"{label}: {'VALID ✓' if res.valid else 'INVALID ✗'}")
        for e in res.errors:
            print(f"    error:   {e}")
        for w in res.warnings:
            print(f"    warning: {w}")
        print()


async def _compare(strict: bool = False) -> int:
    """CLI compare mode: print a per-table table of live-vs-hardcoded schema
    counts and the phantom columns schemas.py lists that the live docs don't.
    Returns the total phantom-column count. In `strict` mode the process exits
    non-zero when any phantom exists — for a scheduled drift-check CI job, so a
    hardcoded schema that has drifted out of the live docs fails loudly instead of
    rotting silently. A table whose live fetch returned nothing (count 0) is skipped
    from the phantom tally to avoid false alarms on a transient fetch failure."""
    print("Live docs schema vs. hardcoded schemas.py (the curated set)\n")
    print(f"{'table':<34} {'hard':>5} {'live':>5} {'agree':>6}  phantom (in schemas.py, not live)")
    rows = await compare_to_hardcoded()
    total_phantom = 0
    for r in rows:
        phantom = ", ".join(r["hardcoded_only"]) or "—"
        if r["live"]:  # only count drift when the live schema actually fetched
            total_phantom += len(r["hardcoded_only"])
        print(f"{r['table']:<34} {r['hardcoded']:>5} {r['live']:>5} {r['agree']:>6}  {phantom}")
    print(f"\nTotal phantom columns (hardcoded but not in live docs): {total_phantom}")
    if strict and total_phantom:
        print(
            "\nDRIFT DETECTED: hardcoded schemas.py lists columns the live docs no "
            "longer have. Update schemas.py.",
            file=sys.stderr,
        )
    return total_phantom


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "compare":
        phantom = asyncio.run(_compare(strict="--strict" in args))
        sys.exit(1 if ("--strict" in args and phantom) else 0)
    else:
        asyncio.run(_demo(args[0] if args else "CDBDataPlaneRequests"))
