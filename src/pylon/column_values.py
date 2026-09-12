"""Documented value sets for table columns, harvested from the reference pages.

A wrong column NAME errors and gets noticed. A wrong column VALUE parses,
validates, executes and matches nothing, so the rule is silently dead — the
failure this repo has already paid for twice, as `identity_s` vs `Identity` and
as `ActivityStatusValue in ("Succeeded")` against a tenant writing `Success`.

The catalog is written by `scripts/audit-table-schemas.py --emit-values` from
the same pages the schema audit already reads. Two kinds of set live in it and
the difference is load-bearing:

  exhaustive   the page says "Possible values:" — a closed set, so a literal
               outside it is a defect and `validate_kql` says so.
  illustrative the page says "for example" — NOT closed, and enforcing one
               would reject correct queries. Measured 2026-08-28: the pages
               list RemoteIPType as "for example Public, Private, Reserved,
               Loopback, Teredo, FourToSixMapping, and Broadcast", and a live
               workspace returned `LinkLocal`. Illustrative sets ground the
               prompt and never reject anything.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_CATALOG = Path(__file__).resolve().parent / "catalog" / "column-values.json"


@lru_cache(maxsize=1)
def _catalog() -> dict[str, dict[str, dict]]:
    """The vendored catalog, or {} when it is absent.

    Absent is "could not find out", and it degrades to no grounding and no
    enforcement rather than to a claim — the direction the table-plan interlock
    also fails in.
    """
    try:
        return json.loads(_CATALOG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def value_sets(table: str) -> dict[str, dict]:
    """{column: {"values": [...], "exhaustive": bool, "type": str}} for `table`."""
    return _catalog().get(table, {})


def enforceable(table: str) -> dict[str, list[str]]:
    """{column: values} for the CLOSED sets only — the ones a check may reject on."""
    return {
        column: spec["values"]
        for column, spec in value_sets(table).items()
        if spec.get("exhaustive")
    }


def grounding_lines(table: str) -> list[str]:
    """Prompt-ready lines naming what each column's documented values are.

    An illustrative set is labelled as one. Telling the model a partial list is
    complete is how it learns to write a filter that excludes a real value.
    """
    lines: list[str] = []
    for column, spec in sorted(value_sets(table).items()):
        values = ", ".join(f'"{v}"' for v in spec["values"])
        if spec.get("exhaustive"):
            lines.append(f"{column} takes exactly these values: {values}")
        else:
            lines.append(
                f"{column} takes values such as {values} — documented as examples, "
                f"not a complete list, so do not write a filter that assumes it is"
            )
    return lines
