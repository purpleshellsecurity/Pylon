"""What the workspace already detects.

The rules leg answers the other half of a coverage question: `resources` says
what telemetry arrives, this says what is watching it. A gap is only a gap
where both are known -- a table with data and no rule reading it, or a rule
reading a table nothing fills.

`rule_health_status` is deliberately left null here. Whether a rule FIRES can
only be established by running it, which costs query time and is its own leg;
inferring "never fires" from a rule this leg merely listed would be an
accusation nothing measured.
"""

from __future__ import annotations

import json
import re

from . import apiversions
from . import azcli
from .text import plural

API = apiversions.SENTINEL

# KQL identifiers that are never tables. `let` bindings are stripped
# separately; these are operators and functions that survive tokenising.
_NOT_TABLES = frozenset({
    "let", "where", "project", "summarize", "extend", "join", "union", "on",
    "by", "and", "or", "not", "in", "has", "contains", "startswith", "ago",
    "now", "datetime", "timespan", "dynamic", "todynamic", "tostring", "toint",
    "count", "dcount", "make_set", "make_list", "arg_max", "arg_min", "bin",
    "case", "iff", "isnotempty", "isempty", "parse_json", "mv_expand", "top",
    "order", "sort", "desc", "asc", "distinct", "range", "print", "materialize",
    "kind", "leftouter", "innerunique", "inner", "hint", "true", "false",
})


def _az_json(url: str) -> dict | None:
    p = azcli.run(["rest", "--method", "get", "--url", url, "-o", "json"],
                  timeout=azcli.CONTROL_TIMEOUT)
    return json.loads(p.stdout) if p.returncode == 0 else None


def workspace_tables(workspace_arm_id: str) -> set[str]:
    """Every table defined on the workspace, whether or not it holds data.

    Used to decide which identifiers in a rule's KQL are tables. Taken from
    the workspace rather than a static list so a custom table (`*_CL`) is
    recognised too.
    """
    payload = _az_json(f"https://management.azure.com{workspace_arm_id}/tables"
                       f"?api-version={apiversions.LOG_ANALYTICS}")
    if not payload:
        return set()
    return {t["name"] for t in payload.get("value", [])}


def tables_in(query: str, known: set[str]) -> list[str]:
    """Tables a KQL query reads.

    Matched against the workspace's own table list rather than parsed
    structurally: a real KQL parser is the correct answer and this is not one,
    so it errs toward naming only identifiers that are definitely tables.
    """
    bound = set(re.findall(r"\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", query))
    found = set()
    for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", query):
        if token in bound or token in _NOT_TABLES:
            continue
        if token in known:
            found.add(token)
    return sorted(found)


def probe(workspace_arm_id: str) -> tuple[list[dict], dict]:
    """(rule rows, read state). Paging is followed, never truncated silently."""
    url = (f"https://management.azure.com{workspace_arm_id}/providers/"
           f"Microsoft.SecurityInsights/alertRules?api-version={API}")
    raw, pages = [], 0
    while url:
        payload = _az_json(url)
        if payload is None:
            return [], {"ran": False,
                        "detail": ("could not read alert rules after "
                                   f"{plural(pages, 'page')}")}
        raw.extend(payload.get("value", []))
        url = payload.get("nextLink")
        pages += 1

    known = workspace_tables(workspace_arm_id)
    rows = []
    for r in raw:
        props = r.get("properties") or {}
        query = props.get("query") or ""
        techniques = props.get("techniques") or []
        # The rule states its own technique. That is the strongest basis
        # available short of a label, and it is not an inference.
        basis = "rule-metadata" if techniques else ("kql-operation" if query else "none")
        rows.append({
            "rule_id": r.get("name"),
            "name": props.get("displayName") or r.get("name") or "",
            "rule_severity": props.get("severity"),
            "rule_health_status": None,
            "health_detail": (None if props.get("enabled")
                              else "rule is disabled in the workspace"),
            "technique_mapping_confidence": basis,
            "techniques": sorted(techniques),
            "tables_referenced": tables_in(query, known) if query else [],
            "_kind": r.get("kind"),
            "_template": props.get("alertRuleTemplateName"),
            "_query": query,
            "_enabled": bool(props.get("enabled")),
            "_techniques": techniques,
            "_tactics": props.get("tactics") or [],
            # Sentinel renames a rule it disables itself, prepending
            # "AUTO DISABLED" and writing the reason into the description.
            # That rename is the reliable signal, and it is here in the rule
            # itself -- no health monitoring required, which matters because
            # health monitoring is off by default.
            #
            # It is NOT the same as a rule someone switched off on purpose:
            # `_enabled` is False for both, and only the rename separates them.
            "_auto_disabled": (props.get("displayName") or "").upper().startswith(
                "AUTO DISABLED"),
            "_description": (props.get("description") or "")[:400],
        })
    return rows, {"ran": True,
                  "detail": f"{len(rows)} rule(s) read across {pages} page(s); "
                            f"{sum(x['_enabled'] for x in rows)} enabled"}
