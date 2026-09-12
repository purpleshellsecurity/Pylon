"""Gaps, as rows a reader can act on.

Everything before this measured state. This turns state into instructions: a
resource, the table its logs would land in, and the exact categories to switch
on. A row is emitted per (surface, table) rather than per resource, because a
storage account can be covered on blobs and dark on files and one status per
account cannot say that.

`dark_reason` decides the remediation and is required for that reason. "Never
configured" means create a setting; "ships elsewhere" means add a destination
to one that already exists; "configured here -- idle in the window" is not a
gap at all and must never be counted with the others.

`gap_severity` stays None. It derives from `criticality_rank`, no resource in
this tenant carries a rankable tier, and a severity invented from a missing
tier looks exactly like a measured one.
"""

from __future__ import annotations

import json

from . import azcli
from . import tablemap


def _last_seen(workspace_guid: str, table: str, resource_id: str) -> float | None:
    """Days since this RESOURCE last wrote to this table, or None.

    Per resource, not per table: `StorageBlobLogs` holding rows says nothing
    about the nine storage accounts that are not filling it.

    The id must be the SURFACE's scope, not the row's. Storage stamps
    `_ResourceId` with the blob service (`.../storageaccounts/x/blobservices/
    default`), so matching on the account id finds nothing and reports a
    working configuration as idle.
    """
    query = (f"{table} | where _ResourceId =~ '{resource_id}' "
             "| summarize newest=max(TimeGenerated) "
             "| extend days = datetime_diff('minute', now(), newest) / 1440.0 "
             "| project days")
    p = azcli.query(workspace_guid, query)
    if p.returncode != 0:
        return None
    rows = json.loads(p.stdout or "[]")
    if not rows or rows[0].get("days") in (None, ""):
        return None
    try:
        return round(float(rows[0]["days"]), 2)
    except (TypeError, ValueError):
        return None


def _reason(settings: dict, reaching: bool) -> str:
    """Which of the five states this surface is in."""
    if not settings.get("readable", True):
        return "settings unreadable"
    if not settings.get("count"):
        return "no diagnostic setting"
    if reaching:
        # A setting reaches the target and the category is still off. This used
        # to return "never configured" too -- the same words as the case above,
        # for a different state with a different fix. One means "create a
        # diagnostic setting", the other means "tick a box on the one you have",
        # and a reader given the first sentence for the second situation goes
        # and builds something that already exists.
        #
        # Found when an audit script read the string the obvious way and
        # reported a false disagreement on the workspace itself.
        return "category not enabled"
    if settings.get("elsewhere"):
        return "ships elsewhere"
    # Settings exist, nothing is enabled and nothing ships anywhere -- the
    # shape a metrics-only setting leaves behind.
    return "metrics only, no log categories"


def build(verdicts: list[dict], live: dict[str, int],
          workspace_guid: str | None) -> tuple[list[dict], dict]:
    """(CoverageGap rows, read state)."""
    gaps, unmapped, idle_checked = [], set(), 0

    for row in verdicts:
        if row.get("assessment_status") != "assessed":
            continue
        for surface in row.get("surfaces", []):
            cats = surface.get("can_emit") or []
            if not cats:
                continue
            settings = surface.get("settings") or {}
            covered = set(settings.get("enabled") or [])
            for group in settings.get("groups") or []:
                covered |= set((surface.get("groups") or {}).get(group, []))
            missing = sorted(set(cats) - covered)
            reaching = bool(settings.get("to_workspace"))

            for category in surface.get("unmapped_categories") or []:
                unmapped.add(category)

            tables = surface.get("expected_tables") or []
            if not tables:
                continue

            # Which categories feed which table. A surface can fill several
            # tables, and the instruction on a row must be the categories that
            # fix THAT row -- telling someone to enable FunctionAppLogs to
            # populate AppServiceAuditLogs is noise that reads as fact.
            dedicated = bool(settings.get("dedicated"))
            per_table: dict[str, list[str]] = {}
            for category in cats:
                table, _ = tablemap.table_for(
                    surface.get("surface_type") or "", category, dedicated)
                if table:
                    per_table.setdefault(table, []).append(category)

            if not missing and reaching:
                # Configured and complete. The only remaining question is
                # whether anything actually arrived, which is a different
                # verdict from a gap and is labelled as such.
                for table in tables:
                    scope_id = (surface.get("log_scope")
                                or surface.get("scope") or row["resource_id"])
                    days = (_last_seen(workspace_guid, table, scope_id)
                            if workspace_guid and table in live else None)
                    idle_checked += 1
                    if days is None:
                        gaps.append({
                            "resource_id": row["resource_id"],
                            "expected_table": table, "is_logging": False,
                            "days_since_last_log": None,
                            "dark_reason": "configured here — idle in the window",
                            "categories_to_enable": [], "gap_severity": None,
                        })
                continue

            reason = _reason(settings, reaching)
            for table in tables:
                feeds = sorted(per_table.get(table, []))
                # Only what is BOTH missing and feeds this table. If every
                # category for the table is already on, the table is not a gap.
                to_enable = sorted(set(feeds) & set(missing)) if missing else feeds
                if missing and not to_enable:
                    continue
                gaps.append({
                    "resource_id": row["resource_id"],
                    "expected_table": table,
                    "is_logging": reaching and not missing,
                    "days_since_last_log": None,
                    "dark_reason": reason,
                    "categories_to_enable": to_enable,
                    "gap_severity": None,
                    # Whether the table NAME was read or assumed. Which table a
                    # category fills depends on `logAnalyticsDestinationType`
                    # on the diagnostic setting -- and a resource with no
                    # setting has none to read it from, which is exactly the
                    # resource every "here is what to enable" line is about.
                    # The name is the documented default and worth printing;
                    # it must not print in the same voice as a measurement.
                    "mode_basis": surface.get("mode_basis") or "assumed",
                })

    detail = f"{len(gaps)} gap(s) from {len(verdicts)} row(s)"
    if idle_checked:
        detail += f"; {idle_checked} covered surface(s) checked for idleness"
    if unmapped:
        # Named rather than dropped: a category with no known table is a hole
        # in the map, and silently omitting it would understate the gaps.
        detail += (f"; {len(unmapped)} category(ies) had no known table and were "
                   f"skipped: {', '.join(sorted(unmapped)[:8])}")
    return gaps, {"ran": True, "detail": detail}
