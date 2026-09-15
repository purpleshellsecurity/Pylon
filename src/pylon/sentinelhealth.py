"""Connector and rule health, read from SentinelHealth rather than the API.

The dataConnectors API returns the connectors someone created as ARM
resources. It is not the whole set: Defender XDR streams into this workspace
through a connection that API never lists, which is why the scan's blind-spot
list named it. SentinelHealth sees it -- 694 success events for
MicrosoftThreatProtection, newest today, against zero rows in the API.

So neither source is complete and the scan reads both:

    dataConnectors API   what was configured as a resource
    SentinelHealth       what is actually running and reporting health

A connector present in one and absent from the other is not a contradiction,
it is each source's blind spot showing. The union is closer to the truth than
either, and where they disagree the report says which source saw it.

SentinelHealth is itself optional -- it is switched on in Sentinel's health and
audit settings. Absent rows mean the feature is off, NOT that nothing is
healthy, and the two must not read alike.
"""

from __future__ import annotations

import json

from . import azcli


def _query(workspace_guid: str, kql: str) -> tuple[list[dict], str | None]:
    p = azcli.query(workspace_guid, kql)
    if p.returncode != 0:
        return [], (p.stderr or "").strip()[:200]
    return json.loads(p.stdout or "[]"), None


def probe(workspace_guid: str, days: int = 30) -> tuple[dict, dict]:
    """(health detail, read state)."""
    # Read through `_SentinelHealth()` rather than the SentinelHealth table.
    # Microsoft asks for this explicitly -- the function absorbs schema changes
    # so a query written today keeps working -- and every sample query in the
    # documentation is written against it.
    #
    # SentinelResourceType is compared case-insensitively everywhere below.
    # Microsoft's own documentation disagrees with itself: the schema reference
    # gives the value as `Analytics rule` and every sample query on the
    # monitoring page uses `Analytics Rule`. KQL `==` is case-sensitive, so
    # picking either means the rule half of this read silently returns nothing
    # the day the other spelling turns out to be the real one. The audit table
    # is worse again -- there the value is `Analytic Rule`, no `s`.
    rows, err = _query(workspace_guid, (
        f"_SentinelHealth() | where TimeGenerated > ago({days}d) "
        "| summarize events=count(), newest=max(TimeGenerated) "
        "by SentinelResourceType, SentinelResourceName, SentinelResourceKind, Status"))
    if err:
        return {}, {"ran": False,
                    "detail": f"SentinelHealth unreadable: {err}"}
    if not rows:
        return {"enabled": False, "days": days}, {
            "ran": False,
            "detail": "SentinelHealth holds no rows, so health monitoring is "
                      "off in Sentinel's settings. That is not the same claim "
                      "as nothing being healthy."}

    # Health monitoring covers only the connectors Microsoft supports it for,
    # so a connector absent here is not necessarily unhealthy or absent -- it
    # may simply not report health. MCAS is configured in this tenant and
    # emits nothing to SentinelHealth.
    connectors: dict[str, dict] = {}
    rule_events: dict[str, int] = {}
    for r in rows:
        # Keyed by the connector INSTANCE, not its kind. Office 365 reports
        # health separately for Exchange, SharePoint and Teams, and grouping
        # by kind collapsed three connectors into one.
        kind = (r.get("SentinelResourceName")
                or r.get("SentinelResourceKind") or "(unnamed)")
        status = r.get("Status") or "Unknown"
        events, newest = int(r["events"]), r["newest"]
        rtype = (r.get("SentinelResourceType") or "").lower()
        if rtype == "data connector":
            slot = connectors.setdefault(
                kind, {"events": 0, "newest": "", "statuses": {}})
            slot["events"] += events
            slot["newest"] = max(slot["newest"], newest)
            slot["statuses"][status] = slot["statuses"].get(status, 0) + events
            slot["kind"] = r.get("SentinelResourceKind") or ""
        elif rtype == "analytics rule":
            rule_events[status] = rule_events.get(status, 0) + events

    # Why rules failed, and which Sentinel switched off. `rule_events` above
    # counts Success against Failure and stops there, which says a rule is
    # failing without saying what to do about it. `Reason` is the field that
    # separates "a table referenced in the query wasn't found" -- a connector
    # problem -- from "the query execution timed out", which is a rule to tune.
    failures, _fail_err = _query(workspace_guid, (
        f"_SentinelHealth() | where TimeGenerated > ago({days}d) "
        "| where SentinelResourceType =~ 'analytics rule' "
        "| where Status != 'Success' "
        "| summarize runs=count(), rules=dcount(SentinelResourceId) by Reason "
        "| order by runs desc"))
    rule_failures = [
        {"reason": r.get("Reason") or "(no reason given)",
         "runs": int(r.get("runs") or 0), "rules": int(r.get("rules") or 0)}
        for r in (failures or [])]

    # There was a query here matching a SentinelHealth `Reason` of "The
    # analytics rule is disabled and was not executed", taken from Microsoft's
    # sample for finding auto-disabled rules. It is gone.
    #
    # That sentence fires for ANY disabled rule. A rule an analyst switched off
    # on purpose produced the same words as one Sentinel killed after repeated
    # failures, and the report said Sentinel had done it. What Sentinel
    # actually does is documented and unambiguous: it prepends "AUTO DISABLED"
    # to the rule's name and writes the reason into the description. That is
    # read from the rule itself in `rules.py`, needs no health monitoring, and
    # therefore works on the many tenants that have it switched off.

    # Two findings the failure count above cannot make, because both live in
    # runs Sentinel calls SUCCESSFUL.
    #
    #   TUNING       the query matched rows and the rule still fired nothing,
    #                because the row count never crossed TriggerThreshold.
    #                `QueryResultAmount` is what the query returned and
    #                `AlertsGeneratedAmount` is what it raised; matched > 0
    #                with alerts == 0 is a threshold set too high, and it is
    #                NOT the same as the scan's own "never fires" label, which
    #                only means the query returned nothing when Pylon ran it.
    #
    #   ENTITIES     `EntitiesDroppedDueToMappingIssuesAmount` above zero
    #                means the alert fired and arrived with no user or host
    #                attached. Nothing looks broken; the incident just cannot
    #                be pivoted on.
    #
    # Both fields are null on a run that did not report them, and `toint(null)`
    # keeps the row out of the comparison rather than reading it as zero. That
    # is the safe direction: a missing field produces no finding.
    tuning, tune_err = _query(workspace_guid, (
        f"_SentinelHealth() | where TimeGenerated > ago({days}d) "
        "| where SentinelResourceType =~ 'analytics rule' "
        "| extend p = todynamic(ExtendedProperties) "
        "| summarize runs=count(), ok=countif(Status == 'Success'), "
        "alerts=sum(toint(p.AlertsGeneratedAmount)), "
        "matched=sum(toint(p.QueryResultAmount)), "
        "dropped=sum(toint(p.EntitiesDroppedDueToMappingIssuesAmount)), "
        "threshold=max(toint(p.TriggerThreshold)), "
        "op=max(tostring(p.TriggerOperator)) "
        "by rule=SentinelResourceName "
        "| where (ok > 0 and alerts == 0 and matched > 0) or dropped > 0 "
        "| order by matched desc"))
    below_threshold, entity_drops = [], []
    for r in (tuning or []):
        row = {"rule": r.get("rule") or "(unnamed)",
               "runs": int(r.get("runs") or 0),
               "matched": int(r.get("matched") or 0),
               "dropped": int(r.get("dropped") or 0),
               "threshold": r.get("threshold"),
               "operator": r.get("op") or ""}
        if row["dropped"] > 0:
            entity_drops.append(row)
        if int(r.get("ok") or 0) > 0 and not int(r.get("alerts") or 0) \
                and row["matched"] > 0:
            below_threshold.append(row)

    # A scheduled rule that fails is retried five more times on the SAME
    # window, so one failure is a delay, not a miss. Six failures on one
    # window is the window going unwatched -- the rule never looked at that
    # slice of time and never will. That is a different and much worse finding
    # than a failure count, and it is the only one here that names data nobody
    # detected on.
    #
    # Microsoft's sample tests `== 6`; this tests `>= 6` so a duplicated health
    # record cannot hide a window that really was skipped.
    skipped, skip_err = _query(workspace_guid, (
        f"_SentinelHealth() | where TimeGenerated > ago({days}d) "
        "| where SentinelResourceType =~ 'analytics rule' "
        "| where SentinelResourceKind =~ 'scheduled' "
        "| where Status != 'Success' "
        "| extend start = tostring(todynamic(ExtendedProperties).QueryStartTimeUTC) "
        "| summarize failures=count() by start, rule=SentinelResourceName "
        "| where failures >= 6 "
        "| summarize windows=count() by rule "
        "| order by windows desc"))
    skipped_windows = [{"rule": r.get("rule") or "(unnamed)",
                        "windows": int(r.get("windows") or 0)}
                       for r in (skipped or [])]

    # Per rule, not just per status. `rule_events` above counts Success against
    # Failure across the whole workspace, which can only ever produce a finding
    # when something is wrong. A tenant where nothing is wrong gets silence from
    # every block on this page, exactly when it wants the opposite.
    #
    # Per-rule counts answer the question the rest of the report cannot: the
    # coverage half says whether a rule CAN fire, this says whether it IS
    # running, and the gap between them is where the useful finding lives. On
    # the tenant this was written against, eight rules reading a table with no
    # data had run 69,138 times and reported success every time -- 41% of all
    # rule execution. Health monitoring calls that healthy, because the query
    # ran. It is not.
    #
    # A rule absent here is not necessarily broken. Fusion has no KQL of its
    # own and writes no execution records at all, so the caller compares this
    # against the deployed rules rather than treating an absence as a fault.
    per_rule, per_rule_err = _query(workspace_guid, (
        f"_SentinelHealth() | where TimeGenerated > ago({days}d) "
        "| where SentinelResourceType =~ 'analytics rule' "
        "| summarize runs=count(), newest=max(TimeGenerated), "
        "failed=countif(Status != 'Success') "
        "by rule=SentinelResourceName "
        "| order by runs desc"))
    rule_runs = [{"rule": r.get("rule") or "(unnamed)",
                  "runs": int(r.get("runs") or 0),
                  "failed": int(r.get("failed") or 0),
                  "newest": r.get("newest") or None}
                 for r in (per_rule or [])]

    # Sentinel's own audit trail is a separate switch from health.
    audit, audit_err = _query(workspace_guid, (
        f"_SentinelAudit() | where TimeGenerated > ago({days}d) "
        "| summarize n=count(), newest=max(TimeGenerated)"))
    audit_rows, audit_newest = 0, None
    if not audit_err and audit:
        try:
            audit_rows = int(audit[0].get("n", 0))
            audit_newest = audit[0].get("newest") or None
        except (TypeError, ValueError, KeyError):
            audit_rows, audit_newest = 0, None

    detail = {
        "enabled": True,
        "days": days,
        "connectors": connectors,
        "rule_events": rule_events,
        "audit_enabled": audit_rows > 0,
        "audit_rows": audit_rows,
        "audit_newest": audit_newest,
        "rule_failures": rule_failures,
        "rule_runs": rule_runs,
        # Separate from an empty `rule_runs`, which would mean no rule ran.
        "rule_runs_read": per_rule_err is None,
        "below_threshold": below_threshold,
        "entity_drops": entity_drops,
        "skipped_windows": skipped_windows,
        # Which of the three extra reads actually ran. A query that errored
        # must not render as "nothing found" -- that is the one confusion this
        # whole scan exists to avoid.
        "tuning_read": tune_err is None,
        "skipped_read": skip_err is None,
        # The most recent health event of any kind, so "on" can be stated with
        # the moment it was last true rather than as a bare claim.
        "newest": max((v["newest"] for v in connectors.values()), default=None),
    }
    failing = sorted(k for k, v in connectors.items()
                     if any(s not in ("Success", "Informational")
                            for s in v["statuses"]))
    bits = [f"health monitoring on; {len(connectors)} connector(s) reporting: "
            + ", ".join(sorted(connectors))]
    if failing:
        bits.append("not healthy: " + ", ".join(failing))
    if rule_failures:
        bits.append(f"{sum(f['runs'] for f in rule_failures)} failed rule run(s) "
                    f"across {len(rule_failures)} reason(s)")
    if below_threshold:
        bits.append(f"{len(below_threshold)} rule(s) matched rows but never "
                    "crossed their alert threshold")
    if entity_drops:
        bits.append(f"{len(entity_drops)} rule(s) dropped entities on mapping")
    if skipped_windows:
        bits.append(f"{sum(s_['windows'] for s_ in skipped_windows)} skipped "
                    f"detection window(s) across {len(skipped_windows)} rule(s)")
    bits.append("SentinelAudit is on" if audit_rows else
                "SentinelAudit is OFF, so changes to rules and connectors "
                "leave no trail in this workspace")
    return detail, {"ran": True, "detail": "; ".join(bits)}
