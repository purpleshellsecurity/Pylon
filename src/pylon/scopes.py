"""The scopes above and beside a resource.

Azure's telemetry does not all hang off resources. Identity lives at the
tenant, control-plane writes at the subscription, and whether the SIEM can
receive any of it is a property of Sentinel itself. Each is read by a
different API and enabled by a different action, so each is measured here and
tagged with the scope it belongs to, rather than being forced into a resource
row where its fields would be meaningless.

Every probe returns the same shape a resource verdict has -- scope,
logging_status, basis -- so one renderer can read all of them.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from . import apiversions
from . import azcli

# A connector reporting Success hours ago is not healthy now. Health events
# arrive continuously, so silence past this threshold is a failure the status
# field does not report -- it keeps saying Success and simply stops updating.
STALE_AFTER = timedelta(hours=12)


def _az(*args) -> tuple[int, str, str]:
    p = azcli.run([*args, "-o", "json"], timeout=azcli.CONTROL_TIMEOUT)
    return p.returncode, p.stdout, (p.stderr or "").strip()


def _classify(enabled: list[str], groups: list[str], available: list[str],
              elsewhere: list[str], noun: str) -> tuple[str, str]:
    """The same three states used at every scope.

    `allLogs` is resolved rather than counted: it is defined as every category
    the scope emits, so a setting carrying it is complete by definition. Any
    other group cannot be resolved -- Azure does not publish group membership
    at these scopes -- and is reported as partial with the group named, rather
    than silently credited or silently ignored.
    """
    if "allLogs" in groups:
        return "fully-enabled", "the allLogs category group reaches the target workspace"
    if enabled and available and set(enabled) >= set(available):
        return "fully-enabled", f"all {len(available)} {noun} reach the target workspace"
    if enabled:
        missing = sorted(set(available) - set(enabled))
        return "partial-enabled", ("not enabled: " + ", ".join(missing[:6])
                                   + (f" (+{len(missing)-6} more)" if len(missing) > 6 else ""))
    if groups:
        return "partial-enabled", (f"enabled by category group {', '.join(groups)}; "
                                   "membership is not published at this scope")
    if elsewhere:
        # Configured, and going somewhere the target cannot query. A different
        # fix from "never configured": add a destination, do not create one.
        return "not-enabled", f"configured but ships to {', '.join(elsewhere)}, not the target"
    return "not-enabled", "no diagnostic setting reaches the target workspace"


def _from_settings(payload: list, workspace_id: str) -> tuple[list, list, list, list]:
    """(enabled categories, enabled groups, available categories, elsewhere).

    A setting may name categories explicitly OR carry a category group, and
    reading only the first silently scores a group-enabled scope as empty --
    which is how a fully-forwarded Activity Log was reported as not-enabled.
    """
    enabled, groups, available, elsewhere = set(), set(), set(), set()
    for s in payload:
        props = s.get("properties", s)
        ws = props.get("workspaceId") or ""
        on_target = ws.lower() == workspace_id.lower()

        cats, grps = set(), set()
        for entry in props.get("logs") or []:
            if entry.get("category"):
                available.add(entry["category"])
            if not entry.get("enabled"):
                continue
            if entry.get("category"):
                cats.add(entry["category"])
            elif entry.get("categoryGroup"):
                grps.add(entry["categoryGroup"])

        if on_target:
            enabled |= cats
            groups |= grps
        elif cats or grps:
            elsewhere.add(ws.split("/")[-1] if ws else "a non-workspace destination")
    return sorted(enabled), sorted(groups), sorted(available), sorted(elsewhere)


def tenant(workspace_id: str) -> dict:
    """Entra ID: who signed in. Tenant-scoped, read through microsoft.aadiam."""
    rc, out, err = _az("rest", "--method", "get", "--url",
                       "https://management.azure.com/providers/microsoft.aadiam/"
                       f"diagnosticSettings?api-version={apiversions.AADIAM}")
    row = {"resource_id": "/providers/microsoft.aadiam/diagnosticSettings",
           "resource_type": "microsoft.aadiam/tenant", "scope": "tenant"}
    if rc != 0:
        return {**row, "assessment_status": "not_assessed", "logging_status": None,
                "basis": f"could not read Entra diagnostic settings: {err[:160]}"}
    settings = json.loads(out).get("value", [])
    enabled, groups, available, elsewhere = _from_settings(settings, workspace_id)
    status, basis = _classify(enabled, groups, available, elsewhere, "Entra log categories")
    return {**row, "assessment_status": "assessed", "logging_status": status,
            "basis": basis, "enabled": enabled, "groups": groups,
            "available": available, "elsewhere": elsewhere}


def subscription(subscription_id: str, workspace_id: str) -> dict:
    """Activity Log: who changed Azure. Subscription-scoped, not a resource."""
    # REST rather than `az monitor diagnostic-settings subscription list`: the
    # CLI returned one of this subscription's five settings, and the one it
    # dropped was the one forwarding the Activity Log to the target.
    rc, out, err = _az("rest", "--method", "get", "--url",
                       f"https://management.azure.com/subscriptions/{subscription_id}"
                       "/providers/microsoft.insights/diagnosticSettings"
                       f"?api-version={apiversions.MONITOR_DIAGNOSTIC_SETTINGS}")
    row = {"resource_id": f"/subscriptions/{subscription_id}",
           "resource_type": "microsoft.resources/subscriptions",
           "scope": "subscription", "subscription": subscription_id}
    if rc != 0:
        return {**row, "assessment_status": "not_assessed", "logging_status": None,
                "basis": f"could not read subscription diagnostic settings: {err[:160]}"}
    payload = json.loads(out or "[]")
    settings = payload.get("value", payload) if isinstance(payload, dict) else payload
    enabled, groups, available, elsewhere = _from_settings(settings, workspace_id)
    status, basis = _classify(enabled, groups, available, elsewhere, "Activity Log categories")
    return {**row, "assessment_status": "assessed", "logging_status": status,
            "basis": basis, "enabled": enabled, "groups": groups,
            "available": available, "elsewhere": elsewhere,
            "settings_seen": len(settings)}


def sentinel_monitoring(workspace_arm_id: str, health: dict) -> list[dict]:
    """Sentinel's own health and audit monitoring, as sentinel-scope rows.

    These replaced a list of data connectors, which was the wrong thing to
    show. That list came from the dataConnectors API, which returns only
    connectors created as ARM resources -- it reported two while a third,
    Defender XDR, was streaming into the same workspace unseen. A count that
    is wrong in a direction the reader cannot detect is worse than no count.

    What belongs at this scope is whether Sentinel is watching ITSELF:

      SentinelHealth  is any connector or rule failing, and would you know
      SentinelAudit   is there a record of who changed a rule or a connector

    Both are switched on in Sentinel's settings and both are measured the only
    way they can be -- by whether their table has anything in it. The union of
    connectors each source can see is reported as detail rather than as a
    count, since neither source is complete.
    """
    def age_of(value):
        """How long since this timestamp, or None if unparseable."""
        text = str(value or "")[:19]
        if not text:
            return None
        try:
            seen = datetime.fromisoformat(text).replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        return datetime.now(timezone.utc) - seen

    def is_stale(value) -> bool:
        age = age_of(value)
        return age is not None and age > STALE_AFTER

    def stamp(value) -> str:
        """A timestamp trimmed to the minute, or empty."""
        return f", last event {str(value)[:16].replace('T', ' ')}" if value else ""

    base = f"{workspace_arm_id}/providers/Microsoft.SecurityInsights"
    on = bool(health.get("enabled"))
    seen = health.get("connectors") or {}
    connectors = sorted(seen)
    # Each connector carries its OWN last event. One aggregate timestamp is
    # the newest across all of them, which says nothing about the others: a
    # connector that stopped reporting a week ago is hidden behind whichever
    # one reported most recently.
    def well(name: str) -> bool:
        statuses = seen[name].get("statuses") or {}
        return (all(st in ("Success", "Informational") for st in statuses)
                and not is_stale(seen[name].get("newest")))

    unhealthy = [n for n in connectors if not well(n)]
    per_connector = " · ".join(
        f"{name}{stamp(seen[name].get('newest')).replace(', last event', '')}"
        for name in connectors)
    rows = [{
        "resource_id": f"{base}/settings/SentinelHealth",
        "resource_type": "microsoft.securityinsights/settings/health",
        "scope": "sentinel", "assessment_status": "assessed",
        "logging_status": ("fully-enabled" if on and not unhealthy
                           else "partial-enabled" if on else "not-enabled"),
        "basis": ((f"{len(connectors) - len(unhealthy)} of {len(connectors)} "
                   f"connector(s) healthy: {per_connector}") if on else
                  "SentinelHealth holds no rows, so health monitoring is off "
                  "and a failing connector or rule would not surface here"),
        "connectors_seen": connectors,
        # Structured as well as prose, so a renderer can lay each connector
        # out on its own line without parsing the basis string.
        # Whether each connector is HEALTHY, not merely that it reports.
        # Anything outside Success/Informational is a failure the row must
        # name rather than average away into "reporting".
        "connectors_detail": [
            {"name": n,
             "newest": seen[n].get("newest"),
             "statuses": sorted(seen[n].get("statuses") or {}),
             "stale": is_stale(seen[n].get("newest")),
             "healthy": well(n)}
            for n in connectors],
    }]
    audit_on = bool(health.get("audit_enabled"))
    days = health.get("days", 30)
    rows.append({
        "resource_id": f"{base}/settings/SentinelAudit",
        "resource_type": "microsoft.securityinsights/settings/audit",
        "scope": "sentinel", "assessment_status": "assessed",
        "logging_status": "fully-enabled" if audit_on else "not-enabled",
        # Stated as an observation over the window, not as a claim that the
        # feature is off: an empty table and a feature switched on moments ago
        # look identical from here.
        "basis": (f"{health.get('audit_rows', 0)} audit event(s) in the past "
                  f"{days} days{stamp(health.get('audit_newest'))}" if audit_on else
                  f"no audit events observed in the past {days} days"),
    })
    return rows


def xdr_families(workspace_arm_id: str, endpoint_detail: dict) -> list[dict]:
    """Defender XDR families as sentinel-scope rows.

    A family with tables arriving is measured. A family with NOTHING is
    `not_assessed` and carries no logging_status, because this scan cannot
    tell an unlicensed product from a licensed one that was never connected.
    Marking those `not-enabled` would assert a gap on no evidence -- the
    difference the assessment_status field exists to keep.
    """
    fams = (endpoint_detail or {}).get("families") or {}
    streams = (endpoint_detail or {}).get("streams") or {}
    base = f"{workspace_arm_id}/providers/Microsoft.SecurityInsights/xdrFamilies"
    rows = []
    for family, split in fams.items():
        present, absent = split.get("present") or [], split.get("absent") or []
        row = {
            "resource_id": f"{base}/{family.replace(' ', '')}",
            "resource_type": f"microsoft.securityinsights/xdrfamilies/"
                             f"{family.replace(' ', '').lower()}",
            "scope": "sentinel", "family": family,
            "tables_present": present, "tables_absent": absent,
        }
        if not present:
            rows.append({**row, "assessment_status": "not_assessed",
                         "logging_status": None,
                         "basis": (f"no data in any of {len(absent)} {family} table(s); "
                                   "an unlicensed Defender product and one that was "
                                   "never connected are indistinguishable from here")})
            continue
        fresh = any(streams.get(t, {}).get("rows_24h") for t in present)
        if absent:
            status = "partial-enabled"
            basis = (f"{len(present)} of {len(present) + len(absent)} tables have data; "
                     f"none in: {', '.join(absent[:4])}")
        elif not fresh:
            status = "partial-enabled"
            newest = max((streams[t].get("latest") or "") for t in present)
            basis = (f"all {len(present)} tables have data but none in the last 24h; "
                     f"latest {str(newest)[:16].replace('T', ' ')}")
        else:
            status = "fully-enabled"
            basis = f"all {len(present)} tables have data within 24h"
        rows.append({**row, "assessment_status": "assessed",
                     "logging_status": status, "basis": basis})
    return rows


def defender_plans(subscription_id: str) -> dict:
    """Defender for Cloud plans -- CONTEXT, deliberately not rows.

    A plan on the Free tier means nothing is watching. That is not a log going
    missing, and giving it a `logging_status` would file "no EDR licence"
    beside "no diagnostic setting" in one column. The model has a
    `reads.defender_plans` entry and no section for them, which is the same
    judgement: read it, report it, do not pretend it is telemetry.
    """
    rc, out, err = _az("security", "pricing", "list", "--subscription", subscription_id)
    if rc != 0:
        return {"ran": False, "detail": f"could not read Defender plans: {err[:160]}",
                "on": [], "off": []}
    plans = json.loads(out).get("value", [])
    on = sorted(p["name"] for p in plans if p.get("pricingTier") == "Standard")
    off = sorted(p["name"] for p in plans if p.get("pricingTier") != "Standard")
    # The raw objects are carried too: `pricingTier` alone does not separate a
    # plan someone paid for from the free baseline, and it hides an unused
    # free trial entirely.
    return {"ran": True, "on": on, "off": off, "plans": plans,
            "detail": (f"{len(on)} of {len(plans)} plans on the Standard tier; "
                       f"off: {', '.join(off) if off else 'none'}")}
