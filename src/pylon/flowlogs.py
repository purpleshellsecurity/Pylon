"""Flow logs: a telemetry path diagnostic settings cannot see.

A virtual network emits `VMProtectionAlerts` through a diagnostic setting AND
flow records through Network Watcher, and the two are configured, enumerated
and destined completely differently. A scan that reads only diagnostic settings
reports a flow-logged network as sending nothing.

Two properties of the mechanism drive everything here:

  * Flow logs are enumerated PER REGION off Network Watcher, never off the
    resource being logged. There is no "list the flow logs on this vnet".
  * The storage account is mandatory and Traffic Analytics is optional. A flow
    log with no Traffic Analytics is working correctly and still reaches no
    workspace, so no detection can query it. That is `ships elsewhere`, not
    `not-enabled`, and the difference is the whole point of reading it.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from . import azcli


def _regions_with_watchers() -> list[str]:
    p = azcli.run(
        ["graph", "query", "-q",
         "Resources | where type =~ 'microsoft.network/networkwatchers' "
         "| distinct location", "-o", "json"],
        timeout=azcli.CONTROL_TIMEOUT,
    )
    if p.returncode != 0:
        return []
    return sorted({r["location"] for r in json.loads(p.stdout).get("data", [])})


def _list_in(location: str) -> list[dict]:
    p = azcli.run(
        ["network", "watcher", "flow-log", "list", "--location", location,
         "-o", "json"],
        timeout=azcli.CONTROL_TIMEOUT,
    )
    if p.returncode != 0:
        return []
    return json.loads(p.stdout or "[]")


def probe() -> dict[str, dict]:
    """{lowercased target resource id: flow log state}.

    Keyed by TARGET rather than by flow log, because the question asked of it
    is always "is this resource covered".
    """
    regions = _regions_with_watchers()
    if not regions:
        return {}

    with ThreadPoolExecutor(max_workers=len(regions)) as pool:
        pages = list(pool.map(_list_in, regions))

    covered: dict[str, dict] = {}
    for page in pages:
        for fl in page:
            target = (fl.get("targetResourceId") or "").lower()
            if not target:
                continue
            ta = ((fl.get("flowAnalyticsConfiguration") or {})
                  .get("networkWatcherFlowAnalyticsConfiguration") or {})
            covered[target] = {
                "flow_log_name": fl.get("name"),
                "enabled": bool(fl.get("enabled")),
                "version": (fl.get("format") or {}).get("version"),
                "storage_id": fl.get("storageId"),
                # Only Traffic Analytics puts flow data in a workspace. Without
                # it the records exist, in blob storage, unqueryable by a rule.
                "traffic_analytics": bool(ta.get("enabled")),
                "workspace_id": ta.get("workspaceResourceId"),
            }
    return covered


def surface_for(resource_id: str, flow_logs: dict[str, dict],
                workspace_id: str) -> dict | None:
    """The flow-log leg of a resource, shaped like a diagnostic-settings surface.

    Returning the same shape lets the existing coverage arithmetic treat flow
    logs as one more surface a resource has, which is what makes a vnet with
    flow logs and no diagnostic setting come out `partial-enabled` rather than
    either extreme.
    """
    state = flow_logs.get(resource_id.lower())
    if state is None:
        return {"scope": f"{resource_id}/flowLogs", "readable": True,
                "can_emit": ["FlowLogs"], "groups": {},
                "settings": {"readable": True, "enabled": [], "groups": [],
                             "to_workspace": False, "elsewhere": [], "count": 0}}
    # Traffic Analytics is the only thing that puts flow data in a workspace,
    # and it must be THE workspace: flow records analysed into a different one
    # are as unreachable to the target SIEM as records left in blob storage.
    on = state["enabled"]
    reaches = (on and state["traffic_analytics"]
               and (state["workspace_id"] or "").lower() == workspace_id.lower())
    # Where it goes instead, when it does not reach the target. Without this
    # a flow log analysed into another workspace reads as "metrics only",
    # which is a different remediation from "point it here".
    elsewhere = []
    if on and not reaches:
        if state["traffic_analytics"] and state["workspace_id"]:
            elsewhere = ["workspace:" + state["workspace_id"].split("/")[-1]]
        elif state["storage_id"]:
            elsewhere = ["storage:" + state["storage_id"].split("/")[-1]
                         + " (no traffic analytics, so no workspace at all)"]
    return {"scope": state["flow_log_name"], "readable": True,
            "can_emit": ["FlowLogs"], "groups": {},
            "flow_log": state,
            "settings": {"readable": True,
                         "enabled": ["FlowLogs"] if on else [],
                         "groups": [],
                         "to_workspace": reaches,
                         "elsewhere": elsewhere,
                         "count": 1}}
