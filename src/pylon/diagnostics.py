"""What each resource CAN emit, and what is actually switched on.

The gap is the subtraction of the second from the first. The workspace is
deliberately never consulted: a resource that is dark writes no rows, so its
absence from a workspace is not evidence about the resource. Asking the
resource itself is the only read that can see a resource that is sending
nothing.

Storage is the reason `surfaces` exists. A storage account reports metrics and
no logs at its own scope, while its blob/file/queue/table services each carry
StorageRead/Write/Delete. Judging the account by its own scope alone marks the
most security-relevant logging in a tenant as impossible.
"""

from __future__ import annotations

import json
from functools import partial
from concurrent.futures import ThreadPoolExecutor

from . import apiversions
from . import azcli
from . import flowlogs
from . import tablemap

WORKERS = 10

# Categories that describe access to the DATA in a resource rather than the
# resource itself. Recorded as a property of the SURFACE, not as a separate
# row: a blob service is part of its storage account, not a different object
# the way a tenant or a subscription is. One row per resource keeps counts
# simple, and "is data access logged" stays answerable by filtering surfaces
# on `plane`. Recorded as a property of the SURFACE, not as a separate
# row: a blob service is part of its storage account, not a different object
# the way a tenant or a subscription is. Keeping it a surface means one row
# per resource -- so counts stay simple -- while "is data access logged" is
# still answerable by filtering surfaces on `plane`. A blob read and a secret fetch are the tenant's data being
# touched; a diagnostic setting being changed is the resource being managed.
# Azure keeps storage's on child services, which makes that split structural,
# but a key vault reports both on the vault -- so this map carries the
# judgement for the types where Azure does not. It is a judgement, and it
# needs review per type added.
DATA_PLANE_CATEGORIES: dict[str, frozenset[str]] = {
    "microsoft.keyvault/vaults": frozenset({"AuditEvent"}),
}

# Types that can be the target of a Network Watcher flow log. Restricted to
# virtual networks: a flow log may also target a subnet or a NIC, and coverage
# inherits NIC > subnet > vnet, but resolving that needs subnet membership this
# read does not fetch. A NIC inside a flow-logged vnet is therefore not credited
# here -- an understatement, which is the safe direction.
FLOW_LOG_TYPES = frozenset({"microsoft.network/virtualnetworks"})

# Types whose log categories live on child services rather than the resource.
SUBSERVICES = {
    "microsoft.storage/storageaccounts":
        ("blobServices", "fileServices", "queueServices", "tableServices"),
}


def _az(*args) -> tuple[int, str, str]:
    p = azcli.run([*args, "-o", "json"], timeout=azcli.CONTROL_TIMEOUT)
    return p.returncode, p.stdout, (p.stderr or "").strip()


def _categories(target_id: str) -> dict:
    """Log categories this scope can emit, and which groups contain them.

    Uses the REST API rather than `az monitor ... categories list`, because the
    CLI drops `categoryGroups` -- and without it a setting enabled by group is
    unresolvable, which previously forced a verdict of "unconfirmed" onto a
    resource that was in fact fully covered.
    """
    rc, out, err = _az("rest", "--method", "get", "--url",
                       f"https://management.azure.com{target_id}/providers/"
                       "microsoft.insights/diagnosticSettingsCategories"
                       f"?api-version={apiversions.MONITOR_DIAGNOSTIC_SETTINGS}")
    if rc != 0:
        low = err.lower()
        unsupported = ("resourcenotsupported" in low or "not supported" in low
                       or "does not support" in low or "notsupported" in low)
        # "The type has no diagnostic settings" IS an answer: nothing to enable.
        # Any other failure is an unknown, and an unknown must never read as
        # "nothing to enable" -- that is the difference this whole file exists
        # to keep.
        return {"readable": unsupported, "can_emit": [], "groups": {},
                "detail": err[:200]}

    can_emit, groups = [], {}
    for entry in json.loads(out).get("value", []):
        props = entry.get("properties", {})
        if props.get("categoryType") != "Logs":
            continue
        name = entry["name"]
        can_emit.append(name)
        for group in props.get("categoryGroups") or []:
            groups.setdefault(group, []).append(name)
    return {"readable": True, "can_emit": sorted(can_emit),
            "groups": {g: sorted(v) for g, v in groups.items()}}


def _settings(target_id: str, workspace_id: str) -> dict:
    """What is enabled at this scope AND ships to the target workspace.

    Destination is part of the measurement, not metadata about it. A category
    enabled on a setting that points at a different workspace is not coverage:
    no rule in the target can read it. Counting it would give a resource a
    green tick for data the SIEM never receives.
    """
    rc, out, err = _az("monitor", "diagnostic-settings", "list", "--resource", target_id)
    if rc != 0:
        return {"readable": False, "detail": err[:200], "enabled": [], "groups": [],
                "to_workspace": False, "elsewhere": [], "count": 0}
    payload = json.loads(out)
    settings = payload if isinstance(payload, list) else payload.get("value", [])

    enabled, groups, elsewhere = set(), set(), set()
    dedicated = False
    for entry_set in settings:
        props = entry_set.get("properties", entry_set)
        ws = props.get("workspaceId") or ""
        on_target = ws.lower() == workspace_id.lower()
        # Resource-specific mode changes which table the same category fills.
        # Only a setting pointing at the target can decide that.
        if on_target and props.get("logAnalyticsDestinationType") == "Dedicated":
            dedicated = True

        cats, grps = set(), set()
        for entry in props.get("logs") or []:
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
            # Enabled, and going somewhere the target SIEM cannot query. Kept
            # so the report can say "configured, but not to you" rather than
            # "never configured", which is a different remediation.
            if ws:
                elsewhere.add("workspace:" + ws.split("/")[-1])
            elif props.get("storageAccountId"):
                elsewhere.add("storage:" + props["storageAccountId"].split("/")[-1])
            elif props.get("eventHubName") or props.get("eventHubAuthorizationRuleId"):
                elsewhere.add("eventhub")
            else:
                elsewhere.add("unknown destination")

    return {"readable": True, "enabled": sorted(enabled), "groups": sorted(groups),
            "to_workspace": bool(enabled or groups), "elsewhere": sorted(elsewhere),
            "dedicated": dedicated, "count": len(settings)}


def _scopes(resource_id: str, resource_type: str) -> list[str]:
    children = SUBSERVICES.get(resource_type)
    if not children:
        return [resource_id]
    return [f"{resource_id}/{c}/default" for c in children]


def _dcr_map(vm_ids: list[str], workspace_id: str) -> dict[str, dict]:
    """Agent-based collection per VM.

    A virtual machine has no resource logs -- its diagnostic settings offer
    metrics only -- yet it is the richest security telemetry source in a
    tenant, reaching a workspace through the Azure Monitor Agent and a data
    collection rule. Reading only diagnostic settings marks every VM
    `out_of_scope`, which says "nothing to switch on" about the one resource
    type where the most is.
    """
    out: dict[str, dict] = {}

    def one(vm_id: str) -> tuple[str, dict]:
        rc, body, _ = _az("monitor", "data-collection", "rule", "association",
                          "list", "--resource", vm_id)
        if rc != 0:
            return vm_id, {"readable": False, "rules": []}
        payload = json.loads(body or "[]")
        items = payload if isinstance(payload, list) else payload.get("value", [])
        rules = []
        for a in items:
            rid = (a.get("properties", a) or {}).get("dataCollectionRuleId")
            if not rid:
                continue
            rc2, body2, _ = _az("monitor", "data-collection", "rule", "show", "--ids", rid)
            if rc2 != 0:
                continue
            props = (json.loads(body2).get("properties")
                     or json.loads(body2))
            streams = sorted({st for f in (props.get("dataFlows") or [])
                              for st in (f.get("streams") or [])})
            dests = [(w.get("workspaceResourceId") or "")
                     for v in (props.get("destinations") or {}).values()
                     if isinstance(v, list) for w in v]
            rules.append({"id": rid, "name": rid.split("/")[-1], "streams": streams,
                          "to_target": any(d.lower() == workspace_id.lower()
                                           for d in dests if d),
                          "destinations": sorted({d.split("/")[-1] for d in dests if d})})
        return vm_id, {"readable": True, "rules": rules}

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for vm_id, state in pool.map(one, vm_ids):
            out[vm_id] = state
    return out


def _agent_surface(rid: str, dcr: dict, os_type: str | None = None) -> dict:
    """The agent/DCR leg of a VM, shaped like any other surface.

    Carries `agent_tables`: which tables this machine's collection actually
    fills. The rule's own streams answer it where one exists; otherwise the
    operating system says what it WOULD fill. `AgentCollection` maps to `Event`
    in the pseudo-category table, and Event is Windows-only -- so a Linux VM
    was being told to enable collection into a table it can never write to.
    """
    state = dcr.get(rid) or {"readable": True, "rules": []}
    if not state["readable"]:
        return {"scope": f"{rid}/dataCollectionRuleAssociations", "readable": False,
                "can_emit": ["AgentCollection"], "groups": {},
                "agent_tables": tablemap.agent_table(None, os_type),
                "settings": {"readable": False, "enabled": [], "groups": [],
                             "to_workspace": False, "elsewhere": [], "count": 0}}
    reaching = [r for r in state["rules"] if r["to_target"]]
    elsewhere = sorted({d for r in state["rules"] if not r["to_target"]
                        for d in r["destinations"]})
    streams = sorted({st for r in state["rules"] if r["to_target"]
                      for st in (r.get("streams") or [])})
    return {"scope": f"{rid}/dataCollectionRuleAssociations", "readable": True,
            "can_emit": ["AgentCollection"], "groups": {},
            "agent_tables": tablemap.agent_table(streams, os_type),
            "dcr": state["rules"],
            "settings": {"readable": True,
                         "enabled": ["AgentCollection"] if reaching else [],
                         "groups": [], "to_workspace": bool(reaching),
                         "elsewhere": elsewhere, "count": len(state["rules"])}}


def _annotate_tables(surfaces: list[dict]) -> None:
    """Record, per surface, which tables its categories land in.

    Done per surface rather than per row because a storage account's blob and
    file services fill different tables, and the mode that decides a table is
    a property of the setting on that scope.
    """
    for s_ in surfaces:
        # A surface that already knows its own tables wins. The agent leg does:
        # a VM's tables come from its collection rule's streams, or from its OS,
        # neither of which the category map can express.
        if s_.get("agent_tables") is not None:
            s_["expected_tables"] = list(s_["agent_tables"])
            s_["unmapped_categories"] = []
            continue
        cats = s_.get("can_emit") or []
        if not cats:
            s_["expected_tables"], s_["unmapped_categories"] = [], []
            continue
        settings = s_.get("settings") or {}
        dedicated = bool(settings.get("dedicated"))
        # Whether a category lands in a resource-specific table or in
        # AzureDiagnostics is `logAnalyticsDestinationType` ON THE SETTING. A
        # resource with no setting has none to read it from, so `dedicated` is
        # False by absence rather than by evidence -- and that is exactly the
        # case every "here is what to enable" line is about.
        #
        # The table name stays: it is the documented default and the most
        # likely answer. But it is a default, and the report must not print it
        # in the same voice as a figure read from Azure. A reader who acts on a
        # guessed table name and finds the logs elsewhere stops believing the
        # measured numbers too.
        # NOT `table_basis` -- models.py already uses that name for a
        # different question (is this table deployed in the workspace).
        s_["mode_basis"] = "measured" if settings.get("count") else "assumed"
        tables, unmapped = tablemap.tables_for(
            s_.get("surface_type") or "", cats, dedicated)
        s_["expected_tables"] = tables
        s_["unmapped_categories"] = unmapped


def _verdict(rid: str, rtype: str, scope: str, surfaces: list[dict],
             extra: dict | None = None) -> dict:
    """One row: the same three states, whatever the scope."""
    _annotate_tables(surfaces)
    base = {"resource_id": rid, "resource_type": rtype, "scope": scope,
            "surfaces": surfaces,
            "expected_tables": sorted({t for s_ in surfaces
                                       for t in s_.get("expected_tables", [])}),
            "unmapped_categories": sorted({c for s_ in surfaces
                                           for c in s_.get("unmapped_categories", [])}),
            **(extra or {})}
    loggable = [s for s in surfaces if s.get("can_emit")]

    if not loggable:
        if any(not s.get("readable") for s in surfaces):
            return {**base, "assessment_status": "not_assessed", "logging_status": None,
                    "basis": "could not read what this scope can emit"}
        return {**base, "assessment_status": "out_of_scope", "logging_status": None,
                "basis": "nothing to enable at this scope"}

    if any(not s["settings"]["readable"] for s in loggable):
        return {**base, "assessment_status": "not_assessed", "logging_status": None,
                "basis": "settings unreadable"}

    live = [s for s in loggable if s["settings"]["to_workspace"]]
    elsewhere = sorted({d for s in loggable for d in s["settings"].get("elsewhere", [])})

    if not live:
        basis = (f"configured but ships to {', '.join(elsewhere)}, not the target"
                 if elsewhere else "nothing reaches the target workspace")
        status = "not-enabled"
    elif len(live) < len(loggable):
        status = "partial-enabled"
        status_basis = f"{len(live)} of {len(loggable)} scopes reach the target workspace"
        basis = status_basis
    else:
        gaps = []
        for s in live:
            covered = set(s["settings"]["enabled"])
            for group in s["settings"]["groups"]:
                covered |= set(s["groups"].get(group, []))
            missing = sorted(set(s["can_emit"]) - covered)
            if missing:
                gaps.append(missing)
        if gaps:
            status, basis = "partial-enabled", "not enabled: " + ", ".join(gaps[0])
        else:
            status, basis = "fully-enabled", "everything this scope emits reaches the target"

    return {**base, "assessment_status": "assessed", "logging_status": status,
            "basis": basis}



def _probe_one(resource: dict, flow_logs: dict, dcr: dict,
               workspace_id: str) -> dict:
    """One ARM resource -> one row, carrying every surface it has."""
    rid, rtype = resource["resource_id"], resource["resource_type"]
    data_plane_cats = DATA_PLANE_CATEGORIES.get(rtype, frozenset())

    surfaces = []

    own = _categories(rid)
    if own.get("can_emit"):
        own["settings"] = _settings(rid, workspace_id)
    # The resource's own categories, split by plane. Both halves are surfaces
    # of the same row -- only the label differs.
    for plane, is_data in (("control", False), ("data", True)):
        cats = [c for c in own.get("can_emit", []) if (c in data_plane_cats) is is_data]
        if not cats and plane == "data":
            continue
        surfaces.append({**own, "scope": rid, "plane": plane,
                         "surface_type": rtype, "log_scope": rid,
                         "can_emit": cats})

    # Child scopes Azure keeps data-plane logs on: storage's blob, file, queue
    # and table services.
    for child in _scopes(rid, rtype):
        if child == rid:
            continue
        cats = _categories(child)
        if cats.get("can_emit"):
            cats["settings"] = _settings(child, workspace_id)
        # ".../blobServices/default" -> "microsoft.storage/storageaccounts/blobservices"
        child_type = f"{rtype}/{child.rsplit('/', 2)[-2].lower()}"
        surfaces.append({**cats, "scope": child, "plane": "data",
                         "surface_type": child_type, "log_scope": child})

    if rtype in FLOW_LOG_TYPES:
        # `scope` on these two is a synthetic id -- a flow log's name, an
        # associations path -- that no table stamps. `log_scope` is the id
        # that actually appears in `_ResourceId`, which is the resource.
        surfaces.append({**flowlogs.surface_for(rid, flow_logs, workspace_id),
                         "plane": "control", "surface_type": rtype,
                         "log_scope": rid})
    if rtype == "microsoft.compute/virtualmachines":
        surfaces.append({**_agent_surface(rid, dcr, resource.get("os_type")),
                         "plane": "control",
                         "surface_type": rtype, "log_scope": rid})

    return _verdict(rid, rtype, "resource", surfaces,
                    {"subscription": resource.get("subscription"),
                     "region": resource.get("region")})


def probe(resources: list[dict], workspace_id: str) -> list[dict]:
    """Every resource as one row, measured against `workspace_id`."""
    flow_logs = flowlogs.probe()
    vm_ids = [r["resource_id"] for r in resources
              if r["resource_type"] == "microsoft.compute/virtualmachines"]
    dcr = _dcr_map(vm_ids, workspace_id)
    worker = partial(_probe_one, flow_logs=flow_logs, dcr=dcr, workspace_id=workspace_id)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        return list(pool.map(worker, resources))
