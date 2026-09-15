"""What data the workspace actually holds, and what endpoints report into it.

`TableHealth` is the other side of `coverage_gaps`. That leg says what SHOULD
arrive and does not; this says what IS there, how much, and how recently --
which is what makes "a rule reads this table" answerable as "and the table is
fed" rather than assumed.

`table_tier` is None where the plan could not be read, which refuses a query
rather than assuming Analytics. An unknown plan is not a free one.

`is_gap` is left False throughout. It means a gap in a TECHNIQUE index -- a
table holding data that nothing here knows how to detect from -- and no such
index exists yet. Setting it from anything else would put a different claim
under a shipped field name.
"""

from __future__ import annotations

import json

from . import apiversions
from . import azcli

VALID_TIERS = {"Analytics", "Basic", "Auxiliary"}


def _query(workspace_guid: str, kql: str) -> tuple[list[dict], str | None]:
    """(rows, error). The error becomes the leg's `detail`, so it is the whole
    explanation a reader gets for why this half of the document is missing."""
    p = azcli.query(workspace_guid, kql)
    rows, error = azcli.loads(p, default=[])
    if error:
        # "'query' is misspelled or not recognized" is az's wording for a
        # missing extension, and it sends the reader looking for a typo. This
        # read is the one that answers "which tables hold data", so losing it
        # silently turns a whole half of the report into blanks.
        extension = azcli.missing_extension(error)
        return [], azcli.install_hint(extension) if extension else error[:200]
    return rows if isinstance(rows, list) else [], None


def deployed(workspace_arm_id: str) -> tuple[list[str] | None, dict[str, str], str | None]:
    """(every table that exists here, {table: plan}, error) from the control plane.

    One call, two answers, deliberately kept apart because they fail in
    different directions. The plan map is best-effort: a table whose plan is
    unreadable is simply absent from it, and callers already treat that as
    "assume Analytics". Existence cannot be best-effort -- it is the evidence
    for which table a detection should name.

    This used to be one function returning `{}` on failure, so "the workspace
    has no such table" and "the control plane did not answer" were the same
    value. That is survivable when the only question is a billing tier. It is
    not survivable as an existence check: it would turn every table into an
    unconfirmed one the moment ARM hiccuped, and a detection would silently
    fall back to the catalogue while reporting nothing unusual.

    `None` for the names means the read failed. `[]` would mean a workspace with
    no tables at all, which is a real if unlikely answer.

    Existence is the signal for resource-specific mode. A dedicated table --
    AZKVAuditLogs, AKSAudit, StorageBlobLogs -- only comes into being when a
    diagnostic setting in resource-specific mode creates it. So its presence is
    proof the tenant uses that mode. Its ABSENCE proves nothing: it may be
    legacy mode, or nothing of that kind may be logging at all.
    """
    p = azcli.run(
        ["rest", "--method", "get", "--url",
         f"https://management.azure.com{workspace_arm_id}/tables"
         f"?api-version={apiversions.LOG_ANALYTICS}",
         "-o", "json"],
        timeout=azcli.CONTROL_TIMEOUT,
    )
    if p.returncode != 0:
        return None, {}, (p.stderr or "").strip()[:200] or "the table list could not be read"
    try:
        payload = json.loads(p.stdout or "{}").get("value", [])
    except json.JSONDecodeError as unparseable:
        return None, {}, f"could not parse the table list: {unparseable}"

    names, plans = [], {}
    for entry in payload:
        name = entry.get("name")
        if not name:
            continue
        names.append(name)
        plan = (entry.get("properties") or {}).get("plan")
        if plan in VALID_TIERS:
            plans[name] = plan
    return sorted(names), plans, None


def plan(workspace_arm_id: str) -> tuple[dict, str | None]:
    """(what this workspace pays under, error).

    A per-GB figure means nothing without the plan it was computed against.
    `PerGB2018` is pay-as-you-go; `CapacityReservation` is a daily commitment
    bought at a discount, and the level is the number of GB/day committed.
    Both are on the workspace object, so the report can state the plan it
    priced against instead of implying every tenant pays list.

    This does NOT produce a rate. Discounts, agreements and the commitment
    tiers themselves are not readable from here, which is why the operator can
    override the rate and why the report says "list price" where it has not
    been told otherwise.
    """
    p = azcli.run(
        ["rest", "--method", "get", "--url",
         f"https://management.azure.com{workspace_arm_id}"
         f"?api-version={apiversions.LOG_ANALYTICS}", "-o", "json"],
        timeout=azcli.CONTROL_TIMEOUT,
    )
    if p.returncode != 0:
        return {}, (p.stderr or "").strip()[:200] or "the workspace could not be read"
    try:
        props = (json.loads(p.stdout or "{}").get("properties") or {})
    except json.JSONDecodeError as unparseable:
        return {}, f"could not parse the workspace: {unparseable}"
    sku = props.get("sku") or {}
    return {"sku": sku.get("name"),
            "commitment_gb_per_day": sku.get("capacityReservationLevel"),
            "retention_days": props.get("retentionInDays")}, None


def probe(workspace_guid: str, workspace_arm_id: str,
          index: dict[str, list[str]] | None = None,
          days: int = 30) -> tuple[list[dict], list[str] | None, dict]:
    """(TableHealth rows, tables deployed here, read state).

    The middle value is every table that EXISTS in the workspace, which is not
    the same set as the rows: those are tables with data in the window. A table
    deployed last week and quiet since is real and absent from the rows.
    """
    activity, err = _query(
        workspace_guid,
        f"union withsource=T * | where TimeGenerated > ago({days}d) "
        "| summarize rows=count(), newest=max(TimeGenerated) by T")
    if err:
        # The activity read failed, but the control-plane list is a separate
        # call and may still answer. Ask it anyway: knowing which tables exist
        # is what lets a detection name the right one, and it does not depend
        # on any data having arrived.
        names, _plans_only, _ = deployed(workspace_arm_id)
        return [], names, {"ran": False,
                           "detail": f"could not read table activity: {err}"}

    # Split by IsBillable, not just by DataType. Volume and cost are not the
    # same question, and the difference is large: SentinelHealth, SecurityAlert,
    # SecurityIncident, AzureActivity and the Office 365 connectors are
    # no-charge sources, and on this tenant they were two thirds of the volume
    # nothing reads. A report that prices megabytes uniformly would invoice the
    # customer for data Microsoft gives away.
    #
    # This column is the WORKSPACE'S OWN answer, which is the only correct one:
    # what a tenant is charged for depends on what it bought -- a Defender XDR
    # connection under E5, a Defender for Servers data grant -- and no price
    # list encodes that. Read it, do not infer it.
    #
    # A DataType can appear under both values in one window, so the two are
    # summed separately rather than one row overwriting the other.
    usage, _ = _query(
        workspace_guid,
        f"Usage | where TimeGenerated > ago({days}d) "
        "| summarize mb=sum(Quantity) by DataType, IsBillable")
    megabytes: dict[str, float] = {}
    billable_mb: dict[str, float] = {}
    for r in usage:
        try:
            name, mb = r["DataType"], float(r["mb"])
        except (TypeError, ValueError, KeyError):
            continue
        megabytes[name] = round(megabytes.get(name, 0.0) + mb, 2)
        # az renders the bool as a string; both shapes are accepted because
        # the SDK path returns a real bool and reading one as the other would
        # silently price every table as free.
        if str(r.get("IsBillable")).lower() == "true":
            billable_mb[name] = round(billable_mb.get(name, 0.0) + mb, 2)

    names, plans, _plans_error = deployed(workspace_arm_id)

    rows = []
    for r in activity:
        name = r["T"]
        rows.append({
            "table_name": name,
            "table_tier": plans.get(name),
            "last_ingest": r.get("newest") or None,
            "megabytes": megabytes.get(name),
            # None, not 0.0, where the meter did not price the table at all:
            # "free" and "not measured" are different answers and the report
            # must not print one as the other.
            "billable_megabytes": (billable_mb.get(name, 0.0)
                                   if name in megabytes else None),
            # Whether the meter reported ANY billable volume, which is not the
            # same as `billable_megabytes > 0`: a table billed for a few
            # kilobytes rounds to 0.0 MB and would otherwise be labelled free.
            # None where the meter did not price the table at all.
            "billable": (name in billable_mb) if name in megabytes else None,
            # A table holding data that the technique index has no opinion
            # on: a worklist for extending the index, not a finding about the
            # tenant. False when no index was supplied, because "nothing is
            # unindexed" and "nothing was checked" must not read alike --
            # `reads.library` says which.
            "is_gap": bool(index) and not index.get(name),
        })
    rows.sort(key=lambda x: -(x["megabytes"] or 0))

    unindexed = sum(1 for x in rows if x["is_gap"])
    unpriced = sum(1 for x in rows if x["megabytes"] is None)
    untiered = sum(1 for x in rows if x["table_tier"] is None)
    detail = (f"{len(rows)} table(s) with data in {days}d; "
              f"{untiered} with no readable plan, {unpriced} the Usage meter "
              f"did not price"
              + (f", {unindexed} the technique index has no opinion on"
                 if index else ", technique index not supplied so is_gap is unset"))
    if names is None:
        detail += "; the workspace table list could not be read"
    return rows, names, {"ran": True, "detail": detail}


def endpoints(workspace_guid: str) -> tuple[dict[str, int] | None, dict]:
    """{OSPlatform: device count}.

    None where the census did not run -- distinct from {}, which is a fleet
    with no devices in it. `DeviceInfo` is absent unless a Defender XDR
    connection is feeding the workspace, and its absence is not evidence of
    an empty fleet.
    """
    rows, err = _query(
        workspace_guid,
        "DeviceInfo | summarize devices=dcount(DeviceId) by OSPlatform")
    if err:
        return None, {"ran": False,
                      "detail": f"DeviceInfo unreadable, so no census: {err}"}
    if not rows:
        return None, {"ran": False,
                      "detail": "DeviceInfo holds no rows; no endpoint census is "
                                "possible, which is not the same as no devices"}
    census = {}
    for r in rows:
        try:
            census[r["OSPlatform"]] = int(r["devices"])
        except (TypeError, ValueError, KeyError):
            continue
    return census, {"ran": True,
                    "detail": f"{sum(census.values())} device(s) across "
                              f"{len(census)} platform(s) reporting to this workspace"}
