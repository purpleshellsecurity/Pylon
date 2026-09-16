"""The inventory leg: what the tenant runs, as `Resource` rows.

One read against Azure Resource Graph, shaped into `analysis_model.Resource`
and written as an `Analysis` with every other leg left un-run. Nothing here
computes coverage, tables, rules or gaps — those are separate legs, and a
document that mixes them cannot say which of its claims were measured.

The interesting constraint is that this leg can never emit `assessed`.
`Resource._status_and_outcome_agree` requires `assessed` to carry a
`logging_status`, and logging is the diagnostic-settings leg. So every row
here is `not_assessed` or `out_of_scope` — enforced by the model rather than
remembered by this file.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import textwrap
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

from . import azcli
from . import chain
from . import connectors as connectors_leg
from . import validate
from . import console
from . import coverage
from . import crosscheck
from . import defender as defender_leg
from . import diagnostics
from . import endpoints as endpoints_leg
from . import exposure as exposure_leg
from . import gapscan
from . import platforms
from . import products
from . import contenthub
from . import rulehealth
from . import rules as rules_leg
from . import scopes
from . import sentinelhealth
from . import summarise
from . import tables as tables_leg
from . import techniques
from .analysis_model import (Analysis, BlockedBy, Connector, CoverageGap, Gap,
                            ReadState, Reads, Recommendations, Resource,
                            RuleHealth, Summary, TableHealth)

ENDPOINTS_PATH = "endpoints.json"
OUT_PATH = "analysis.json"
RECOMMEND_PATH = "recommendations.json"
# A sidecar: the model has no section for Defender plans, because a plan
# being off is not a log going missing. The rows are still worth keeping,
# so the report can show them without parsing a read's prose.
PLANS_PATH = "defender_plans.json"
# Rules carry where they came from -- a Content Hub template or someone's
# hand -- which RuleHealth has no field for and a reader needs.
RULES_PATH = "rules_detail.json"
# Template ids alone cannot be read; the catalogue carries their names
# so a suggestion can say WHICH detection it means.
CATALOGUE_PATH = "templates.json"
PAGE = 1000

# Ordered so pagination by --skip is stable; ARG gives no guarantee otherwise.
QUERY = ("Resources | project id, type, subscriptionId, location, tags, "
         "publicNetworkAccess = tostring(properties.publicNetworkAccess), "
         "networkDefaultAction = tostring(properties.networkAcls.defaultAction), "
         "publicIngestion = tostring(properties.publicNetworkAccessForIngestion), "
         "osType = tostring(properties.storageProfile.osDisk.osType) "
         "| order by id asc")

# Tag keys that carry the owner's own criticality judgement, matched
# case-insensitively. Whichever lands first wins, so the most explicit name is
# checked before the vaguest.
CRITICALITY_TAG_KEYS = (
    "criticality",
    "businesscriticality",
    "business-criticality",
    "business_criticality",
    "importance",
    "severity",
    "tier",
)

# Types with no log categories at all — nothing to switch on, so they can never
# be dark and counting them inflates the denominator. These four are the ones
# `Resource`'s own docstring names.
OUT_OF_SCOPE_TYPES = frozenset({
    "microsoft.compute/disks",
    "microsoft.network/networkinterfaces",
    "microsoft.web/serverfarms",
    "microsoft.managedidentity/userassignedidentities",
})

# Only explicit ordinals are rankable. "business-critical" is a real tier and an
# unrankable one; inventing an integer for it would look exactly like a measured
# rank. 0 is highest, matching `criticality_rank`.
_RANKABLE = (
    re.compile(r"^tier\s*[-_]?\s*(\d+)$", re.I),
    re.compile(r"^p(\d+)$", re.I),
    re.compile(r"^(\d+)$"),
)


def rank_of(tier: str) -> int | None:
    """The tier as a sortable integer, or None where nothing here can rank it."""
    value = tier.strip()
    for pattern in _RANKABLE:
        match = pattern.match(value)
        if match:
            return int(match.group(1))
    return None


def read_criticality(tags: dict | None) -> tuple[str, int | None, str]:
    """(tier, rank, source) from the owner's tags, verbatim where present."""
    for key, value in (tags or {}).items():
        if key.strip().lower() in CRITICALITY_TAG_KEYS and str(value).strip():
            tier = str(value)          # verbatim — never normalised
            return tier, rank_of(tier), "tag"
    return "unrated", None, "unrated"


# The properties Azure uses to say "reachable from the internet". No one of
# them covers every type: storage reports `networkAcls.defaultAction` and
# leaves `publicNetworkAccess` unset, Key Vault and App Service report the
# latter, and Log Analytics and Application Insights report neither -- they
# use `publicNetworkAccessForIngestion`. All three are read and any can answer.
NETWORK_PROPS = ("publicNetworkAccess", "networkDefaultAction", "publicIngestion")

# Types that CAN face the internet but whose reachability is a network-path
# question -- a public IP, an inbound NSG rule, a load balancer frontend --
# rather than a property on the resource. This scan does not read network
# paths, so these are reported "unknown" and end up unrated. Calling them
# not-reachable because no property said otherwise is the inference this whole
# field is built to refuse: it would place three VMs in the clean tier without
# anything having checked whether they answer on a public address.
NETWORK_PATH_TYPES = frozenset({
    "microsoft.compute/virtualmachines",
    "microsoft.network/publicipaddresses",
    "microsoft.network/loadbalancers",
    "microsoft.network/applicationgateways",
    "microsoft.network/azurefirewalls",
    "microsoft.network/bastionhosts",
    "microsoft.network/frontdoors",
    "microsoft.cdn/profiles",
})


def types_with_reachability(rows: list[dict]) -> frozenset[str]:
    """Types that expose a reachability property, learned from the tenant.

    A hardcoded allowlist would silently classify any type it had not heard of
    as "no such concept", which reads identically to "not reachable". Deriving
    the set from what the query actually returned means a new type shows up as
    `unknown` -- a question -- rather than as a clean answer nobody measured.
    """
    return frozenset(
        (r.get("type") or "").lower() for r in rows
        if any((r.get(p) or "").strip() for p in NETWORK_PROPS))


# The ARM property each projected column came from, so the basis a row reports
# is the name a reader can go and look up rather than this file's shorthand.
PROP_NAME = {
    "publicNetworkAccess": "publicNetworkAccess",
    "networkDefaultAction": "networkAcls.defaultAction",
    "publicIngestion": "publicNetworkAccessForIngestion",
}


def read_reachability(row: dict, has_property: frozenset[str]
                      ) -> tuple[str | None, str | None]:
    """((enabled|disabled|unknown|None), the property and value that said so).

    Restriction wins over permission: a resource with the public endpoint on
    but `defaultAction: Deny` is reachable only from selected networks, and
    calling that exposed would overstate it.

    This measures whether the resource ANSWERS from any network. It is not a
    claim about anonymous access -- a storage account with the firewall open
    and `allowBlobPublicAccess: false` still requires a key, a SAS or a token.
    Conflating the two would turn an open firewall into a data breach.
    """
    kind = (row.get("type") or "").lower()
    seen = [(PROP_NAME[p], (row.get(p) or "").strip())
            for p in NETWORK_PROPS if (row.get(p) or "").strip()]
    for name, value in seen:
        if value.lower() in ("disabled", "deny"):
            return "disabled", f"{name}={value}"
    for name, value in seen:
        if value.lower() in ("enabled", "allow"):
            return "enabled", f"{name}={value}"
    if kind in NETWORK_PATH_TYPES:
        return "unknown", "reachability is a network path, which this scan does not read"
    if kind in has_property:
        return "unknown", "the type reports a reachability property and this run got no value"
    return None, None


def read_exposure(tags_ignored, public_network_access: str | None,
                  role_assignments: tuple[list[str], bool] | None
                  ) -> tuple[int | None, str]:
    """(exposure_rank, exposure_source) -- explicit tiers, first match wins.

    `tags_ignored` is never read. It is in the signature to say so at every
    call site: this ranking is structural, and the moment a tag reaches it the
    field becomes a second `criticality_tier` wearing a measured-looking name.

        0  publicly reachable AND a privileged role sits above it
        1  publicly reachable
        2  a privileged role sits above it
        3  a privileged role, scoped to this resource alone
        4  neither -- checked and clean

    Tier 1 absorbs "public with a role scoped only to itself": a role that
    cannot reach past a resource already open to the internet adds nothing to
    the blast radius. The role names are still recorded on the row.

    Returns (None, "unrated") wherever an input needed to place the resource is
    missing -- a failed role read, or a type that has a reachability property
    this run did not get a value for. That is NOT tier 4.
    """
    _ = tags_ignored
    if role_assignments is None:
        return None, "unrated"
    if public_network_access == "unknown":
        return None, "unrated"
    roles, above = role_assignments
    public = public_network_access == "enabled"
    if public and above:
        return 0, "role_assignment"
    if public:
        return 1, "public_network_access"
    if above:
        return 2, "role_assignment"
    if roles:
        return 3, "role_assignment"
    return 4, "scope"


def query_graph() -> list[dict]:
    """Every resource in reach, paged. Raises if the read itself fails."""
    rows: list[dict] = []
    while True:
        proc = azcli.run(
            ["graph", "query", "-q", QUERY,
             "--first", str(PAGE), "--skip", str(len(rows)), "-o", "json"],
            timeout=azcli.CONTROL_TIMEOUT,
        )
        payload, error = azcli.loads(proc, default={})
        if error:
            raise RuntimeError(error)
        page = (payload or {}).get("data") or []
        rows.extend(page)
        if len(page) < PAGE:
            return rows


def to_row(verdict: dict, tags: dict | None = None,
           exposure: dict | None = None) -> Resource:
    """A verdict from any scope -> a `Resource`. One shape for every scope.

    `exposure` is None for the tenant, subscription and Sentinel rows: they are
    not resources, nothing assigns a network endpoint or an RBAC scope to them,
    and placing them on the ladder would invent a reading.
    """
    tier, rank, source = read_criticality(tags)
    exposure = exposure or {}
    return Resource(
        public_network_access=exposure.get("public_network_access"),
        public_network_access_basis=exposure.get("public_network_access_basis"),
        privileged_role_assignments=exposure.get("privileged_role_assignments") or [],
        exposure_rank=exposure.get("exposure_rank"),
        exposure_source=exposure.get("exposure_source", "unrated"),
        resource_id=verdict["resource_id"],
        resource_type=verdict["resource_type"],
        scope=verdict.get("scope", "resource"),
        subscription=verdict.get("subscription"),
        region=verdict.get("region"),
        os_type=verdict.get("os_type"),
        criticality_tier=tier,
        criticality_rank=rank,
        criticality_source=source,
        assessment_status=verdict["assessment_status"],
        logging_status=verdict["logging_status"],
    )


def resolve_workspace(value: str) -> tuple[str, str, str]:
    """(arm id, name, guid) for a workspace given any of its three names.

    Taken as a parameter rather than discovered: a tenant can hold several
    Sentinel workspaces -- this one holds three -- and which of them is THE
    SIEM is a fact about the engagement, not something a scan can infer.

    The lookup itself lives in `validate` so that every command taking
    `--workspace` accepts the same spellings. It used to be written twice, and
    the two copies took the name, the resource id and the customer guid between
    them rather than each taking all three.
    """
    return validate.lookup(value)


LEG_WIDTH = 42
# Reset per run; appended by `_leg` so the summary can total the scan.
_elapsed: list[float] = []


@contextlib.contextmanager
def _leg(name: str):
    """Announce a read before it runs, and time it.

    The 2026-09-07 nightly hung for 37m58s and the log held NOTHING -- not even
    the workspace line, because stdout is block-buffered when it is a pipe and
    the process was killed before a flush. Even unbuffered it would have shown
    one line and then silence: `run` prints the target, then nothing until a
    summary that a hung scan never reaches.

    So a leg says its name BEFORE it blocks. "The scan hung" becomes "the scan
    hung reading table activity", which is the difference between a bug report
    and a guess. Timed on the way out because the useful question after a
    timeout is which leg got slower, and by how much against the 2m54s a whole
    scan used to take.

    stderr, so `analyze` piped to a file still yields a clean document; flushed
    per line, so the last line before a kill is the leg that was running.

    ONE line, not two. The name is written WITHOUT a newline so it appears the
    instant the leg starts, then the elapsed time is appended to the same line
    when it ends. A hang still shows the leg that was running -- the whole
    point of printing early -- without paying for it in duplicated names.
    """
    print(f"  {name:<{LEG_WIDTH}}", end="", file=sys.stderr, flush=True)
    started = time.monotonic()
    ok = True
    try:
        yield
    except BaseException:
        ok = False
        raise
    finally:
        elapsed = time.monotonic() - started
        _elapsed.append(elapsed)
        print(f"{elapsed:>7.1f}s" if ok else f"{'failed':>8}",
              file=sys.stderr, flush=True)


def _unresolved_rules(rule_rows: list[dict]) -> list[dict]:
    """Rules that HAVE a query and still resolved to no table.

    Distinct from a rule with no KQL at all: Fusion and the other
    service-decided kinds have nothing to resolve, and counting them here would
    report a limitation the scan does not have.
    """
    return [r for r in rule_rows
            if r.get("_query") and not r.get("tables_referenced")]


def run(workspace: str) -> int:
    """The scan, callable. Split from `main` so `pylon analyze` can invoke it
    without going through argparse and without this module owning the CLI."""
    workspace_id, workspace_name, workspace_guid = resolve_workspace(workspace)
    # Flushed: this was the ONE line the 37m58s nightly should have shown and
    # did not, because stdout block-buffers into a pipe and the kill never
    # reached a flush. A scan that says nothing is a scan nobody can debug.
    _elapsed.clear()
    print(f"\nPylon  |  {workspace_name}  |  30-day window\n",
          file=sys.stderr, flush=True)
    try:
        with _leg("resource inventory"):
            rows = query_graph()
    except Exception as exc:
        # The read did not happen, so the section stays null. `_legs_agree`
        # would reject the alternative.
        reads = Reads(inventory=ReadState(ran=False, detail=str(exc)[:500]))
        resources = None
    else:
        # osType rides along because a VM's agent table depends on it: Linux
        # writes Syslog and never Event. The Resource Graph query already
        # selects it; it was simply dropped here, so every Linux VM was told to
        # feed the Windows event log.
        stub = [{"resource_id": r["id"],
                 "resource_type": (r.get("type") or "").lower(),
                 "subscription": r.get("subscriptionId"),
                 "os_type": r.get("osType"),
                 "region": r.get("location")} for r in rows]
        tags_by_id = {r["id"]: r.get("tags") for r in rows}

        # Structural exposure. Reachability rides on the inventory query that
        # already ran; privileged roles are one new read, and if it fails every
        # resource in the subscription stays unrated rather than being placed
        # in the clean tier on no evidence.
        sub_for_roles = rows[0].get("subscriptionId") if rows else None
        with _leg("privileged roles"):
            role_read = (exposure_leg.read(sub_for_roles) if sub_for_roles
                         else {"ran": False, "by_scope": {},
                               "detail": "no subscription in the inventory to read"})
        has_net = types_with_reachability(rows)
        exposure_by_id = {}
        for r in rows:
            pna, why = read_reachability(r, has_net)
            covering = (exposure_leg.covering(r["id"], role_read["by_scope"])
                        if role_read["ran"] else None)
            rank, source = read_exposure(None, pna, covering)
            exposure_by_id[r["id"]] = {
                "public_network_access": pna,
                "public_network_access_basis": why,
                "privileged_role_assignments": covering[0] if covering else [],
                "exposure_rank": rank, "exposure_source": source,
            }

        # resource scope
        with _leg("diagnostic settings"):
            verdicts = diagnostics.probe(stub, workspace_id)
        # the scopes above and beside it
        sub_id = rows[0].get("subscriptionId") if rows else None
        verdicts.append(scopes.tenant(workspace_id))
        if sub_id:
            verdicts.append(scopes.subscription(sub_id, workspace_id))
        # Sentinel's own health and audit monitoring, rather than a connector
        # list: the connectors API sees only the ones created as resources.
        if workspace_guid:
            with _leg("Sentinel health"):
                health, health_read2 = sentinelhealth.probe(workspace_guid)
        else:
            health, health_read2 = {}, {"ran": False,
                                        "detail": "workspace guid unresolved"}
        verdicts.extend(scopes.sentinel_monitoring(workspace_id, health))
        defender = scopes.defender_plans(sub_id) if sub_id else {"ran": False, "detail": "no subscription"}
        with _leg("analytics rules"):
            rule_rows, rules_read = rules_leg.probe(workspace_id)
        # Both connector legs, unioned, so a blind spot is claimed only where
        # neither can see the source. `health` is already read above.
        kinds = crosscheck.connector_kinds(workspace_id, health)
        with _leg("ingestion"):
            cross = (crosscheck.check(verdicts, workspace_guid, kinds=kinds)
                     if workspace_guid
                     else {"ran": False, "detail": "workspace guid unresolved",
                           "contradictions": [], "unreported": [], "tables": {}})
        with _leg("ingestion gaps"):
            gap_rows, gaps_read = coverage.build(verdicts, cross.get("tables") or {},
                                                 workspace_guid)
        if workspace_guid:
            # The index is scanned from THIS workspace's templates: what it can
            # detect is a function of the solutions installed here. Built first
            # so `tables` can say which tables it has no opinion on.
            with _leg("rule templates"):
                known = rules_leg.workspace_tables(workspace_id)
                index, catalogue, index_read = techniques.probe(
                    workspace_id, known, rules_leg.tables_in)
            with _leg("table tiers"):
                table_rows, deployed_names, tables_read = tables_leg.probe(
                    workspace_guid, workspace_id, index)
                # What this workspace pays under. Cheap (one control-plane
                # GET), and without it a per-GB figure in the report is a
                # number with no stated basis. `{}` on failure: the report
                # then says it priced at list without naming a plan, rather
                # than naming the wrong one.
                workspace_plan, _plan_err = tables_leg.plan(workspace_id)
            # Tiers gate the health check: a billable table is refused, not
            # judged. Tables absent from this map hold no data at all.
            # The None is KEPT, not coerced to "Analytics". Coercing it meant
            # a table whose plan the control plane would not report counted as
            # free to query, which is the one direction a spend gate must not
            # fail in. `rulehealth` now refuses an unknown plan the same way it
            # refuses a known billable one.
            tiers = {t["table_name"]: t["table_tier"] for t in table_rows}
            with _leg(f"rule health ({len(rule_rows)} analytics rules)"):
                rule_rows, health_read = rulehealth.probe(rule_rows, workspace_guid, tiers)
            with _leg("detections by a security product"):
                product_cover, product_read = products.probe(workspace_guid)
            # Which plans are off AND have something here they would protect.
            # Both halves are already measured, so this needs no mapping that
            # can go stale.
            present = collections.Counter((r.get("type") or "").lower() for r in rows)
            plan_rows, plan_read = defender_leg.assess(
                defender.get("on", []), defender.get("off", []), present,
                defender.get("plans"))
            with _leg("Defender for Endpoint"):
                census, endpoint_detail, census_read = endpoints_leg.probe(workspace_guid)
            # The denominator. ATT&CK narrowed to the platforms this tenant
            # demonstrably runs -- not the installed template list, which would
            # measure Content Hub against itself.
            vm_os = collections.Counter(
                (r.get("osType") or "").strip() for r in rows if (r.get("osType") or "").strip())
            plats, plat_evidence = platforms.detect(
                [{"resource_type": (r.get("type") or "").lower(), "scope": "resource"}
                 for r in rows] + [{"resource_type": v["resource_type"],
                                    "scope": v.get("scope", "resource")}
                                   for v in verdicts],
                set(tiers), dict(vm_os), census)
            candidates = platforms.universe(plats)
            plat_read = platforms.read_state(plats, plat_evidence, len(candidates))
            gap_rows2, gaps2_read = gapscan.build(index, rule_rows, set(tiers),
                                                  product_cover, candidates)
            # XDR families belong in the document, not only in a sidecar.
            verdicts.extend(scopes.xdr_families(workspace_id, endpoint_detail))
        else:
            table_rows, tables_read = [], {"ran": False, "detail": "workspace guid unresolved"}
            # {}, not None: the report treats an empty plan as "could not find
            # out" and says it priced at list without naming a plan. Bound here
            # because the guid-unresolved path must still write the document
            # that explains itself, not raise UnboundLocalError -- which is
            # exactly what it did until the tests for this path caught it.
            workspace_plan = {}
            # None, not []. The control-plane table list was never read, and an
            # empty list would mean a workspace with no tables -- which is what
            # `deployed.from_analysis` would hand the generator as evidence.
            deployed_names = None
            health_read = {"ran": False, "detail": "workspace guid unresolved"}
            index, catalogue = {}, []
            index_read = {"ran": False, "detail": "workspace guid unresolved"}
            gap_rows2, gaps2_read = [], {"ran": False, "detail": "workspace guid unresolved"}
            product_cover = {}
            product_read = {"ran": False, "detail": "workspace guid unresolved"}
            plan_rows, plan_read = [], {"ran": False, "detail": "not assessed",
                                        "exposed": []}
            census, endpoint_detail = None, {}
            census_read = {"ran": False, "detail": "workspace guid unresolved"}
            plat_read = {"ran": False,
                         "detail": "the workspace guid did not resolve, so no "
                                   "platform could be measured and no denominator built"}
        measured = sum(v["assessment_status"] == "assessed" for v in verdicts)
        reads = Reads(
            inventory=ReadState(
                ran=True,
                detail=f"azure resource graph returned {len(rows)} resource(s)"),
            # `ran` was hardcoded True. `diagnostics.probe` cannot fail as a
            # whole -- a resource it could not reach becomes an unassessed row
            # rather than an exception -- so the boolean was always claiming a
            # read that may have measured nothing. The detail said "0 of 97
            # assessed" honestly beside it, which means a reader of the sentence
            # was fine and a reader of the flag was misled.
            #
            # Now it says what it is: the read RAN if it assessed anything. Zero
            # of 97 is a read that did not happen in the only sense that matters
            # to a consumer deciding whether to trust the section.
            diagnostic_settings=ReadState(
                ran=measured > 0,
                detail=f"tenant, subscription, resource and sentinel scopes "
                       f"measured against {workspace_name}; "
                       f"{measured} of {len(verdicts)} rows assessed"
                       + ("" if measured else
                          " -- nothing was assessed, so this section is not "
                          "evidence about the tenant")),
            role_assignments=ReadState(ran=role_read["ran"],
                                       detail=role_read["detail"]),
            platforms=ReadState(ran=plat_read["ran"], detail=plat_read["detail"]),
            # BOTH halves, not just the control-plane call. `defender["ran"]`
            # says `az security pricing list` answered; the assessment that
            # turns that into rows lives inside `if workspace_guid:` and is
            # stubbed out when the guid does not resolve. So a run that read
            # the plans and assessed none of them reported ran=True with a
            # detail reading "not assessed", wrote an empty
            # defender_plans.json, dropped the Defender section from the
            # report, and left this question out of "what this scan could not
            # answer" -- the summary said 10 unanswered checks when it was 11.
            #
            # Exactly what the note above `diagnostic_settings` describes
            # fixing for its own field: a reader of the sentence was fine and a
            # reader of the flag was misled.
            defender_plans=ReadState(
                ran=defender["ran"] and plan_read["ran"],
                detail=(plan_read["detail"] + ". " + product_read["detail"])),
            sentinel_health=ReadState(ran=health_read2["ran"],
                                      detail=health_read2["detail"]),
            rules=ReadState(ran=rules_read["ran"], detail=rules_read["detail"]),
            # The cross-check is a guard on this scan, not a measurement of the
            # tenant -- so it is recorded as a read, and never as findings.
            differential=ReadState(ran=cross["ran"], detail=cross["detail"]),
            resource_activity=ReadState(ran=gaps_read["ran"], detail=gaps_read["detail"]),
            table_activity=ReadState(ran=tables_read["ran"], detail=tables_read["detail"]),
            # Its own leg, not a rider on table_activity. The control-plane list
            # is a separate call that can answer when the data-plane query does
            # not, and vice versa -- and a detection picking a table name needs
            # to know which of those happened.
            provisioned_tables=ReadState(
                ran=deployed_names is not None,
                detail=(f"{len(deployed_names)} table(s) deployed in the workspace"
                        if deployed_names is not None
                        else "the workspace table list could not be read")),
            endpoint_census=ReadState(ran=census_read["ran"], detail=census_read["detail"]),
            rule_audit=ReadState(ran=health_read["ran"], detail=health_read["detail"]),
            # Resolved for EVERY deployed rule, or it did not answer. A rule
            # whose query calls a saved KQL function names no table in its own
            # text, and this scan does not open function bodies -- so its
            # tables never reach the table or coverage sections and both are a
            # floor rather than a count. `report.py` has counted these all
            # along and rendered the number as a note under one table, which is
            # not where a reader looks for what went unanswered.
            rule_tables=ReadState(
                ran=rules_read["ran"] and not _unresolved_rules(rule_rows),
                detail=(
                    f"{len(rule_rows)} rule(s) resolved to the tables they read"
                    if rules_read["ran"] and not _unresolved_rules(rule_rows) else
                    f"{len(_unresolved_rules(rule_rows))} of {len(rule_rows)} rule(s) "
                    "name no table directly, most likely calling a saved KQL "
                    "function such as an ASIM parser. Any table they read is "
                    "counted as unwatched, so coverage is a floor"
                    if rules_read["ran"] else rules_read["detail"])),
            library=ReadState(ran=index_read["ran"], detail=index_read["detail"]),
            gaps=ReadState(ran=gaps2_read["ran"], detail=gaps2_read["detail"]),
        )
        resources = [to_row(v, tags_by_id.get(v["resource_id"]),
                            exposure_by_id.get(v["resource_id"]))
                     for v in verdicts]

    # Every other leg is left at its default of not-run, and every other section
    # at None. Construction is the validation: pydantic raises here if the
    # document contradicts itself.
    analysis = Analysis(
        generated_at=datetime.now(timezone.utc),
        workspace=workspace_name,
        reads=reads,
        resources=resources,
        # Each section guarded by its OWN leg, not by the inventory read. These
        # two were guarded on `resources is not None` alone, so a tenant where
        # Resource Graph answers and the SecurityInsights read is denied built a
        # document claiming rules it never read -- and `_legs_agree` refused it,
        # killing the scan with a pydantic traceback instead of writing the
        # document that says which leg failed. `tables` below already had this
        # right; the difference was never deliberate.
        # `_enabled` is promoted rather than stripped. The underscore prefix
        # marks a sidecar field, and this one is a MEASUREMENT: whether the rule
        # is switched on, read from its own properties. Dropping it meant the
        # analysis could not tell an enabled rule from a disabled one, and
        # anything wanting to know had to go and read rules_detail.json.
        rules=([RuleHealth(enabled=r.get("_enabled"),
                           **{k: v for k, v in r.items() if not k.startswith("_")})
                for r in rule_rows]
               if resources is not None and rules_read["ran"] else None),
        coverage_gaps=([CoverageGap(**g) for g in gap_rows]
                       if resources is not None and gaps_read["ran"] else None),
        # `tables` is tied to reads.table_activity by the model's own
        # validator: populated exactly when that read ran, null otherwise.
        tables=([TableHealth(**t) for t in table_rows]
                if resources is not None and tables_read["ran"] else None),
        # Guarded like every other section. Unguarded, an inventory read that
        # RAISED -- a lapsed `az login`, Resource Graph refusing -- crashed here
        # with UnboundLocalError instead of writing the document that says the
        # read did not happen. The one path the whole model exists to describe
        # was the one path that could not reach it.
        endpoint_os=(census if resources is not None else None),
        # Tied to reads.provisioned_tables by the model's validator, the same way
        # `tables` is tied to table_activity.
        # Guarded like every other section: on the inventory-failure path the
        # `else` branch never ran, so the name is unbound. `_legs_agree` needs
        # None here anyway -- the read is at its ran=False default.
        provisioned_tables=(deployed_names if resources is not None else None),
        # The health detail itself, not just its read state. Two findings live
        # in here and nowhere else: rules Sentinel auto-disabled, and why runs
        # failed.
        #
        # Guarded on `resources`, like every other section. `health` is bound
        # inside the else-branch of the inventory read, so an inventory that
        # RAISED -- a lapsed `az login` -- leaves it unbound and this line
        # crashes with UnboundLocalError instead of writing the document that
        # says the read did not happen. The first draft of this line did
        # exactly that, and the test written for the identical bug last time
        # caught it.
        sentinel_health=((health or None) if resources is not None else None),
        # Bound inside the same else-branch as `health`, so guarded the same
        # way for the same reason.
        workspace_plan=((workspace_plan or None) if resources is not None else None),
        gaps=([Gap(**g) for g in gap_rows2]
              if resources is not None and gaps2_read["ran"] else None),
        # Connectors as a source. `kinds` is the union of both connector legs,
        # and `cross["ran"]` is what says that union means anything: with it
        # false, nothing can be called absent and every row says so.
        connectors=([Connector(**r) for r in connectors_leg.assess(
            None, rule_rows, kinds)]
            if resources is not None and cross["ran"] else None),
    )

    if analysis.resources is not None:
        # THE CHAIN, walked once the legs have all landed.
        #
        # Every leg answers its own question and none of them join up, so the
        # document could say "8 rules cannot fire" in one section and
        # "StorageBlobLogs received nothing" in another and never that the
        # first is caused by the second. Stamped here rather than inside each
        # leg because no leg has the upstream context: `rulehealth` knows a
        # rule matched nothing and cannot know why.
        #
        # Built from the BUILT objects for the same reason the summary is.
        _fed = {t.table_name for t in (analysis.tables or [])}
        _blocks = chain.table_blocks(
            [g.model_dump() for g in (analysis.coverage_gaps or [])])
        _rule_rows = [r.model_dump() for r in (analysis.rules or [])]
        for _r in _rule_rows:                      # chain joins on _techniques
            _r["_techniques"] = _r.get("techniques") or []
        _rule_blocked = chain.rule_blocks(_rule_rows, _fed, _blocks)
        for rule in (analysis.rules or []):
            found = _rule_blocked.get(rule.name)
            if found:
                rule.blocked_by = BlockedBy(**found.as_dict())
        _tech_blocked = chain.technique_blocks(
            [g.model_dump() for g in (analysis.gaps or [])], _rule_rows,
            _rule_blocked)
        for gap in (analysis.gaps or []):
            found = _tech_blocked.get(gap.technique_id)
            if found:
                gap.blocked_by = BlockedBy(**found.as_dict())

        # Computed from the built objects, so the counts describe THIS
        # document rather than the loose values that went into it.
        analysis.summary = Summary(**summarise.build(
            analysis.resources, analysis.rules or [], analysis.tables or [],
            analysis.gaps or [], analysis.coverage_gaps or [],
            analysis.fresh_days))

    # A separate document on a separate cadence. Written only when the
    # analysis it derives from exists, and carrying that analysis's timestamp
    # so a reader can see when the two have drifted apart.
    #
    # This runs BEFORE analysis.json is written, which it did not used to.
    # `contenthub.build` is the only source of what each installed solution
    # DECLARES it needs, and that is half the evidence for reporting a
    # connector as expected and absent. Written first, the document went to
    # disk carrying only the half derived from rules, and the re-assessment
    # below updated an object nobody would read again.
    rec_note = None
    # A run that does not produce recommendations must not leave the PREVIOUS
    # run's beside its own analysis.json. The two are joined by
    # `analysis_generated_at`, and `report_detections` refuses to render a
    # mismatched pair -- correct, but it turns a stale file from a scan nobody
    # is looking at any more into a hard failure of the scan that just
    # succeeded. Removing it says the same thing without the refusal: there are
    # no recommendations for this scan.
    if not (analysis.resources is not None and workspace_id):
        try:
            os.remove(RECOMMEND_PATH)
        except OSError:
            pass
    if analysis.resources is not None and workspace_id:
        solution_rows, rec_note = contenthub.build(
            workspace_id, {t.table_name for t in (analysis.tables or [])},
            catalogue,
            [g.model_dump() for g in (analysis.coverage_gaps or [])],
            [r.model_dump() for r in (analysis.resources or [])],
            plan_rows, sum((analysis.endpoint_os or {}).values()))
        # Re-assessed now that the solutions exist. At construction only the
        # rules were available, and a solution DECLARING a connector is the
        # stronger half of the evidence: it is this tenant saying outright that
        # it expects that source. `contenthub.build` runs after the document is
        # constructed, so this is the first point both halves are in hand.
        if analysis.connectors is not None:
            analysis.connectors = [
                Connector(**r) for r in
                connectors_leg.assess(solution_rows, rule_rows, kinds)]
        # Built here rather than in a module of its own. `recommend.py` existed
        # to wrap these five fields in a dict and was named after `pylon
        # recommend`, a verb removed in 1.1.0 -- so every reviewer walking the
        # tree stopped on it to ask whether it was dead. The three values it
        # carried that the model did not (schema version 2, and cost figures
        # that are measured zeros rather than absent ones) are defaults on
        # `Recommendations` now, where the document's shape already lived.
        recommendations = Recommendations(
            generated_at=datetime.now(analysis.generated_at.tzinfo),
            workspace=workspace_name,
            analysis_generated_at=analysis.generated_at,
            solutions=solution_rows,
        )
        with open(RECOMMEND_PATH, "w", encoding="utf-8") as handle:
            handle.write(recommendations.model_dump_json(indent=2))

    with open(OUT_PATH, "w", encoding="utf-8") as handle:
        handle.write(analysis.model_dump_json(indent=2))

    verdict_path = "verdicts.json"
    if resources is not None:
        with open(verdict_path, "w", encoding="utf-8") as handle:
            json.dump(verdicts, handle, indent=2)
        with open(PLANS_PATH, "w", encoding="utf-8") as handle:
            json.dump(plan_rows, handle, indent=2)
        with open(RULES_PATH, "w", encoding="utf-8") as handle:
            json.dump(rule_rows, handle, indent=2)
        with open(CATALOGUE_PATH, "w", encoding="utf-8") as handle:
            json.dump(catalogue, handle, indent=2)
        if endpoint_detail:
            # Which inventoried machines have a sensor, matched on the ARM id
            # the device itself reports rather than on a hostname.
            endpoint_detail["inventory"] = endpoints_leg.matched_to_inventory(
                endpoint_detail, analysis.resources or [])
            with open(ENDPOINTS_PATH, "w", encoding="utf-8") as handle:
                json.dump(endpoint_detail, handle, indent=2)

    if _elapsed:
        print("  " + "-" * (LEG_WIDTH + 8), file=sys.stderr)
        print(f"  {'total':<{LEG_WIDTH}}{sum(_elapsed):>7.1f}s",
              file=sys.stderr, flush=True)

    # ---- the summary ------------------------------------------------------
    # Grouped and labelled rather than dumped. It used to print
    # `reads.inventory.ran = True`, `endpoint_os = {'Windows11': 1}` and
    # `rule health = 13 never-fires; 12 fires; 1 not-assessed` -- internal
    # names, a Python dict repr, and a semicolon-joined string, at a person.
    #
    # Every number still comes from the DOCUMENT, not the loose lists. The
    # lists say 0 for a leg that never ran, and "analytics rules 0" on an
    # operator's screen is the exact claim this project refuses. A leg that
    # did not run reads `not measured`, the same words the report uses.
    NOT_MEASURED = "not measured"

    def count(value) -> str:
        return NOT_MEASURED if value is None else f"{len(value):,}"

    def number(value) -> str:
        """A count the document already computed, rather than a length."""
        return NOT_MEASURED if value is None else f"{value:,}"

    def row(label: str, value: str, note: str = "") -> None:
        print(f"  {label:<28}{value:>12}" + (f"   {note}" if note else ""))

    print()
    print(console.heading("MEASURED"))
    # From the SUMMARY, not from `resources`. That list is every verdict row,
    # and the scope rows ride in it -- tenant, subscription, Sentinel
    # monitoring, the XDR families -- so a tenant with three storage accounts
    # was told it had seven resources, on the first line of the screen. The
    # document and the report both filtered to `scope == "resource"` the whole
    # time and said three. The comment above this block already states the
    # rule: every number comes from the document, not from the loose lists.
    row("resources", number(analysis.summary.resources
                            if analysis.summary is not None else None))
    row("analytics rules", count(analysis.rules))
    row("tables ingesting", count(analysis.tables))
    # Said with the caveat attached. A tenant with 36 tables holding data can
    # have 845 schemas provisioned by Content Hub solutions, and an earlier
    # version of this tool read the larger number as proof of use. That was
    # the bug the first real run found.
    row("table schemas", count(analysis.provisioned_tables),
        "defined on the workspace, not ingesting")
    row("ingestion gaps", count(analysis.coverage_gaps))
    row("ATT&CK techniques assessed",
        count(gap_rows2 if resources is not None else None))

    if resources is not None and rule_rows:
        tally = collections.Counter(r.get("rule_health_status") for r in rule_rows)
        print()
        print(console.heading("ANALYTICS RULES"))
        for status, label in (("fires", "returned rows when tested"),
                              ("never-fires", "returned nothing"),
                              ("not-assessed", "could not be tested")):
            if tally.get(status):
                print(f"  {tally[status]:>4}  {label}")

    if resources is not None and endpoint_detail.get("inventory"):
        inv = endpoint_detail["inventory"]
        total = len(inv["with_sensor"]) + len(inv["without_sensor"])
        print()
        print(console.heading("DEFENDER FOR ENDPOINT"))
        print(f"  {len(inv['with_sensor'])} of {total} inventoried "
              f"machine{'' if total == 1 else 's'} "
              f"{'has' if len(inv['with_sensor']) == 1 else 'have'} a sensor")
        for name, n in sorted((census or {}).items()):
            print(f"  {name:<28}{n:>12}")

    if rec_note:
        print()
        print(console.heading("CONTENT HUB"))
        # Split on the semicolon, which is where the counts stop being one
        # sentence: the total on one line, what to do about it on the next.
        for clause in rec_note["detail"].split("; "):
            if clause.strip():
                print(f"  {clause.strip().rstrip('.')}")

    # A leg that could not run is a question nobody answered. Named with its
    # reason, so the next command to type is on the screen.
    NOT_THIS_COMMAND = {"library", "generation"}
    unread = [(field, state) for field, state in
              analysis.reads.model_dump().items()
              if isinstance(state, dict) and not state.get("ran")
              and field not in NOT_THIS_COMMAND]
    if unread:
        print()
        print(console.heading("NOT MEASURED") + f"   {len(unread)} check"
              f"{'' if len(unread) == 1 else 's'}")
        for field, state in unread:
            why = textwrap.wrap(state.get("detail") or "did not run", 48) or [""]
            print(f"  {field.replace('_', ' '):<28}{why[0]}")
            for line in why[1:]:
                print(f"  {'':<28}{line}")
        print()
        print("  These are unanswered questions, not clean results. The report")
        print("  says the same on every page they touch.")

    if resources is not None and (cross["contradictions"] or cross["unreported"]):
        print()
        print(console.heading("DISAGREEMENTS"))
        for c in cross["contradictions"]:
            print(f"  {c['scope']} reads as not-enabled, but {c['table']} "
                  f"has {c['rows']:,} rows")
        if cross["unreported"]:
            print("  arriving via paths no configuration API reports: "
                  + ", ".join(cross["unreported"]))

    print()
    print(console.heading("WROTE"))
    print(f"  {OUT_PATH}")
    if rec_note:
        print(f"  {RECOMMEND_PATH}")
    return 0 if analysis.reads.inventory.ran else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan a tenant's telemetry against one Sentinel workspace.")
    parser.add_argument(
        "--workspace", required=True,
        help="the Sentinel/Log Analytics workspace to measure against: "
             "a name, or a full ARM resource id")
    return run(parser.parse_args().workspace)


if __name__ == "__main__":
    sys.exit(main())
