#!/usr/bin/env python3
"""Render the telemetry health report: what is logging, and what is not.

The first of two documents. This one answers "is the telemetry healthy" and
stops there; `report_detections.py` answers "what should we deploy". They were
one page, and a reader could not tell which question a given table was
answering.

A renderer, not a second source of truth: every number here is read from
`analysis.json` and none is recomputed. Where the document records that a
claim is weak -- a docs-sourced table name, a path the configuration APIs
cannot see -- the report says so rather than presenting
every row at the same confidence. A coverage report that reads more certain
than its inputs is the failure mode this whole scan was built to avoid.
"""

from __future__ import annotations

import collections
import json
import sys

from . import endpoints, plan_detections, usage
from .reportkit import HEAD, bar, e, plural, short

OUT = "telemetry_health_report.html"

STATE_ORDER = ["fully-enabled", "partial-enabled", "not-enabled", None]
STATE_LABEL = {"fully-enabled": "Fully enabled", "partial-enabled": "Partly enabled",
               "not-enabled": "Not enabled", None: "Nothing to enable"}


# What each read answers, in a reader's words. Only the legs whose absence
# changes how the report should be read -- a client does not need every
# internal step, they need to know which questions went unanswered.
READ_LABEL = {
    "inventory": "Which resources exist",
    "diagnostic_settings": "What each resource is configured to log",
    "table_activity": "Which tables hold data",
    "provisioned_tables": "Which table schemas are defined (not which hold data)",
    "rules": "Which analytics rules are deployed",
    "rule_audit": "Whether each rule's query runs",
    "resource_activity": "Which resources are sending data",
    "defender_plans": "Which Defender plans are enabled",
    "sentinel_health": "Whether Sentinel health monitoring is on",
    "role_assignments": "Who holds privileged roles",
}


# Tables this scan reads on every run. Excluded from the unread list for the
# same reason the Defender XDR family is: something does read them, and here
# that something is Pylon.
SCAN_READS = {"SentinelHealth", "SentinelAudit"}


def unread_tables(tables: list[dict], rules_by_table: dict,
                  read_elsewhere: set[str] | None = None) -> list[dict]:
    """Tables holding data that no deployed rule reads, biggest first.

    The mirror of the log-gap table, which asks the opposite question: tables a
    rule reads that hold nothing. Both halves were already measured -- megabytes
    per table comes from the Usage meter, and which tables rules read comes from
    the rules themselves -- and nothing had put them together.

    This is the cost finding the report can actually make. Query cost per rule
    is zero on the Analytics tier and the tool refuses to run billable-tier
    queries anyway; cost per true positive needs a price only the customer
    knows. Volume arriving that nothing reads needs neither, because it is two
    measured numbers and no arithmetic on money at all.

    Deliberately NOT called waste. A table can be read by a hunting query, a
    workbook, an export or an auditor, none of which this scan can see. What is
    true is that no deployed ANALYTICS RULE reads it, and that is what the
    caller must say.

    TWO KNOWN LIMITS, BOTH IN THE FALSE-POSITIVE DIRECTION
    ------------------------------------------------------
    `rules_by_table` comes from `rules.tables_in`, which matches identifiers
    against the workspace's table list rather than parsing KQL. A rule that
    reaches a table through a FUNCTION -- `MyUnionFunction()` -- names no table
    the matcher can see, so that table appears here as unread when a rule does
    read it. The matcher errs toward naming fewer tables, which is the safe
    direction for its own job and the unsafe one for this.

    `read_elsewhere` is the second: Defender XDR tables are read by Defender's
    own detections, not by Sentinel analytics rules. Listing 41 GB of
    DeviceFileEvents as "no rule reads this" is true and useless -- the product
    that owns the data reads it. Callers pass the XDR family tables here and
    they are excluded.

    SCAN_READS is the same exclusion turned on this tool. Pylon reads the two
    Sentinel health tables itself, on every run, to produce the rule-execution
    and connector sections of this very report. On the tenant this was written
    against SentinelHealth was 256 MB -- the largest entry in the list and 57%
    of its headline -- while being both free and read. Leaving it in made the
    one number a reader takes away from this section wrong twice over.

    `billable_megabytes` is carried through separately because volume and cost
    are different questions with different answers. It comes from the Usage
    meter's own IsBillable column, which is the workspace's answer to what it
    is charged for, not an inference from a price list.
    """
    skip = (read_elsewhere or set()) | SCAN_READS
    out = []
    for table in tables or []:
        name = table.get("table_name")
        if not name or name in skip or rules_by_table.get(name):
            continue
        megabytes = table.get("megabytes")
        # A table the Usage meter did not price is not a table with no volume.
        # Sorting it as zero would bury it under tables that measured smaller.
        out.append({"table": name, "megabytes": megabytes,
                    "billable_megabytes": table.get("billable_megabytes"),
                    "billable": table.get("billable"),
                    "tier": table.get("table_tier"),
                    "measured": megabytes is not None})
    # Ordered by what it costs, then by what it is. A reader acting on this
    # section acts on the bill, and the free entries sort to the bottom
    # together rather than interleaving with the ones worth an argument.
    return sorted(out, key=lambda t: (not t["measured"],
                                      -(t["billable_megabytes"] or 0),
                                      -(t["megabytes"] or 0), t["table"]))


def group_dead_rules(rule_detail: list[dict], with_data: set[str]) -> list[dict]:
    """Rules that cannot fire, grouped by the empty tables they read.

    Twenty-six rows one per rule made a reader count thirteen problems where
    the tenant had two empty tables. Grouping them says the same thing once.

    Grouped by FACT, not by cause. The key is "the tables this rule reads that
    hold no data" -- something measured. It is tempting to write "8 rules
    cannot fire BECAUSE AKSAudit is empty", and for a rule reading one empty
    table that is true; for a rule reading two tables where one is empty it is
    a guess, because the other may be full of rows that simply do not match.
    So the heading states what was observed and lets the reader draw the
    conclusion.

    A rule that matched nothing while every table it reads HAS data gets its
    own group, and the note under it names two possibilities rather than one.

    The query is not broken: a rule whose query failed is reported as broken
    elsewhere, so anything reaching this group RAN and returned nothing. That
    is either a condition matching nothing in the table, or a rule correctly
    watching for something that has not happened. This file does not parse KQL
    and cannot tell those apart, so it says both. Folding these in with the
    others would invent a cause for the one case where none is known, and
    implying a fault would send somebody to fix a rule that is fine.
    """
    groups: dict[tuple, dict] = {}
    for rule in rule_detail:
        if rule.get("rule_health_status") != "never-fires":
            continue
        tables = list(rule.get("tables_referenced") or [])
        empty = tuple(sorted(t for t in tables if t not in with_data))
        slot = groups.setdefault(empty, {"tables": list(empty), "names": []})
        slot["names"].append(rule.get("name") or "(unnamed)")

    out = []
    for key, slot in groups.items():
        slot["names"].sort()
        slot["count"] = len(slot["names"])
        # No empty table among the ones it reads: everything it needs is
        # arriving and it still matched nothing.
        slot["unexplained"] = not key
        out.append(slot)
    # Biggest group first; the unexplained one last, because it is the one
    # with no shared fix behind it.
    return sorted(out, key=lambda g: (g["unexplained"], -g["count"],
                                      g["tables"]))


def coverage_of_reads(reads: dict) -> list[tuple[str, bool, str]]:
    """(question, answered, why not) for each read, worst first.

    A professional report says what it looked at AND what it could not. This
    codebase already records both per leg; nothing was rendering the second
    half where a reader would see it, so a scan missing four of its twelve
    reads produced a document that looked complete.

    Unanswered first, because those are the ones that change how everything
    above should be read.
    """
    rows = []
    for key, question in READ_LABEL.items():
        state = reads.get(key) or {}
        rows.append((question, bool(state.get("ran")),
                     (state.get("detail") or "").strip()))
    return sorted(rows, key=lambda r: (r[1], r[0]))


def gap_facts(res_rows: list[dict], coverage_gaps: list[dict],
              rules_by_table: dict) -> dict[str, dict]:
    """{resource type: what its gaps cost}.

    Two things a reader needs and the census cannot give: which deployed rules
    stop working because of this gap, and what to switch on to close it. Both
    are already in the document -- a gap names the table it would feed and the
    categories that feed it, and a rule names the tables it reads -- and
    nothing had joined them per resource type.

    Rules are counted by name, not per gap. Ten storage accounts feeding one
    table that one rule reads blocks ONE rule, not ten.
    """
    kind_of = {r["resource_id"]: r["resource_type"] for r in res_rows}
    out: dict[str, dict] = {}
    for gap in coverage_gaps or []:
        kind = kind_of.get(gap.get("resource_id"))
        if not kind:
            continue
        slot = out.setdefault(kind, {"tables": set(), "cats": set(),
                                     "rules": set(), "assumed": False,
                                     "reasons": set()})
        if gap.get("dark_reason"):
            slot["reasons"].add(gap["dark_reason"])
        # One gap in the group with an assumed table name is enough to mark
        # the step. Marking only when EVERY gap is assumed would let a single
        # measured resource vouch for nine that were not.
        if gap.get("mode_basis") != "measured":
            slot["assumed"] = True
        table = gap.get("expected_table")
        if table:
            slot["tables"].add(table)
            for rule in rules_by_table.get(table) or []:
                slot["rules"].add(rule.get("name") or rule.get("rule_id"))
        slot["cats"].update(gap.get("categories_to_enable") or [])
    return out


def headline(res_rows: list[dict], by_type: dict, rule_detail: list[dict],
             plans: list[dict] | None, tables_checked,
             facts: dict[str, dict] | None = None) -> dict:
    """What goes above every table: one finding, then where to start.

    The first version of this was four sentences of equal weight stacked in a
    box. Every one was true and the reader still had to work out which mattered
    and what to do, which is the job a summary exists to do for them.

    So it is now shaped like a finding: the state in one line, the second fact
    that changes what you do, and an ordered list of the largest groups with
    the count each fix covers.

    Rules kept from the first version. Every figure comes from a section below
    -- nothing here measures anything -- and a figure that is missing produces
    no line rather than a confident one. No verdict either: "your logging
    posture is poor" is not a measurement and a reader who disagrees has no way
    to check it. Counts they can check.
    """
    out: dict = {"lead": "", "second": "", "actions": [], "caveat": ""}

    dark = [r for r in res_rows
            if r.get("logging_status") in ("not-enabled", "partial-enabled")]
    if res_rows and dark:
        out["lead"] = (f"{len(dark)} of {len(res_rows)} resources have no "
                       f"diagnostic setting sending to this workspace.")

    # The fact that changes what you do, rather than another count of the same
    # thing. A rule that cannot fire is a detection the tenant believes it has.
    cannot_fire = [r for r in rule_detail
                   if r.get("rule_health_status") == "never-fires"]
    if rule_detail and cannot_fire:
        out["second"] = (f"{len(cannot_fire)} of {len(rule_detail)} analytics rules "
                         f"read tables with no ingestion and cannot fire.")

    # Where one change covers the most resources. Three, because a list of
    # thirteen is the table below it with extra steps.
    covered_by_defender: dict[str, int] = {}
    for plan in plans or []:
        if plan.get("enabled") or not (plan.get("protects") or 0):
            continue
        for kind, n in (plan.get("matching_resources") or {}).items():
            covered_by_defender[kind] = max(covered_by_defender.get(kind, 0), n)

    # Ordered by what the gap COSTS, not by how many rows it fills. Ten dead
    # storage accounts nobody has written a rule against matter less than one
    # gap stopping three deployed detections, and a list sorted by count says
    # the opposite. Count breaks the tie, because among gaps that block the
    # same number of rules the bigger group is the better first move.
    facts = facts or {}

    def cost(item):
        kind, d = item
        fact = facts.get(kind) or {}
        # A step nobody can act on is not a place to start, however many
        # resources are in it. A real report put "5 datacollectionrules" third
        # with no cost, no fix and nothing under it -- it read as the section
        # having run out mid-sentence.
        actionable = 0 if fact.get("cats") else 1
        return (actionable, -len(fact.get("rules") or ()),
                -(d["off"] + d["partial"]), kind)

    ranked = sorted(((k, d) for k, d in by_type.items() if d["off"] + d["partial"]),
                    key=cost)
    for kind, d in ranked[:3]:
        gap = d["off"] + d["partial"]
        fact = facts.get(kind) or {}
        name = type_phrase(kind, gap).split(" ", 1)[1]
        alt = ""
        if covered_by_defender.get(kind):
            alt = ("A disabled Defender plan covers these too, with no "
                   "diagnostic setting to configure.")

        # What to switch on. Capped, because a step listing twenty categories
        # is a step nobody reads -- the table below carries the full set.
        cats = sorted(fact.get("cats") or ())
        how = ""
        if cats:
            shown = ", ".join(cats)
            more = ""
            tables = sorted(fact.get("tables") or ())
            into = f" → {tables[0]}" if len(tables) == 1 else ""
            # The table name is the documented default when no setting exists
            # to read the mode from. Said out loud, because a reader who acts
            # on a guessed table name and finds the logs elsewhere stops
            # believing the measured numbers too.
            # Short, because it repeats on every step and the long form read
            # as three lines of the same caveat. "assumed" beside a table name
            # says the thing; the Method section carries the why.
            note = " (assumed)" if into and fact.get("assumed") else ""
            how = f"Enable {shown}{more}{into}{note}"

        # Nothing to switch on means nothing was mapped for this type. Say
        # that, rather than leaving a bare count under a heading promising a
        # next step: "we could not work out the fix" is a fact a reader can
        # act on, and silence is not.
        if not how:
            reasons = sorted(fact.get("reasons") or ())
            how = (f"{reasons[0].capitalize()}. No categories mapped for this "
                   f"resource type — see the log-gap table."
                   if reasons else
                   "Not enough detail to name a fix. See the table below.")

        blocked = sorted(fact.get("rules") or ())
        out["actions"].append({"count": gap, "what": name, "alt": alt,
                               "how": how, "blocks": blocked})

    # Said last and said plainly. A reader who does not know half the document
    # is missing reads the other half as the whole picture.
    if tables_checked is None:
        out["caveat"] = ("Table activity was not measured on this run, so nothing "
                         "below says whether data is arriving — only whether "
                         "logging is switched on.")
    return out


def stat(value) -> str:
    """A headline number, or a mark saying it was never measured.

    `None` means the leg did not run. Dropped into an f-string it renders as
    the word "None", which sits in the same slot as a count and reads like one
    -- a report that had measured nothing announced "None tables with data",
    which a reader takes as zero. That is the one direction this document is
    not allowed to be wrong in, and it was wrong in it on the first real run.
    """
    return "—" if value is None else str(value)


def row_state(r: dict) -> tuple[str, str]:
    """(label, css class) for a row.

    A null `logging_status` means one of two different things and the label
    has to say which: `out_of_scope` is nothing to switch on, while
    `not_assessed` is a question this scan could not answer. Reporting the
    second as the first claims a resource is fine when it was never measured.
    """
    if r.get("logging_status") is None and r.get("assessment_status") == "not_assessed":
        return "Not assessed", "partial"
    status = r.get("logging_status")
    return STATE_LABEL[status], STATE_CLASS[status]
STATE_CLASS = {"fully-enabled": "ok", "partial-enabled": "partial",
               "not-enabled": "none", None: "void"}
# Plain names for the ARM types a Defender plan protects, so the summary reads
# as things rather than as provider strings.
TYPE_LABEL = {
    "microsoft.storage/storageaccounts": "storage accounts",
    "microsoft.compute/virtualmachines": "virtual machines",
    "microsoft.hybridcompute/machines": "Arc machines",
    "microsoft.keyvault/vaults": "key vaults",
    "microsoft.web/sites": "web apps",
    "microsoft.sql/servers": "SQL servers",
    "microsoft.containerservice/managedclusters": "Kubernetes clusters",
    "microsoft.containerregistry/registries": "container registries",
    "microsoft.documentdb/databaseaccounts": "Cosmos DB accounts",
    "microsoft.apimanagement/service": "API Management services",
    "microsoft.cognitiveservices/accounts": "AI services",
    # Added after a real report said "3 virtualnetworks" and "5
    # datacollectionrules". The ARM tail is the machine's name for a thing;
    # a summary is read out loud.
    "microsoft.network/virtualnetworks": "virtual networks",
    "microsoft.network/networksecuritygroups": "network security groups",
    "microsoft.network/publicipaddresses": "public IP addresses",
    "microsoft.network/bastionhosts": "Bastion hosts",
    "microsoft.insights/datacollectionrules": "data collection rules",
    "microsoft.insights/components": "Application Insights components",
    "microsoft.operationalinsights/workspaces": "Log Analytics workspaces",
    "microsoft.operationsmanagement/solutions": "management solutions",
    "microsoft.automation/automationaccounts": "Automation accounts",
    "microsoft.logic/workflows": "Logic Apps",
    "microsoft.app/managedenvironments": "Container Apps environments",
}

# Sentinel connectors are identified by a GUID in their resource id. The
# connector KIND is the thing a reader recognises, so it is shown instead.
# Tenant- and subscription-scope rows are not resources, and their ARM ids
# ("microsoft.aadiam/diagnosticSettings") name a mechanism rather than a thing
# a reader recognises.
SOURCE_LABEL = {
    "microsoft.aadiam/tenant": "Entra ID",
    "microsoft.resources/subscriptions": "Activity Log",
}

CONNECTOR_LABEL = {
    "microsoftcloudappsecurity": "Microsoft Defender for Cloud Apps",
    "office365": "Office 365",
    "microsoftthreatprotection": "Microsoft Defender XDR",
    "microsoftdefenderadvancedthreatprotection": "Microsoft Defender for Endpoint",
    "azureactivedirectory": "Microsoft Entra ID",
    "azureactivedirectoryidentityprotection": "Entra ID Protection",
    "azuresecuritycenter": "Microsoft Defender for Cloud",
    "threatintelligence": "Threat Intelligence",
    "azureadvancedthreatprotection": "Microsoft Defender for Identity",
    "officeatp": "Microsoft Defender for Office 365",
}

SCOPE_LABEL = {"tenant": "Tenant", "subscription": "Subscription",
               "resource": "Resource", "data_plane": "Data plane",
               "sentinel": "Sentinel"}
SCOPE_BLURB = {
    "tenant": "Identity — who signed in.",
    "subscription": "Control plane — who changed Azure.",
    "resource": "What each resource emits about itself.",
    "data_plane": "Who touched the data inside a resource.",
    "sentinel": "Whether the SIEM is wired to receive it.",
}
# The model's `dark_reason` vocabulary is precise about the CATEGORY but not
# about the job. Those two situations -- no setting at all, and a setting with
# this category unticked -- are different pieces of work, and used to share the
# reason "never configured": this table keyed on (reason, has_setting) to tell
# them apart. The document now carries the distinction itself, so a plain lookup
# is enough and nothing downstream has to reconstruct it.
ACTION = {
    "no diagnostic setting": ("No diagnostic setting",
                              "Nothing is configured on this resource. Create a setting."),
    "category not enabled": ("Setting exists, category off",
                             "A setting already sends to this workspace. Tick the category on it."),
    "ships elsewhere": ("Sending to another workspace",
                        "Logging works, but not to here. Add this workspace as a destination."),
    "metrics only, no log categories": ("Metrics only",
                                        "A setting exists but collects no logs. Enable log categories."),
    "configured here — idle in the window": ("Configured, nothing arrived",
                                             "Set up correctly and silent. Investigate the resource."),
    "settings unreadable": ("Settings could not be read",
                            "The scan could not check. Verify permissions."),
}


def type_phrase(kind: str, n: int) -> str:
    """`3 key vaults`, `1 key vault`.

    TYPE_LABEL where there is one, because the ARM tail gives
    "storageaccounts", which is the machine's name for a thing and not a
    phrase anyone says out loud.

    Every label in TYPE_LABEL is a regular plural, so dropping the final "s"
    is enough. There is no vaults/vaulti case to get wrong, and a real
    inflection library for eleven strings would be the worse answer.
    """
    name = TYPE_LABEL.get(kind) or kind.split("/")[-1]
    if n == 1 and name.endswith("s"):
        name = name[:-1]
    return f"{n} {name}"


def classify(reason: str) -> tuple[str, str]:
    """(label, what to do) for one dark reason.

    Took a `has_setting` flag until the reason itself carried the distinction.
    A parameter that exists only to disambiguate a value is a sign the value is
    under-specified; deleting it is the point of having split the vocabulary.
    """
    return ACTION.get(reason) or (reason, "")


def group_by_type(res_rows: list[dict]) -> dict[str, dict]:
    """{resource type: a census of its logging state}.

    Module-level rather than inline in `build` so it can be tested. Every bug
    this file has had was in counting, not in HTML, and counting is the half
    that a test can hold still.

    Only rows where logging is a QUESTION are counted. A resource with nothing
    to switch on (`out_of_scope`) is not a gap, and including it would make
    every "3 of 10" here quietly wrong in the reassuring direction. A row the
    scan could not answer for (`not_assessed`) IS counted, in its own column,
    because "could not check" is not "clean".
    """
    by_type: dict[str, dict] = {}
    for r in res_rows:
        status = r.get("logging_status")
        if status is None and r.get("assessment_status") != "not_assessed":
            continue
        slot = by_type.setdefault(r["resource_type"],
                                  {"total": 0, "off": 0, "partial": 0,
                                   "on": 0, "unknown": 0, "names": []})
        slot["total"] += 1
        if status == "not-enabled":
            slot["off"] += 1
            slot["names"].append(short(r["resource_id"]).split("/")[-1])
        elif status == "partial-enabled":
            slot["partial"] += 1
            slot["names"].append(short(r["resource_id"]).split("/")[-1])
        elif status == "fully-enabled":
            slot["on"] += 1
        else:
            slot["unknown"] += 1
    return by_type


def build(a: dict, plans: list[dict] | None,
          eps: dict | None, verdicts: list[dict] | None = None,
          rules_detail: list[dict] | None = None) -> str:
    s = a["summary"]
    reads = a["reads"]
    resources = a["resources"]
    by_scope = collections.defaultdict(list)
    for r in resources:
        # XDR families are sentinel-scope rows in the document but have a
        # section of their own, so repeating them here would say the same
        # thing twice and in a worse form.
        if "/xdrfamilies/" in r["resource_type"]:
            continue
        by_scope[r["scope"]].append(r)

    res_rows = by_scope.get("resource", [])
    res_states = collections.Counter(r["logging_status"] for r in res_rows)

    # ---- what is not logging, grouped by resource type ---------------------
    # This was an exposure ranking: "N of M resources that are not logging can
    # be reached from outside". It needed three paragraphs of caveats to avoid
    # misleading -- reachable is not anonymous, a VM's reachability is an NSG
    # rule this scan does not read, and the privilege half of the ranking was
    # identical on every row -- and after all of them it still did not say what
    # to go and do.
    #
    # Grouped by type it needs none of that. "Nine of your ten storage accounts
    # are not logging" is a sentence someone can act on, and it is true without
    # qualification. Reachability is still measured and still in analysis.json;
    # it is just not the axis this table sorts on.
    dark = [r for r in res_rows
            if r["logging_status"] in ("not-enabled", "partial-enabled")]

    by_type = group_by_type(res_rows)

    # Most work first, then the types nobody could check, then the clean ones.
    # A type with nothing wrong is still listed -- the point is a census of
    # where you stand, and a type that vanishes when it is healthy makes the
    # list mean something different every run.
    type_rows_sorted = sorted(
        by_type.items(),
        key=lambda kv: (-(kv[1]["off"] + kv[1]["partial"]),
                        -kv[1]["unknown"], kv[0]))

    def type_row(rtype: str, d: dict) -> str:
        # The chip counts only what was actually checked. The first render of
        # this table gave a Windows VM nobody could assess the chip "all
        # logging", because zero gaps out of one resource is zero gaps -- which
        # is the exact confusion the rest of this codebase exists to refuse.
        # Not being able to look is not a clean bill of health, so unassessed
        # resources are held out of the denominator and named separately.
        checked = d["total"] - d["unknown"]
        missing = d["off"] + d["partial"]
        if checked == 0:
            chip = '<span class="chip chip--void">not assessed</span>'
        elif missing == 0:
            chip = f'<span class="chip chip--ok">all {checked} configured</span>'
        elif missing == checked:
            chip = f'<span class="chip chip--none">0 of {checked} configured</span>'
        else:
            chip = (f'<span class="chip chip--partial">{missing} of {checked} '
                    f'not configured</span>')
        # The names, so the row is a place to start rather than a statistic.
        # Every one of them: a list that stops at eight and says "+2 more" is
        # hiding the resources a reader has to go and fix. Nothing in this
        # document is truncated for length any more, for the same reason.
        names = (f'<div class="rule-names">{e(", ".join(d["names"]))}</div>'
                 if d["names"] else "")
        unknown = (f'<div class="more">+{d["unknown"]} not assessed</div>'
                   if d["unknown"] else "")
        return f"""
      <tr>
        <td>{e(rtype)}{names}</td>
        <td>{checked}{unknown}</td>
        <td>{chip}</td>
      </tr>"""

    exp_rows = "".join(type_row(k, v) for k, v in type_rows_sorted)
    # The denominator the table's own rows add up to, computed here rather than
    # taken from `summary`. `dark_resources` up in Coverage counts `not-enabled`
    # only; this section also counts `partial-enabled`, so the two numbers are
    # legitimately different and sit two inches apart. A heading that borrowed
    # the other one would make the table below it look like it could not add.
    loggable_here = sum(d["total"] - d["unknown"] for _, d in type_rows_sorted)

    # The privileged-role notes that used to sit under this table are gone.
    # Both were true and neither was usable: the first said three roles are
    # assigned at subscription scope and therefore separate none of these rows,
    # and the second said the count is a floor. A caveat about a measurement
    # that changes no row is noise in a table about what to go and fix. The
    # measurement is still made and still in analysis.json.

    # ---- fix list: what to switch on, and what it turns on -----------------
    rules_by_table = collections.defaultdict(list)
    for r in a.get("rules") or []:
        for t in r["tables_referenced"]:
            rules_by_table[t].append(r)
    live_tables = {t["table_name"]: t for t in (a.get("tables") or [])}

    by_id = {row["resource_id"]: row for row in (verdicts or [])}

    def scope_name(r: dict) -> str:
        """A recognisable name for a non-resource row, plus what is on.

        A data connector's resource id is a GUID, which tells a reader
        nothing. Its kind does.
        """
        rtype = r["resource_type"]
        if rtype.startswith("microsoft.securityinsights/settings/"):
            v = by_id.get(r["resource_id"]) or {}
            name = r["resource_id"].rsplit("/", 1)[-1]
            conns = v.get("connectors_detail") or []
            if conns:
                # One line per connector, so a stalled one is not buried in a
                # run-on list beside a healthy one.
                lines = "".join(
                    f'<div><span class="chip chip--{"ok" if c.get("healthy") else "none"}">'
                    f'{"Healthy" if c.get("healthy") else "Not healthy"}</span> '
                    f'{e(c["name"])} '
                    f'<code>{e(str(c["newest"])[:16].replace("T", " "))}</code></div>'
                    for c in conns)
                well = sum(1 for c in conns if c.get("healthy"))
                return (f"<strong>{e(name)}</strong>"
                        f'<span class="more">{well} of '
                        f'{plural(len(conns), "connector")} healthy</span>'
                        f'<div class="stack">{lines}</div>')
            # Inline, so the status chip, the name and the reason read as one
            # line rather than stacking.
            return (f"<strong>{e(name)}</strong>"
                    f'<span class="more">{e(v.get("basis") or "")}</span>')
        if rtype.startswith("microsoft.securityinsights/dataconnectors/"):
            kind = rtype.rsplit("/", 1)[-1]
            name = CONNECTOR_LABEL.get(kind, kind)
            v = by_id.get(r["resource_id"]) or {}
            on, avail = v.get("enabled") or [], v.get("available") or []
            off = [x for x in avail if x not in on]
            bits = []
            if on:
                bits.append("on: " + ", ".join(on))
            if off:
                bits.append("off: " + ", ".join(off))
            tail = (f'<span class="more">{e(" · ".join(bits))}</span>'
                    if bits else "")
            return f"<strong>{e(name)}</strong> {tail}"
        label = SOURCE_LABEL.get(rtype)
        if label:
            v = by_id.get(r["resource_id"]) or {}
            on = v.get("enabled") or []
            groups = v.get("groups") or []
            avail = v.get("available") or []
            # `allLogs` is defined as every category the scope emits, so it
            # is complete and nothing is missing. Any other group cannot be
            # resolved -- Azure does not publish membership at these scopes --
            # so the group is named and no gap is claimed either way.
            if "allLogs" in groups:
                head, missing = "all categories (allLogs)", []
            elif groups:
                head = f"{', '.join(groups)} category group"
                missing = []
            else:
                missing = sorted(set(avail) - set(on))
                head = (f"{len(on)} of {len(avail)} categories" if avail
                        else f"{len(on)} categories")
            gap = ""
            if on:
                gap += ('<div class="stack"><div>Enabled: '
                        f'{e(", ".join(sorted(on)))}</div></div>')
            if missing:
                shown = ", ".join(missing)
                more = f" +{len(missing) - 6} more" if len(missing) > 6 else ""
                # Append: the enabled list is already in `gap` and assigning
                # here would drop it.
                gap += ('<div class="stack"><div>Not enabled: '
                        f"{e(shown)}{e(more)}</div></div>")
            return (f"<strong>{e(label)}</strong>"
                    f'<span class="more">{e(head)}</span>{gap}')
        return f'<code>{e(short(r["resource_id"]))}</code>'

    fixes = collections.defaultdict(
        lambda: {"n": 0, "cats": set(),
                 "reasons": collections.defaultdict(list)})
    for g in a.get("coverage_gaps") or []:
        f = fixes[g["expected_table"]]
        f["n"] += 1
        f["cats"].update(g["categories_to_enable"])
        # Keep which resources sit behind each reason, not just how many. When
        # a table is dark for two different reasons, the useful thing is which
        # resource needs which action.
        label, _ = classify(g["dark_reason"])
        f["reasons"][label].append(short(g["resource_id"]).split("/")[-1])
    ranked = sorted(fixes.items(),
                    key=lambda kv: (-len(rules_by_table.get(kv[0], [])), -kv[1]["n"]))


    # ---- sections ---------------------------------------------------------
    fix_rows = []
    for table, f in ranked:
        unlocks = rules_by_table.get(table, [])
        fed = table in live_tables
        seen = (live_tables.get(table) or {}).get("last_ingest")
        # Not "never": only the window was queried. Saying never would claim
        # more than was measured.
        seen_cell = (f'<code>{e(seen[:16].replace("T", " "))}</code>' if seen
                     else f'<span class="muted">none in {a["window_days"]}d</span>')
        # One reason needs no breakdown -- the Resources column already gives
        # the count. Two or more do, because the fix differs per resource, and
        # naming the resource beats counting it.
        by_reason = sorted(f["reasons"].items(), key=lambda kv: -len(kv[1]))
        if len(by_reason) == 1:
            reason = e(by_reason[0][0])
        else:
            reason = "<br>".join(
                f'{e(r)}<div class="rule-names">'
                + e(", ".join(sorted(names)))
                + "</div>"
                for r, names in by_reason)
        fix_rows.append(f"""
      <tr>
        <td><code>{e(table)}</code>
            <span class="chip chip--{'ok' if fed else 'void'}">{'has data' if fed else 'empty'}</span></td>
        <td class="detail">{seen_cell}</td>
        <td class="num">{f['n']}</td>
        <td class="cats">{", ".join(f'<code>{e(c)}</code>' for c in sorted(f['cats']))}</td>
        <td>{reason}</td>
        <td class="unlock">{('<strong>' + str(len(unlocks)) + '</strong> rule' + ('s' if len(unlocks) != 1 else '')) if unlocks else '<span class="muted">—</span>'}
            {'<div class="rule-names">' + '<br>'.join(e(u['name']) for u in unlocks) + '</div>' if unlocks else ''}</td>
      </tr>""")

    scope_rows = []
    for scope in ["tenant", "subscription", "resource", "data_plane", "sentinel"]:
        rows = by_scope.get(scope)
        if not rows:
            continue
        counts = collections.Counter(r["logging_status"] for r in rows)
        if scope == "resource":
            detail = bar([(STATE_LABEL[k], counts.get(k, 0), STATE_CLASS[k])
                          for k in STATE_ORDER])
        else:
            detail = "".join(
                f'<div class="one"><span class="chip chip--{row_state(r)[1]}">'
                f'{e(row_state(r)[0])}</span>'
                f'{scope_name(r)}</div>' for r in rows)
        scope_rows.append(f"""
      <section class="scope">
        <div class="scope__head">
          <h3>{e(SCOPE_LABEL[scope])}</h3>
          <p>{e(SCOPE_BLURB[scope])}</p>
        </div>
        <div class="scope__body">{detail}</div>
      </section>""")


    # Rules are the tenant's own; templates are Microsoft content sitting in
    # Content Hub. Conflating them is what made the counts unreadable.
    rule_detail = rules_detail or []
    custom_n = sum(1 for r in rule_detail if not r.get("_template"))
    tpl_n = sum(1 for r in rule_detail if r.get("_template"))

    # Chip colour is a HEALTH scale: green/amber/red/grey. Origin is not a
    # health state, so it is plain text -- an amber "Yours" read as a warning
    # against every rule the tenant wrote itself.
    HEALTH_CLASS = {"fires": "ok", "never-fires": "none", "broken": "none",
                    "unreadable": "partial", "inconclusive": "partial",
                    "not-assessed": "void"}
    # The raw status words are this codebase's vocabulary, not a reader's.
    # "never-fires" is a hyphenated verb phrase, and "unreadable" sounds like
    # a claim about the rule when it is an admission about the scan. Each says
    # what happened, in the order a reader needs it: the verdict, then who it
    # is about.
    HEALTH_LABEL = {
        "fires": "Matched data",
        "never-fires": "Cannot fire",
        "broken": "Query rejected",
        "unreadable": "Not tested",
        "inconclusive": "Inconclusive",
        "not-assessed": "Not tested",
    }
    # Worst first. A table sorted alphabetically buries the rules that do not
    # work among the ones that do, and the reader has to find them.
    HEALTH_ORDER = {"never-fires": 0, "broken": 1, "inconclusive": 2,
                    "unreadable": 3, "not-assessed": 4, "fires": 5}
    def _reads_cell(rule: dict) -> str:
        """What to print when no table was resolved for a rule.

        This said "no KQL" for both of the cases below, and only one of them is
        that. A rule whose query is a call to a saved KQL function -- an ASIM
        parser, a Content Hub solution's parser, a custom-log parser -- names no
        table in its own text, because the table is inside the function body and
        the function lives elsewhere on the workspace. Microsoft's own guidance
        is to write rules that way, so this is common rather than exotic.

        The scan reads rule text and does not open functions, so it cannot see
        those tables. Saying "no KQL" about a rule that plainly HAS a query
        reports a limitation of the scan as a fact about the tenant, which is
        the one mistake this codebase exists to prevent. Named for what it is.
        """
        if not rule.get("_query"):
            return '<span class="muted">no KQL</span>'
        return ('<span class="muted" title="The query names no table directly. '
                'It most likely calls a saved KQL function, such as an ASIM '
                'parser, whose body this scan does not read.">not resolved</span>')

    rule_rows_html = "".join(f"""
      <tr>
        <td>{e(r['name'][:52])}</td>
        <td class="detail">{'From template' if r.get('_template') else 'Yours'}</td>
        <td><span class="chip chip--{HEALTH_CLASS.get(r['rule_health_status'], 'void')}">
            {e(HEALTH_LABEL.get(r['rule_health_status'], 'Not tested'))}</span>
            {f'<div class="rule-names">{e(r["health_detail"][:110])}</div>' if r.get('health_detail') else ''}</td>
        <td class="cats">{", ".join(f'<code>{e(t)}</code>' for t in r['tables_referenced']) or _reads_cell(r)}</td>
      </tr>""" for r in sorted(rule_detail,
                              key=lambda x: (HEALTH_ORDER.get(x['rule_health_status'], 9),
                                             x['name'])))
    def dead_group(g: dict) -> str:
        shown = ", ".join(g["names"])
        plural = "" if g["count"] == 1 else "s"
        if g["unexplained"]:
            head = (f'{g["count"]} analytics rule{plural} matched nothing, and every '
                    f'table '
                    f'{"it reads holds" if g["count"] == 1 else "they read holds"} '
                    f'data')
            why = ("Every table these read is receiving data, so the query ran "
                   "against real logs and matched none of them. Either a "
                   "condition does not match what is in the table, or the rule "
                   "is watching for something that has not happened here.")
        else:
            head = (f'{g["count"]} analytics rule{plural} read '
                    f'{", ".join(g["tables"])}, which '
                    f'{"has" if len(g["tables"]) == 1 else "have"} no ingestion')
            why = ""
        note = f'<div class="more">{e(why)}</div>' if why else ""
        return (f'<div class="dead"><h4>{e(head)}</h4>'
                f'<div class="rule-names">{e(shown)}</div>'
                f'{note}</div>')

    # Health-monitoring findings, from the SentinelHealth read. Rendered with
    # the rules because that is what they are about; a reader looking at a rule
    # table wants to know which of those rules Sentinel switched off.
    health = (a.get("sentinel_health") or {})
    # From the RULE, not from health monitoring. The first version matched a
    # SentinelHealth `Reason` of "The analytics rule is disabled and was not
    # executed" -- Microsoft's own sample query for finding auto-disabled
    # rules. But that sentence fires for ANY disabled rule: one an analyst
    # switched off on Friday reads identically, and the heading above it said
    # Sentinel had done it after repeated failures. That is a claim the data
    # did not support.
    #
    # What Sentinel actually does, documented: it prepends "AUTO DISABLED" to
    # the rule's name and writes the reason into its description. The rename
    # is deliberate, it is unambiguous, and it arrives with the rule -- so this
    # works on a tenant with health monitoring switched off, which is most of
    # them.
    auto_off = [r for r in rule_detail if r.get("_auto_disabled")]
    failures = health.get("rule_failures") or []
    health_on = bool(health.get("enabled"))

    def off_row(rule: dict) -> str:
        # The reason Sentinel wrote into the description when it disabled the
        # rule. Shown because "it is off" without "here is why" is a finding
        # nobody can act on.
        why = (rule.get("_description") or "").strip()
        return (f'<div class="rule-names">{e(rule.get("name") or "(unnamed)")}'
                + (f'<span class="more">: {e(why[:160])}</span>' if why else "")
                + '</div>')

    off_block = "" if not auto_off else (
        f'<div class="dead"><h4>{len(auto_off)} analytics rule'
        f'{"" if len(auto_off) == 1 else "s"} disabled by Sentinel after '
        f'repeated permanent failures</h4>'
        + "".join(off_row(r) for r in auto_off)
        + '<div class="more">Sentinel renamed these and switched them off. '
          'They are not running.</div></div>')

    fail_block = "" if not failures else (
        '<div class="dead"><h4>'
        + f'{sum(f["runs"] for f in failures)} failed rule run'
        + ("" if sum(f["runs"] for f in failures) == 1 else "s")
        + f' across {len(failures)} reason'
        + ("" if len(failures) == 1 else "s") + '</h4>'
        + "".join(f'<div class="rule-names">{e(f["reason"])} '
                  f'<span class="more">{plural(f["runs"], "run")}, '
                  f'{plural(f["rules"], "rule")}</span></div>'
                  for f in failures)
        + '</div>')

    # Three findings that live inside runs Sentinel calls successful, so no
    # failure count reaches them. Each renders only when its read ran; a query
    # that errored says nothing rather than saying "none".
    def names(rows: list[dict], label) -> str:
        return "".join(f'<div class="rule-names">{e(label(r))}</div>'
                       for r in rows)

    below = health.get("below_threshold") or []
    thresh_block = "" if not below else (
        f'<div class="dead"><h4>{len(below)} analytics rule'
        f'{"" if len(below) == 1 else "s"} matched rows but never fired</h4>'
        + names(below, lambda r: (
            f'{r["rule"]}: {r["matched"]} rows matched over '
            f'{r["runs"]} runs, threshold '
            f'{r["operator"]} {stat(r["threshold"])}'))
        + '<div class="more">The threshold sits above what the query finds, so '
          'nothing is raised. Check whether that was intended.</div></div>')

    drops = health.get("entity_drops") or []
    drop_block = "" if not drops else (
        f'<div class="dead"><h4>{len(drops)} analytics rule'
        f'{"" if len(drops) == 1 else "s"} raised alerts with entities '
        f'missing</h4>'
        + names(drops, lambda r: f'{r["rule"]}: {r["dropped"]} entity drops '
                                 f'over {r["runs"]} runs')
        + '<div class="more">These alerts arrived with no user, host or IP '
          'attached. They still fired, so nothing looks broken.</div></div>')

    skips = health.get("skipped_windows") or []
    skip_block = "" if not skips else (
        f'<div class="dead"><h4>'
        f'{plural(sum(r["windows"] for r in skips), "detection window")} '
        f'{"was" if sum(r["windows"] for r in skips) == 1 else "were"} never '
        f'searched</h4>'
        + names(skips, lambda r: f'{r["rule"]}: {plural(r["windows"], "window")}')
        + '<div class="more">A scheduled rule gets six attempts at a window. '
          'These failed all six. That time was never examined and will not be '
          'revisited.</div></div>')

    # The one that has to be said when the others are silent. Health monitoring
    # is off by default and only collects from the moment it is switched on, so
    # an empty result here means the feature is off -- NOT that nothing failed.
    health_off_block = "" if health_on else (
        '<div class="dead"><h4>Rule failures were not measured</h4>'
        '<div class="more">Sentinel health monitoring is off, so this scan '
        'cannot tell a rule that never failed from one failing every run. '
        'Turn it on in Sentinel &rsaquo; Settings &rsaquo; Auditing and health '
        'monitoring. Ingesting SentinelHealth is free; SentinelAudit is '
        'billed as ordinary log volume. Both collect from the moment they '
        'are switched on, not retroactively.'
        '</div></div>')

    dead = group_dead_rules(rule_detail, set(live_tables))
    dead_block = ("" if not dead else
                  '<div class="deadlist">'
                  + "".join(dead_group(g) for g in dead) + "</div>")

    # The health findings are NOT gated on the rules table. They were, and a
    # test caught it: a rule Sentinel auto-disabled is exactly the case where
    # the rules list may be short or empty, so hiding the finding behind
    # "we have rules to show" hides it when it matters most. Same for
    # "health monitoring is off", which is most worth saying on a workspace
    # that looks quiet.
    findings = (f"{health_off_block}{off_block}{skip_block}{fail_block}"
                f"{thresh_block}{drop_block}{dead_block}")
    # Counted, not just labelled. One row reading "not resolved" is a curiosity;
    # eleven of forty means the coverage figures on this page are understated by
    # an amount the reader should know before acting on them.
    _unresolved = sum(1 for r in rule_detail
                      if r.get("_query") and not r["tables_referenced"])
    unresolved_note = "" if not _unresolved else (
        f'<p class="muted" style="margin-top:8px">'
        f'{_unresolved} rule{"s" if _unresolved != 1 else ""} shown as '
        f'<b>not resolved</b>: the query names no table directly, most likely '
        f'calling a saved KQL function such as an ASIM parser. This scan reads '
        f'rule text and does not open function bodies, so any table those rules '
        f'read is counted as unwatched below. Coverage here is a FLOOR.</p>')
    table = "" if not rule_detail else f"""
  <div class="scroll"><table>
    <thead><tr><th>Rule</th><th>Origin</th><th>Result</th><th>Reads</th></tr></thead>
    <tbody>{rule_rows_html}</tbody>
  </table></div>{unresolved_note}"""
    heading = (f"{sum(1 for r in rule_detail if r['rule_health_status'] == 'fires')}"
               f" of {len(rule_detail)} analytics rules returned rows when tested"
               if rule_detail else "Rule health")
    rules_block = "" if not (rule_detail or findings) else f"""
<section class="block">
  <div class="eyebrow">Analytics rules</div>
  <h2>{heading}</h2>
  {findings}{table}
</section>"""

    # ── rule execution ──────────────────────────────────────────────────────
    # What the coverage half above cannot say. It answers "can this rule fire",
    # from the tables it reads; this answers "is it running", from Sentinel's
    # own execution records. A tenant where every rule is healthy gets nothing
    # from the findings blocks above, because each renders only on a fault --
    # so the report goes quiet exactly when the customer wants proof.
    #
    # The sharp finding is the overlap: a rule can run thousands of times,
    # report success every time, and be searching a table with no data in it.
    # Success means the query ran, not that the rule can ever fire.
    runs = health.get("rule_runs") or []
    exec_block = ""
    if health.get("rule_runs_read") and runs:
        total_runs = sum(r["runs"] for r in runs)
        failed_runs = sum(r["failed"] for r in runs)
        by_name = {r["name"]: r for r in rule_detail}
        dead_names = {r["name"] for r in rule_detail
                      if r.get("tables_referenced")
                      and not any(t in live_tables for t in r["tables_referenced"])}
        wasted = [r for r in runs if r["rule"] in dead_names]
        wasted_runs = sum(r["runs"] for r in wasted)
        # Rules that ran but are not in the deployed list, and deployed rules
        # that wrote no execution record. Fusion is the second kind by design:
        # it has no KQL, so the service decides its health and it emits nothing.
        silent = [r for r in rule_detail if r["name"] not in {x["rule"] for x in runs}]

        def run_row(r: dict) -> str:
            rule = by_name.get(r["rule"]) or {}
            reads = [t for t in (rule.get("tables_referenced") or [])
                     if t not in live_tables]
            why = ("" if not reads else
                   f'<div class="rule-names">reads {e(", ".join(sorted(reads)))}, '
                   f'which {"holds" if len(reads) == 1 else "hold"} no data in '
                   f'this workspace</div>')
            chip = ('<span class="chip chip--ok">all success</span>'
                    if not r["failed"] else
                    f'<span class="chip chip--none">{r["failed"]:,} failed</span>')
            return (f'<tr><td>{e(r["rule"])}{why}</td>'
                    f'<td class="num">{r["runs"]:,}</td>'
                    f'<td class="num">{e(str(r["newest"])[:16].replace("T", " ")) if r["newest"] else ""}</td>'
                    f'<td class="detail">{chip}</td></tr>')

        wasted_finding = "" if not wasted else (
            f'<div class="deadlist"><div class="dead"><h4>{wasted_runs:,} of those '
            f'runs &mdash; {wasted_runs / total_runs * 100:,.0f}% of all rule execution '
            f'in the window &mdash; searched a table with no data</h4>'
            f'<div class="rule-names">{e(", ".join(sorted(x["rule"] for x in wasted)))}</div>'
            '<div class="more">Success here means the query ran, not that the '
            'rule can ever fire. Either the data these were written for is not '
            'arriving, or this tenant does not run the product they watch.'
            '</div></div></div>')

        silent_note = "" if not silent else (
            f'<p class="note">{plural(len(silent), "deployed rule")} wrote no '
            f'execution record: {e(", ".join(sorted(r["name"] for r in silent)))}. '
            'A Fusion rule has no KQL of its own and the service decides its '
            'health, so it reports none. That is expected, not a gap.</p>')

        exec_heading = (f'{len(runs)} of {len(rule_detail)} analytics rules ran '
                        f'{total_runs:,} times. '
                        + ("None failed." if not failed_runs else
                           f'{failed_runs:,} of those runs failed.'))
        exec_block = f"""
<section class="block">
  <div class="eyebrow">Rule execution</div>
  <h2>{exec_heading}</h2>
  {silent_note}
  {wasted_finding}
  <div class="scroll"><table>
    <thead><tr><th>Rule</th><th>Runs</th><th>Last run</th><th>Outcome</th></tr></thead>
    <tbody>{"".join(run_row(r) for r in runs)}</tbody>
  </table></div>
  <p class="note">Run counts differ because rules differ in frequency and in
     when they were created. A low count is not a fault on its own.</p>
</section>"""

    # ── connector health ────────────────────────────────────────────────────
    # The other half of the same read, and the one that answers "is data still
    # arriving" with a timestamp rather than a claim.
    conns = health.get("connectors") or {}
    conn_block = ""
    if conns:
        def conn_row(name: str, c: dict) -> str:
            bad = {k: v for k, v in c["statuses"].items()
                   if k not in ("Success", "Informational")}
            info = c["statuses"].get("Informational", 0)
            state = (f'<span class="chip chip--none">'
                     f'{e(", ".join(sorted(bad)))}</span>' if bad else
                     f'{info:,} informational' if info else
                     '<span class="chip chip--ok">all success</span>')
            return (f'<tr><td><code>{e(name)}</code></td>'
                    f'<td class="num">{c["events"]:,}</td>'
                    f'<td class="num">{e(str(c["newest"])[:16].replace("T", " "))}</td>'
                    f'<td class="detail">{state}</td></tr>')
        audit_words = (
            f'Auditing is on as well: <code>SentinelAudit</code> holds '
            f'{plural(health.get("audit_rows") or 0, "configuration change")}'
            + (f', the most recent on {e(str(health["audit_newest"])[:10])}'
               if health.get("audit_newest") else "") + '. '
            if health.get("audit_enabled") else
            '<code>SentinelAudit</code> is off, so changes to rules and '
            'connectors leave no trail in this workspace. ')
        conn_block = f"""
<section class="block block--ref">
  <div class="eyebrow">Connector health</div>
  <h2>{plural(len(conns), "connector")} reporting in</h2>
  <div class="scroll"><table>
    <thead><tr><th>Connector</th><th>Reports</th><th>Newest</th><th>Outcome</th></tr></thead>
    <tbody>{"".join(conn_row(n, conns[n]) for n in sorted(conns, key=lambda k: -conns[k]["events"]))}</tbody>
  </table></div>
  <p class="note">{audit_words}Health monitoring covers only the connectors
     Microsoft supports it for, so a connector absent here is not necessarily
     unhealthy. Ingesting <code>SentinelHealth</code> is free;
     <code>SentinelAudit</code> is billed as ordinary log volume.</p>
</section>"""

    # Defender: two tables, because "off with resources here" and "on" are
    # different reads and mixing them makes neither scannable.
    plan_block = ""
    if plans:
        def detects_cell(p):
            d = plan_detections.for_plan(p["plan"])
            if not d:
                return '<span class="muted">&mdash;</span>'
            # None means the reference does not enumerate alerts for this
            # plan, which is different from it having none.
            head = (f'<strong>{d["alert_types"]}</strong> documented alert types'
                    if d["alert_types"] is not None
                    else "alerts not enumerated in the reference")
            ex = "".join(f"<div>&middot; {e(x)}</div>" for x in d["examples"])
            tac = (f'<div class="rule-names">{e(", ".join(d["tactics"]))}</div>'
                   if d["tactics"] else "")
            return f'{head}{tac}<div class="rule-names">{ex}</div>'

        def status_chip(p):
            # Three states, not two. `pricingTier: Standard` covers both a plan
            # someone bought and the free baseline, and a disabled plan with an
            # untouched trial is a different prospect from one without.
            if p.get("foundational") and p["enabled"]:
                return '<span class="chip chip--void">Free tier</span>'
            if p["enabled"]:
                return '<span class="chip chip--ok">Enabled</span>'
            if p.get("free_trial_available"):
                return ('<span class="chip chip--none">Disabled</span> '
                        '<span class="chip chip--partial">30-day trial unused</span>')
            return '<span class="chip chip--none">Disabled</span>'

        def plan_table(rows):
            body = "".join(f"""
      <tr>
        <td><code>{e(p['plan'])}</code>{f' <span class="chip chip--void">{e(p["sub_plan"])}</span>' if p.get('sub_plan') else ''}</td>
        <td>{status_chip(p)}</td>
        <td class="num">{p['protects'] if p['protects'] is not None else '&mdash;'}
            {'<div class="rule-names">' + ", ".join(type_phrase(t, n) for t, n in sorted(p['matching_resources'].items())) + '</div>' if p.get('matching_resources') else ''}</td>
        <td class="detail">{e(p.get('note') or '')}
            {'<div class="rule-names">enabled ' + e(str(p['enabled_on'])[:10]) + '</div>' if p.get('enabled_on') else ''}</td>
        <td class="detail">{detects_cell(p)}</td>
      </tr>""" for p in rows)
            return f"""<div class="scroll"><table>
    <thead><tr><th>Plan</th><th>Status</th><th>Resources</th><th>What it covers</th>
        <th>What it detects</th></tr></thead>
    <tbody>{body}</tbody></table></div>"""

        # Distinct resources that would gain protection, by type. A type can
        # appear under more than one plan (clusters under both Containers and
        # KubernetesService), so it is counted once, not once per plan.
        exposed_types: dict[str, int] = {}
        for p in plans:
            if p["enabled"] or not (p.get("protects") or 0):
                continue
            for t, n in (p.get("matching_resources") or {}).items():
                exposed_types[t] = max(exposed_types.get(t, 0), n)
        exposed_total = sum(exposed_types.values())

        off_with = sorted((p for p in plans
                           if not p["enabled"] and (p["protects"] or 0) > 0),
                          key=lambda p: -p["protects"])
        on = sorted((p for p in plans if p["enabled"]),
                    key=lambda p: (p.get("foundational", False), p["plan"]))
        paid = [p for p in on if p.get("paid_protection")]

        plan_block = f"""
<section class="block block--ref">
  <div class="eyebrow">Defender for Cloud</div>
  <h2>{plural(len(paid), "workload plan")} enabled, {len(off_with)} disabled</h2>
  <p class="muted">{exposed_total} resource{'' if exposed_total == 1 else 's'} covered if the
     disabled plans were enabled:</p>
  {bar([(type_phrase(t, n).split(' ', 1)[1], n, 'none') for t, n in
        sorted(exposed_types.items(), key=lambda kv: -kv[1])])}
  {plan_table(off_with + on)}
</section>"""

    # Endpoints: a count per platform cannot say whether a sensor is alive,
    # so the detail sits beside it.
    ep_block = ""
    if eps and eps.get("devices"):
        devs = eps["devices"]
        inv = eps.get("inventory") or {}
        streams = eps.get("streams") or {}
        silent = eps.get("silent_streams") or []
        fams = eps.get("families") or {}
        # Every XDR table, present or not. An absent table is a row of zeroes
        # rather than a name in a footnote, because the reader is comparing
        # families and a family whose rows are missing cannot be compared with
        # one whose rows are there.
        #
        # Grouped under a heading row per family, rather than a Family column
        # repeated on all twenty-two rows. The section heading counts families,
        # so the table has to be readable as families or the count is a number
        # with nothing behind it. It also makes an entirely absent family --
        # usually an unlicensed product, not a broken pipeline -- read as one
        # block instead of rows scattered by sort order.
        xdr_rows = ""
        for fam, split in fams.items():
            present = sorted(split.get("present") or [],
                             key=lambda t: -streams[t]["rows_window"])
            absent = sorted(split.get("absent") or [])
            xdr_rows += f"""
      <tr class="grouprow">
        <th colspan="4">{e(fam)}
            <span class="more">{len(present)} of {len(present) + len(absent)} arriving</span></th>
      </tr>"""
            for name in present:
                st = streams[name]
                xdr_rows += f"""
      <tr>
        <td><code>{e(name)}</code></td>
        <td class="num">{st['rows_24h']}</td>
        <td class="num">{st['rows_window']}</td>
        <td class="num">{e(str(st['latest'])[:19].replace("T", " "))}</td>
      </tr>"""
            for name in absent:
                xdr_rows += f"""
      <tr>
        <td><code>{e(name)}</code></td>
        <td class="num">0</td>
        <td class="num">0</td>
        <td class="num"><span class="muted">no data</span></td>
      </tr>"""
        arriving = sum(len(v.get("present") or []) for v in fams.values())
        total_x = arriving + sum(len(v.get("absent") or []) for v in fams.values())
        live_fams = [f for f, v in fams.items() if v.get("present")]

        dev_rows = "".join(f"""
      <tr>
        <td><code>{e(d['name'])}</code>
            {'<div class="rule-names">' + e(d['azure_resource_id'].split('/')[-1]) + ' in this subscription</div>' if d.get('azure_resource_id') else '<div class="rule-names">not an inventoried Azure resource</div>'}</td>
        <td>{e(d['os'])} {e(d.get('os_version') or '')}<div class="rule-names">{e(d.get('type') or '')}</div></td>
        <td><span class="chip chip--{'ok' if d['onboarded'] else 'none'}">{e(d['onboarding_status'])}</span>
            <span class="chip chip--{'ok' if d['sensor'] == 'Active' else 'partial'}">sensor {e(d['sensor'])}</span></td>
        <td class="detail">exposure {e(d.get('exposure') or 'unknown')}
            {'<br>' + e(str(d['mitigation'])) if d.get('mitigation') and d['mitigation'] not in ('{}', 'None') else ''}</td>
      </tr>""" for d in devs)

        healthy_n = sum(1 for d in devs if d.get("sensor") == "Active")

        ep_block = f"""
<section class="block block--ref">
  <div class="eyebrow">Defender for Endpoint</div>
  <h2>{plural(len(devs), "device")} onboarded, {healthy_n} with a healthy sensor</h2>
  <div class="scroll"><table>
    <thead><tr><th>Device</th><th>OS</th><th>State</th><th>Detail</th></tr></thead>
    <tbody>{dev_rows}</tbody>
  </table></div>
  {f'<p class="note">No sensor on <strong>{len(inv.get("without_sensor", []))}</strong> of {len(inv.get("without_sensor", [])) + len(inv.get("with_sensor", []))} inventoried machines: ' + e(", ".join(x.split("/")[-1] for x in inv.get("without_sensor", []))) + '</p>' if inv.get("without_sensor") else ''}
</section>

<section class="block block--ref">
  <div class="eyebrow">Advanced hunting tables</div>
  <h2>{arriving} of {total_x} tables ingesting, across {len(live_fams)} of {len(fams)} families</h2>
  <div class="scroll"><table>
    <thead><tr><th>Table</th><th>Rows (24h)</th><th>Rows (30d)</th>
        <th>Latest log</th></tr></thead>
    <tbody>{xdr_rows}</tbody>
  </table></div>
</section>"""

    head = headline(res_rows, by_type, rule_detail, plans, s.get("tables_checked"),
                    gap_facts(res_rows, a.get("coverage_gaps") or [], rules_by_table))
    def step(action: dict) -> str:
        bits = []
        if action["blocks"]:
            names = ", ".join(action["blocks"])
            rest = ""
            bits.append(f'<span class="lead__cost">Blocks '
                        f'{len(action["blocks"])} analytics rule'
                        f'{"" if len(action["blocks"]) == 1 else "s"}: '
                        f'{e(names)}{e(rest)}</span>')
        if action["how"]:
            bits.append(f'<span>{e(action["how"])}</span>')
        if action["alt"]:
            bits.append(f'<span>{e(action["alt"])}</span>')
        return (f'<li><strong>{action["count"]} {e(action["what"])}</strong>'
                f'{"".join(bits)}</li>')

    steps = "".join(step(a) for a in head["actions"])
    # Defender reads its own data; a report telling a reader that nothing
    # reads DeviceFileEvents would be loudly wrong about the largest number
    # on the page. Taken from the static family list rather than from `eps`,
    # so the exclusion still holds when the endpoint leg could not run.
    unread = unread_tables(a.get("tables") or [], rules_by_table,
                           set(endpoints.STREAMS))
    unread_measured = [t for t in unread if t["measured"]]
    unread_mb = sum(t["megabytes"] or 0 for t in unread_measured)
    # Only the tables the meter actually priced as billable contribute. A table
    # whose billable volume is None was never priced, and counting it as zero
    # would understate the bill in the one section written to state it.
    unread_billable = [t for t in unread if t["billable"]]
    billable_mb = sum(t["billable_megabytes"] or 0 for t in unread_billable)
    free_mb = unread_mb - billable_mb
    biggest = max((t["billable_megabytes"] or 0 for t in unread_billable),
                  default=0.0)

    def cost_cell(t: dict) -> str:
        if t["billable"] is None:
            return '<span class="muted">not priced</span>'
        if not t["billable"]:
            # Free is a finding, not a blank. It is why most of this section's
            # volume is nothing to act on.
            return '<span class="chip chip--ok">free</span>'
        money = usage.ingest_cost(t["billable_megabytes"] or 0)
        # Charged but sub-cent. Printing $0.00 here would read as free, which
        # is a different claim and the wrong one.
        return f"${money:,.2f}" if money >= 0.005 else \
            '<span class="muted">&lt;$0.01</span>'

    unread_rows = "".join(f"""
      <tr>
        <td><code>{e(t['table'])}</code></td>
        <td class="num">{f"{t['megabytes']:,.1f}" if t['measured'] else '<span class="muted">not priced</span>'}</td>
        <td class="num">{cost_cell(t)}</td>
        <td class="detail">{e(t['tier'] or '')}</td>
      </tr>""" for t in unread)

    # The plan the figure was computed against. Without it a per-GB number is
    # unfalsifiable: the reader cannot tell whether it applies to them.
    wplan = a.get("workspace_plan") or {}
    plan_words = "This workspace's plan could not be read."
    if wplan.get("sku") == "CapacityReservation" and wplan.get("commitment_gb_per_day"):
        plan_words = (f"This workspace is on a {wplan['commitment_gb_per_day']} GB/day "
                      "commitment tier, which is bought below list.")
    elif wplan.get("sku"):
        plan_words = f"This workspace is {wplan['sku']}, with no commitment tier."

    unread_heading = plural(len(unread), "table") + " ingesting, no analytics rule reads them"
    if unread_billable:
        unread_heading += (f" \u2014 {billable_mb:,.0f} MB of it billable, about "
                           f"${usage.ingest_cost(billable_mb):,.2f} over the window")
    unread_block = "" if not unread else f"""
<section class="block">
  <div class="eyebrow">Unread ingestion</div>
  <h2>{unread_heading}</h2>
  <p class="note">{(f"{free_mb:,.0f} MB of the {unread_mb:,.0f} MB costs nothing: Microsoft does "
                    "not charge for those sources, and that is read from this workspace's own "
                    "usage meter rather than assumed from a price list. "
                    if free_mb >= 0.5 else
                    f"{unread_mb:,.0f} MB over the window. " if unread_measured else
                    "Volume was not priced for these. ")}{
      f"Of what is billed, <strong>one table is {biggest / billable_mb * 100:,.0f}% of it</strong>. "
      if billable_mb and biggest / billable_mb >= 0.5 else ""}
     <strong>{"Still not" if free_mb >= 0.5 else "Not"} necessarily waste.</strong> A hunting query, a workbook or
     an export may read these and this scan cannot see any of them. Defender XDR
     tables are excluded, and so are the Sentinel health tables, which this scan
     reads itself. A rule reaching a table through a function is also
     invisible here.</p>
  <div class="scroll"><table>
    <thead><tr><th>Table</th><th>MB in window</th><th>Cost in window</th><th>Tier</th></tr></thead>
    <tbody>{unread_rows}</tbody>
  </table></div>
  <p class="pricebar">
    <span>rate</span> <strong>${usage.ingest_price():,.2f}/GB</strong>
    <span>&middot; Analytics tier, pay-as-you-go list price. {e(plan_words)}</span>
    <span>&middot; set <strong>PYLON_PRICE_GB</strong> to your negotiated or commitment-tier rate</span>
  </p>
</section>"""

    summary_block = "" if not (head["lead"] or head["second"]) else f"""
<section class="block block--lead">
  <div class="eyebrow">Summary</div>
  {f'<p class="lead__1">{e(head["lead"])}</p>' if head["lead"] else ''}
  {f'<p class="lead__2">{e(head["second"])}</p>' if head["second"] else ''}
  {f'<div class="lead__do"><h3>Where to start</h3><p class="lead__axis">Ordered by how many analytics rules each gap blocks.</p><ol>{steps}</ol></div>' if steps else ''}
  {f'<p class="lead__caveat">{e(head["caveat"])}</p>' if head["caveat"] else ''}
</section>"""

    limits = []
    # Match the phrase crosscheck.py actually emits, and take THAT clause --
    # not the last one. Testing for the word "unreported" matched nothing, so
    # this limitation silently never rendered; taking `[-1]` would have filed a
    # contradiction under the wrong heading on any run without this clause.
    MARK = "arriving via paths the configuration APIs do not report: "
    cross = reads.get("differential", {})
    for clause in (cross.get("detail") or "").split("; "):
        if clause.startswith(MARK):
            limits.append(("Data arriving with no configuration behind it",
                           "Every other verdict here can name the setting that "
                           "produced it. These cannot. The scan sees the rows "
                           "land and nothing more. "
                           + e(clause[len(MARK):]) + "."))
    # An empty Limitations section is a heading that says the scan is blind and
    # then names nothing, which reads worse than saying nothing at all. Every
    # entry is now measured per run, so having none is a real outcome.
    limit_block = "" if not limits else """
<section class="block">
  <div class="eyebrow">Limitations</div>
  <h2>What this scan cannot see</h2>
  <div class="limits">%s</div>
</section>""" % "".join(
        f'<div class="limit"><h4>{e(t)}</h4><div>{d}</div></div>' for t, d in limits)

    # The Method section used to list every read and whether it answered. On a
    # clean scan that is ten rows all saying "Answered", restating a workspace
    # name and window the page header already carries -- noise in a document
    # whose whole job is to be worth reading.
    #
    # It survives only for the case it was built for. A read that did NOT
    # answer means a section above it is incomplete rather than empty, and
    # nothing else on the page says so. When every read answered, the section
    # is absent, because "we checked everything" is what a report with no such
    # section already implies.
    unanswered = [(q, why) for q, ok, why in coverage_of_reads(reads) if not ok]
    method_rows = "".join(
        f"""
      <tr>
        <td>{e(question)}</td>
        <td class="detail">{e(why[:150]) if why else 'no reason recorded'}</td>
      </tr>""" for question, why in unanswered)
    method_block = "" if not unanswered else f"""
<section class="block">
  <div class="eyebrow">Not measured</div>
  <h2>{plural(len(unanswered), "question")} this scan could not answer</h2>
  <p class="method__note">Any section resting on one of these is incomplete
     rather than empty.</p>
  <div class="scroll"><table>
    <thead><tr><th>Question</th><th>Why not</th></tr></thead>
    <tbody>{method_rows}</tbody>
  </table></div>
</section>"""

    return f"""<title>Telemetry Health</title>
{HEAD}

<div class="wrap">
<header>
  <h1>Telemetry Health</h1>
  <div class="meta">
    <div><span>workspace</span><code>{e(a.get('workspace'))}</code></div>
    <div><span>generated</span><code>{e(a['generated_at'][:19].replace('T', ' '))}</code></div>
    <div><span>window</span><code>{a['window_days']} days</code></div>
    <div><span>scope</span><code>{e(a['scope'])}</code></div>
  </div>
</header>

{summary_block}

<section class="block">
  <div class="eyebrow">Scan</div>
  <div class="stat-row">
    <div class="stat"><span class="stat__n">{stat(s.get('resources'))}</span><span class="stat__l">resources · {plural(s.get('resource_types'), "type") if s.get('resource_types') is not None else "&mdash; types"}</span></div>
    <div class="stat"><span class="stat__n">{stat(s.get('rules_total'))}</span><span class="stat__l">analytics rules · {custom_n} custom, {tpl_n} from a template</span></div>
    <div class="stat"><span class="stat__n">{stat(s.get('tables_checked'))}</span><span class="stat__l">{'tables ingesting' if s.get('tables_checked') is not None else 'table activity NOT MEASURED'}</span></div>
  </div>
</section>

<section class="block">
  <div class="eyebrow">Diagnostic settings</div>
  <h2>{len(dark)} of {loggable_here} resources, diagnostic setting missing or incomplete</h2>
  {bar([(STATE_LABEL[k], res_states.get(k, 0), STATE_CLASS[k]) for k in STATE_ORDER])}
  <div class="scroll"><table>
    <thead><tr><th>Resource type</th><th>Checked</th><th>Status</th></tr></thead>
    <tbody>{exp_rows}</tbody>
  </table></div>
</section>

{rules_block}
{exec_block}
{conn_block}

{unread_block}

<section class="block">
  <div class="eyebrow">Data sources</div>
  <h2>What each scope emits about itself</h2>
  <div>{"".join(scope_rows)}</div>
</section>

<section class="block">
  <div class="eyebrow">Ingestion gaps</div>
  <h2>{plural(len(fix_rows), "table")} with no ingestion, ordered by analytics rules blocked</h2>
  <div class="scroll"><table>
    <thead><tr><th>Table</th><th>Last log seen<br><span class="more">in {a['window_days']}d</span></th><th>Resources</th><th>Enable</th><th>Why it is dark</th><th>Analytics rules</th></tr></thead>
    <tbody>{"".join(fix_rows)}</tbody>
  </table></div>
</section>

{plan_block}

{ep_block}
{limit_block}
{method_block}

</div>"""


def main() -> int:
    with open("analysis.json", encoding="utf-8") as f:
        analysis = json.load(f)
    try:
        with open("defender_plans.json", encoding="utf-8") as f:
            plans = json.load(f)
    except FileNotFoundError:
        plans = None
    try:
        with open("endpoints.json", encoding="utf-8") as f:
            eps = json.load(f)
    except FileNotFoundError:
        eps = None
    try:
        with open("verdicts.json", encoding="utf-8") as f:
            verdicts = json.load(f)
    except FileNotFoundError:
        verdicts = None
    try:
        with open("rules_detail.json", encoding="utf-8") as f:
            rules_detail = json.load(f)
    except FileNotFoundError:
        rules_detail = None
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(build(analysis, plans, eps, verdicts, rules_detail))
    # Indented and verbless, so under `pylon analyze` it lands as another
    # line in the scan's WROTE block rather than restating the verb.
    print(f"  {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
