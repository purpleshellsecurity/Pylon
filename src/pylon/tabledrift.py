"""Does `tablemap.TABLE_MAP` still match what Azure offers?

`TABLE_MAP` is hand-written from Microsoft's documentation. That is the only
place the mapping exists -- ARM will tell you which categories a resource type
can emit, but never which Log Analytics table they land in -- so the file cannot
be replaced by a lookup. What it CAN have is an expiry check.

The failure this exists to catch is silent and one-directional. Azure adds a
category to a resource type; the map does not have it; `table_for` returns
`unmapped`; the category is real, loggable, and now invisible to every coverage
verdict the scan makes. Nothing breaks. The scan just stops asking about a thing
that exists. A map that is never re-checked degrades into a map of the day it
was written.

WHAT THIS LEG CAN AND CANNOT ANSWER
-----------------------------------
ARM answers one half:

    az monitor diagnostic-settings categories list --resource <id>

It returns the category NAMES a resource type can emit, and `categoryType`
separating logs from metrics. It does NOT return the destination table, and it
does NOT say whether a category supports resource-specific mode -- `Dedicated`
is `logAnalyticsDestinationType` on the diagnostic SETTING, not a property of the
category. So this leg reports:

    unlisted   ARM offers a log category the map has no row for  -> a blind spot

and it reports ONE, because only one direction can be proven from a tenant. The
first run against a real workspace reported seven Windows App Service categories
as retired by Azure; the tenant's only `microsoft.web/sites` was a Linux Function
App, which genuinely does not offer them. Even probing every instance -- which
this now does -- "nothing here offers it" is not "Azure removed it": you would
have to own the variant that offers it to tell. So a category the map has and
this tenant does not see is printed as context and fails nothing

and never proposes a table name. Filling in the table is the workspace half, and
it is a different kind of claim: evidence from one tenant rather than a fact
about Azure.

Categories are a property of the resource TYPE, not the instance, so one
resource per type answers for all of them. Eleven types is eleven calls.

WHY THE PARSING IS DEFENSIVE
----------------------------
The exact response shape could not be pinned from Microsoft's published
reference -- the CLI page documents no output at all and the REST schema pages
404 -- and az flattens ARM's `properties` bag inconsistently across commands. So
`log_categories` looks for `categoryType` in both places and, when it finds it
in neither, says SHAPE UNKNOWN and reports no drift for that type.

That last part is the important one. Guessing "no categoryType means it is a log
category" would report every metric category as a missing row, and a drift
report that cries wolf on first contact is a drift report nobody reads twice.
Not being able to tell is not a finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import console
from . import diagnostics
from .text import plural
from . import azcli
from .tablemap import TABLE_MAP

# The value of `categoryType` for the half we map. Metrics categories are real
# and are deliberately out of scope: they do not land in a log table and
# `TABLE_MAP` makes no claim about them.
LOGS = "logs"


@dataclass
class Drift:
    """What one resource type's categories look like against the map.

    `ran` carries the same meaning it does everywhere else in this codebase: a
    type whose categories could not be read is not a type that agrees with the
    map. `unlisted` and `not_offered_here` are empty in both cases, so they must
    never be read without it.
    """

    resource_type: str
    probe_id: str = ""
    ran: bool = False
    error: str | None = None
    # How many instances of this type were probed and unioned.
    instances: int = 0
    # ARM offers it, the map has no row. The blind spot, and the only finding.
    unlisted: list[str] = field(default_factory=list)
    # The map has a row no instance in THIS tenant offers. Context, not a
    # finding: it may be a resource variant this tenant does not run.
    not_offered_here: list[str] = field(default_factory=list)
    # Read fine, but `categoryType` was not where either shape puts it, so logs
    # could not be told from metrics and no comparison was made.
    shape_unknown: bool = False
    # In the map, and this tenant runs no instance of it. Not a failure and not
    # a pass: a question nobody could ask. It used to be dropped on the floor,
    # so "7 match the map" read as though the whole map had been verified.
    no_instance: bool = False

    @property
    def drifted(self) -> bool:
        """Only a blind spot counts. `not_offered_here` cannot be proven from
        one tenant, so failing a monthly job on it would cry wolf every month
        for every resource variant the owner happens not to run."""
        return bool(self.unlisted)

    def public(self) -> dict:
        """The finding without the probe's resource id.

        `probe_id` is a full ARM path -- subscription guid, resource group and
        resource name -- and it is kept because the first question about a
        surprising finding is "which resource did you ask?". It must not be what
        gets written to a file, uploaded as a CI artifact or pasted into a pull
        request: this tool is meant to be public, and a drift report is exactly
        the kind of low-stakes output nobody thinks to check before sharing.

        The finding does not need it. Categories belong to the resource TYPE, so
        the type is the whole subject of every line here.
        """
        return {k: v for k, v in self.__dict__.items() if k != "probe_id"}


def read_categories(resource_id: str) -> tuple[list[dict] | None, str | None]:
    """(categories, error) from ARM for one resource. Never raises.

    `None` for the categories means the read failed, which is not the same as a
    resource type offering none -- an empty list is that, and it is a legitimate
    answer for a type with nothing to switch on.
    """
    proc = azcli.run(
        ["monitor", "diagnostic-settings", "categories", "list",
         "--resource", resource_id, "-o", "json"],
        timeout=azcli.CONTROL_TIMEOUT,
    )
    if proc.returncode != 0:
        return None, (proc.stderr or "").strip()[:300] or "az returned no reason"
    try:
        payload = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as unparseable:
        return None, f"could not parse the category list: {unparseable}"
    # az returns either a bare list or {"value": [...]} depending on version.
    if isinstance(payload, dict):
        payload = payload.get("value") or []
    if not isinstance(payload, list):
        return None, f"unexpected category payload: {type(payload).__name__}"
    return [c for c in payload if isinstance(c, dict)], None


def _category_type(entry: dict) -> str | None:
    """`categoryType`, wherever this az version decided to put it.

    Returns None when it is in neither place, which the caller must treat as
    "cannot tell" rather than defaulting either way.
    """
    for holder in (entry, entry.get("properties") or {}):
        if not isinstance(holder, dict):
            continue
        for key in ("categoryType", "category_type"):
            value = holder.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
    return None


def log_categories(entries: list[dict]) -> tuple[set[str], bool]:
    """(log category names, shape_unknown).

    `shape_unknown` is True when entries exist but not one of them carried a
    `categoryType`. Then the set is empty and means nothing -- the caller must
    not compare it to anything.
    """
    if not entries:
        return set(), False

    names, saw_a_type = set(), False
    for entry in entries:
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        kind = _category_type(entry)
        if kind is None:
            continue
        saw_a_type = True
        if kind == LOGS:
            names.add(name.strip())
    return (names, False) if saw_a_type else (set(), True)


def compare(resource_type: str, offered: set[str]) -> tuple[list[str], list[str]]:
    """(unlisted, not-offered-here) for one type: ARM's categories vs the map."""
    mapped = set(TABLE_MAP.get(resource_type.lower(), {}))
    return sorted(offered - mapped), sorted(mapped - offered)


def representatives(rows: list[dict]) -> dict[str, list[str]]:
    """{resource type: every resource id of that type}.

    This probed ONE instance per type, on the stated premise that categories are
    a property of the type. They are not. `microsoft.web/sites` covers Web Apps,
    Function Apps and Logic Apps, on Windows and on Linux, and each offers a
    different set -- so a tenant whose only site was a Linux Function App had
    seven real Windows categories reported as retired by Azure.

    Every instance is probed and the offered categories unioned. Sorted so the
    order is stable between runs: a report that reshuffles because it walked the
    resources differently cannot be diffed against the last one.
    """
    chosen: dict[str, list[str]] = {}
    for row in sorted(rows, key=lambda r: str(r.get("id") or "")):
        rtype = str(row.get("type") or "").lower()
        rid = str(row.get("id") or "")
        if not (rtype and rid):
            continue
        # Storage keeps its log categories on child services, so the map is
        # keyed by `.../storageaccounts/blobservices` and the three siblings.
        # Resource Graph's `Resources` table returns TOP-LEVEL resources only,
        # so it reports `.../storageaccounts` and never a sub-service -- those
        # four map rows matched nothing and were skipped as "no instance here"
        # on every tenant that has ever run this.
        #
        # Storage is the commonest resource type there is. The alarm meant to
        # catch a category going missing was blind exactly where it mattered
        # most, and said "match the map" while being so. Expanded here, from
        # the same SUBSERVICES table `diagnostics` probes with, so the two
        # cannot drift apart.
        children = diagnostics.SUBSERVICES.get(rtype)
        if children:
            for child in children:
                chosen.setdefault(f"{rtype}/{child.lower()}", []).append(
                    f"{rid}/{child}/default")
        else:
            chosen.setdefault(rtype, []).append(rid)
    return chosen


def survey(probes: dict[str, list[str]], types: list[str] | None = None) -> list[Drift]:
    """Check each mapped type that this tenant actually has an instance of.

    Every instance of a type is probed and the offered categories unioned,
    because two resources of the same type can offer different sets -- a Linux
    Function App and a Windows Web App are both `microsoft.web/sites`.

    A type in the map with no instance here is skipped rather than reported: the
    tenant not running one says nothing about whether Azure changed it. That is
    the honest limit of a tenant-grounded check, and it is why this leg detects
    blind spots in what you own and cannot complete the map for what you do not.
    """
    wanted = [t.lower() for t in (types if types is not None else TABLE_MAP)]
    out: list[Drift] = []
    for rtype in sorted(wanted):
        instances = probes.get(rtype) or []
        if not instances:
            # Recorded, not dropped. The tenant not running a type says nothing
            # about whether Azure changed it, so this is neither a pass nor a
            # failure -- but a verdict that silently omits four of eleven map
            # rows reads as though it checked all eleven.
            out.append(Drift(resource_type=rtype, ran=False, no_instance=True))
            continue

        offered: set[str] = set()
        errors, shapes, read_any = [], 0, False
        for probe in instances:
            entries, error = read_categories(probe)
            if entries is None:
                errors.append(error or "unreadable")
                continue
            names, shape_unknown = log_categories(entries)
            if shape_unknown:
                shapes += 1
                continue
            read_any = True
            offered |= names

        if not read_any:
            # Nothing usable came back from any instance. Which of the two
            # reasons dominated decides what the report can say.
            if shapes and not errors:
                out.append(Drift(resource_type=rtype, probe_id=instances[0],
                                 ran=True, shape_unknown=True))
            else:
                out.append(Drift(resource_type=rtype, probe_id=instances[0],
                                 ran=False, error="; ".join(errors[:2])))
            continue

        unlisted, absent = compare(rtype, offered)
        out.append(Drift(resource_type=rtype, probe_id=instances[0], ran=True,
                         instances=len(instances), unlisted=unlisted,
                         not_offered_here=absent))
    return out


def render(findings: list[Drift]) -> str:
    """The report, written so an unread type cannot be mistaken for a clean one."""
    if not findings:
        return ("NOT CHECKED  no resource in this tenant matches any mapped type, "
                "so nothing could be compared")

    absent_type = [f for f in findings if f.no_instance]
    drifted = [f for f in findings if f.drifted]
    unread = [f for f in findings if not f.ran and not f.no_instance]
    unclear = [f for f in findings if f.ran and f.shape_unknown]
    clean = [f for f in findings if f.ran and not f.shape_unknown and not f.drifted]

    # The verdict FIRST. It used to be one line between two blocks, with the
    # longest block on the page being the one explicitly labelled "NOT a
    # finding" -- twenty-two lines of context above a one-line result. A reader
    # cannot tell what the command decided from a screen arranged that way.
    lines = [console.heading("TABLEDRIFT")
             + f"  {plural(len(findings), 'type')} in the map",
             "",
             f"  {len(clean):>4}  match the map",
             f"  {len(drifted):>4}  drifted",
             f"  {len(unread) + len(unclear):>4}  could not be checked",
             f"  {len(absent_type):>4}  not run in this tenant, so not checked",
             ""]

    # What the command is for, because nothing on screen said.
    lines += [
        "  The map says which diagnostic category lands in which table. Azure",
        "  will name the categories a resource type offers and never the table",
        "  they land in, so the map is written by hand and this is its expiry",
        "  check.",
    ]

    if drifted:
        lines += ["", console.heading("DRIFTED") + "   the map is missing a row"]
        for finding in drifted:
            lines.append(f"  {finding.resource_type}")
            for category in finding.unlisted:
                lines.append(f"    {category}  offered by Azure, no row in the "
                             f"map, so invisible to every coverage verdict")

    if absent_type:
        lines += ["", console.heading("NOT RUN HERE")
                  + "   in the map, no instance to ask",
                  ""]
        for finding in absent_type:
            lines.append(f"  {finding.resource_type}")

    if unread or unclear:
        lines += ["", console.heading("NOT CHECKED")]
        for finding in unread:
            lines.append(f"  {finding.resource_type}: {finding.error}")
        for finding in unclear:
            lines.append(f"  {finding.resource_type}: the category list carried "
                         f"no categoryType, so logs could not be told from metrics")

    # Last, and never counted into the verdict. A category the map has and no
    # instance here offers is not evidence Azure removed it: this tenant may
    # not run the variant that offers it, which is exactly what a Linux
    # Function App does to seven Windows App Service categories.
    absent = [f for f in findings if f.ran and f.not_offered_here]
    if absent:
        total = sum(len(f.not_offered_here) for f in absent)
        lines += ["",
                  console.heading("NOT OFFERED HERE")
                  + f"   {plural(total, 'category', 'categories')}, context only",
                  "",
                  "  The map has these and no instance in this tenant offers them.",
                  "  From one tenant, a variant you do not run and a retired",
                  "  category look identical, so neither is counted above.",
                  ""]
        for finding in absent:
            probed = (f"   {plural(finding.instances, 'instance')} probed"
                      if finding.instances else "")
            lines.append(f"  {finding.resource_type}{probed}")
            for category in finding.not_offered_here:
                lines.append(f"    {category}")
    return "\n".join(lines)
