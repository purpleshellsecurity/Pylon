"""What is blocked by something further upstream, and what is merely unknown.

Every leg of the scan answers its own question and none of them join up. The
report could say "8 analytics rules cannot fire" in one section and
"StorageBlobLogs received nothing" in another, two inches apart, and never that
the first is caused by the second. A reader met eleven problems where the tenant
had one.

This module walks the one chain the whole scan is measuring:

    resource  ->  diagnostic setting  ->  table  ->  rule  ->  technique

and stamps each downstream row with the ROOT cause when there is one. Root, not
the immediate parent: "waiting on step 1, no diagnostic setting on 10 storage
accounts" is something a person can go and do, and "blocked by step 4, which is
blocked by step 2, which is blocked by step 1" is a puzzle.

THREE STATES, NOT TWO
---------------------
The temptation is to treat this as blocked/not-blocked, and that is wrong in the
direction this codebase exists to refuse. `dark_reason` already partitions into
exactly the three answers needed:

    blocking        a measured break. No setting, category off, ships to
                    another workspace, metrics only. Downstream says so and
                    points here.
    not blocking    "configured here, idle in the window". The resource is set
                    up correctly and quiet. Nothing downstream is blocked by a
                    thing that is working.
    not established "settings unreadable". The scan could not look. Downstream
                    is NOT blocked, because a break was never measured, and it
                    is not clean either. It is unknown, and it says so.

Reporting the third as the first would invent a cause. Reporting it as the
second would hide that a section rests on a question nobody answered.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .text import plural

# A measured break at step 1: the source is not sending, and the fix is a
# change to a diagnostic setting.
BLOCKING_REASONS: frozenset[str] = frozenset({
    "no diagnostic setting",
    "category not enabled",
    "metrics only, no log categories",
    "ships elsewhere",
})

# The scan could not read the setting. Not a break, not a clean bill.
UNREADABLE_REASONS: frozenset[str] = frozenset({"settings unreadable"})

# "configured here — idle in the window" is deliberately in neither. The
# resource is logging correctly and has nothing to say. A downstream row that
# blamed it would be pointing at working configuration.


@dataclass
class Blocked:
    """Why a row cannot be judged on its own merits.

    `step` is where the break is, so the reader knows which section to go to.
    `subject` is the thing that is broken, and `reason` is one sentence naming
    what to do about it.
    """

    step: int
    subject: str
    reason: str
    # Every resource behind this break, so the count is the tenant's rather
    # than an example. Ten storage accounts with no setting is one cause.
    resources: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"step": self.step, "subject": self.subject,
                "reason": self.reason, "resources": list(self.resources)}


def table_blocks(coverage_gaps: list[dict] | None) -> dict[str, Blocked]:
    """{table: the step 1 break that leaves it empty}, measured breaks only.

    A table with several dark resources behind it collapses to ONE entry
    carrying all of them, because that is one fix. A table whose only gaps are
    idle-but-configured, or unreadable, is absent: nothing downstream of it is
    blocked by a break nobody measured.
    """
    grouped: dict[str, dict[str, list[str]]] = {}
    for gap in coverage_gaps or []:
        reason = gap.get("dark_reason")
        if reason not in BLOCKING_REASONS:
            continue
        table = gap.get("expected_table")
        if not table:
            continue
        name = (gap.get("resource_id") or "").rsplit("/", 1)[-1]
        grouped.setdefault(table, {}).setdefault(reason, []).append(name)

    out: dict[str, Blocked] = {}
    for table, by_reason in grouped.items():
        # The reason behind the most resources decides the sentence; the rest
        # ride along in `resources` so the count stays the tenant's.
        reason, names = max(by_reason.items(), key=lambda kv: len(kv[1]))
        every = sorted({n for ns in by_reason.values() for n in ns})
        out[table] = Blocked(
            step=1, subject=table,
            reason=f"{plural(len(every), 'resource')} feeding "
                   f"{table}: {reason}",
            resources=every)
    return out


def unreadable_tables(coverage_gaps: list[dict] | None) -> set[str]:
    """Tables whose emptiness could not be explained because a setting would
    not read. Downstream of these, nothing is blocked and nothing is clean."""
    return {gap.get("expected_table") for gap in (coverage_gaps or [])
            if gap.get("dark_reason") in UNREADABLE_REASONS
            and gap.get("expected_table")}


def rule_blocks(rules: list[dict] | None, live_tables: set[str],
                blocks: dict[str, Blocked]) -> dict[str, Blocked]:
    """{rule name: the upstream break that stops it firing}.

    A rule is blocked only when EVERY table it reads is empty and at least one
    of them traces to a measured break. A rule with one live table can fire, so
    whatever it is doing is its own business.

    A rule whose tables were never resolved is absent: the scan does not open
    saved KQL functions, so it has no idea what that rule reads and cannot say
    anything is blocking it.
    """
    out: dict[str, Blocked] = {}
    for rule in rules or []:
        tables = rule.get("tables_referenced") or []
        if not tables or any(t in live_tables for t in tables):
            continue
        causes = [blocks[t] for t in tables if t in blocks]
        if not causes:
            continue
        root = causes[0]
        out[rule.get("name") or "(unnamed)"] = root
    return out


def technique_blocks(gaps: list[dict] | None, rules: list[dict] | None,
                     rule_blocked: dict[str, Blocked]) -> dict[str, Blocked]:
    """{technique id: the upstream break behind it}.

    Only for techniques whose claiming rules are ALL blocked. A technique with
    one unblocked rule is that rule's story, not the pipeline's.

    Points at the root, so a technique whose rule reads an empty table reads
    "waiting on step 1" rather than "blocked by a rule, which is blocked by a
    table, which is blocked by a setting".
    """
    claims: dict[str, list[str]] = {}
    for rule in rules or []:
        name = rule.get("name") or "(unnamed)"
        for tech in (rule.get("_techniques") or []):
            claims.setdefault(tech, []).append(name)

    out: dict[str, Blocked] = {}
    for gap in gaps or []:
        tech = gap.get("technique_id")
        here = claims.get(tech) or []
        if not here:
            continue
        causes = [rule_blocked[n] for n in here if n in rule_blocked]
        if len(causes) != len(here):
            continue          # at least one claiming rule is not blocked
        out[tech] = causes[0]
    return out


def solution_blocks(solutions: list[dict] | None,
                    blocks: dict[str, Blocked]) -> dict[str, Blocked]:
    """{solution id: the upstream break under it}.

    Updating content on a pipeline that is down changes no outcome, so a
    solution whose data types all trace to a measured break is reported as
    waiting rather than as work.
    """
    out: dict[str, Blocked] = {}
    for row in solutions or []:
        types = row.get("data_types") or []
        if not types:
            continue
        causes = [blocks[t] for t in types if t in blocks]
        if len(causes) != len(types):
            continue
        out[row.get("solution_id") or row.get("display_name") or "?"] = causes[0]
    return out
