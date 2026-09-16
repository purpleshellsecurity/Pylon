"""Connectors as a SOURCE, judged only where this tenant already expects one.

Azure resources log through a diagnostic setting. Microsoft 365, AWS, Defender
and threat intel have no diagnostic setting at all, so the connector IS the
source: nothing arrives without it. The scan read connectors only as a health
signal, which put them at the wrong end of the chain. A tenant with no Office
365 connector had nothing anywhere saying so, and the break surfaced two steps
later as an empty table with no cause.

THE LINE THIS MODULE WILL NOT CROSS
-----------------------------------
There is no list of connectors a tenant ought to have, and there must not be.
What a client should connect depends on what they run, what they license and
what they are paying someone else to watch, none of which this scan can see. A
built-in "recommended connectors" list is a per-client opinion wearing the
costume of a measurement, and it would be wrong on most tenants.

So a connector is reported as missing on EVIDENCE FROM THIS TENANT, or not at
all. Two kinds, both measured:

    an installed Content Hub solution declares it as a dependency
    a deployed analytics rule reads a table only that connector fills

Either one means somebody here already decided they wanted that data. A
connector nobody here expects is simply absent from the report, whatever anyone
else runs.

MATCHING IS THE WEAK JOINT, AND IT FAILS SAFE
---------------------------------------------
A solution declares a connector by `contentId`; the dataConnectors API returns a
`kind`. They usually agree ("Office365") and nothing guarantees it. A miss here
produces a connector reported as expected-and-absent when it is really present
under another spelling -- so the comparison is case-folded, and anything that
cannot be matched is dropped rather than reported. A quiet miss is better than a
confident wrong finding.
"""

from __future__ import annotations

from .crosscheck import CLAIMED_BY
from .text import plural

# Connector kinds that carry no data of their own, so "missing" says nothing
# useful about them.
_NOT_A_SOURCE: frozenset[str] = frozenset({"azuresecuritycenter"})


def _fold(name: str | None) -> str:
    return (name or "").strip().lower()


def expected(solutions: list[dict] | None,
             rules: list[dict] | None,
             live_tables: set[str] | None = None) -> dict[str, list[str]]:
    """{connector: why this tenant expects it}, from measured evidence only.

    The value is one line of evidence per reason, so the report can say who is
    doing the expecting rather than asserting it.
    """
    out: dict[str, list[str]] = {}

    for row in solutions or []:
        name = row.get("display_name") or row.get("solution_id") or "a solution"
        for cid in (row.get("requires_connectors") or []):
            if not cid or _fold(cid) in _NOT_A_SOURCE:
                continue
            out.setdefault(cid, []).append(
                f"the installed {name} solution declares it")

    # A deployed rule reading a table only one connector fills is the other
    # half. `CLAIMED_BY` is deliberately generous -- it lists every kind that
    # could account for a table -- so a table with several claimants says
    # nothing about any one of them and is skipped.
    by_table = {t: kinds for t, kinds in CLAIMED_BY.items() if len(kinds) == 1}
    reading: dict[str, list[str]] = {}
    for rule in rules or []:
        for table in (rule.get("tables_referenced") or []):
            kinds = by_table.get(table)
            if not kinds:
                continue
            reading.setdefault(kinds[0], []).append(
                rule.get("name") or "(unnamed)")
    for kind, names in reading.items():
        out.setdefault(kind, []).append(
            f"{plural(len(names), 'deployed rule')} "
            f"{'reads' if len(names) == 1 else 'read'} a table only it fills")

    return {k: sorted(dict.fromkeys(v)) for k, v in out.items()}


def assess(solutions: list[dict] | None,
           rules: list[dict] | None,
           present_kinds: set[str] | None) -> list[dict]:
    """One row per connector worth reporting, present or expected-and-absent.

    `present_kinds` is None when neither connector leg ran, which is NOT an
    empty set: no knowledge of connectors cannot be read as no connectors, so
    nothing is called absent and every row says the question was not asked.
    """
    wanted = expected(solutions, rules)
    present = {_fold(k) for k in (present_kinds or set())}
    unknown = present_kinds is None

    rows: list[dict] = []
    for kind in sorted(present_kinds or set()):
        if _fold(kind) in _NOT_A_SOURCE:
            continue
        rows.append({"connector": kind, "state": "present",
                     "because": ["present in the workspace"],
                     "fills": sorted(t for t, ks in CLAIMED_BY.items()
                                     if _fold(kind) in {_fold(x) for x in ks})})
    for kind, why in sorted(wanted.items()):
        if _fold(kind) in present:
            continue
        rows.append({
            "connector": kind,
            "state": "not-established" if unknown else "expected-absent",
            "because": why if not unknown else
            why + ["the connector list could not be read on this run"],
            "fills": sorted(t for t, ks in CLAIMED_BY.items()
                            if _fold(kind) in {_fold(x) for x in ks})})
    return rows
