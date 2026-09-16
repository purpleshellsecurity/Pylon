"""Every technique that applies to this tenant, and what should be done about it.

The candidate set is ATT&CK narrowed to the platforms the tenant demonstrably
runs -- see `platforms.py`, which earns each platform from a measurement. It
used to be "every technique an installed Content Hub template mentions", which
measured Content Hub against itself: installing a solution moved both the
numerator and the denominator, and uninstalling one improved coverage. The
templates are still read, but now only as CONTENT -- one way to close a gap,
not the definition of one.

The change makes coverage look far worse and adds a verdict that was previously
unrepresentable: a technique that applies here and that no installed template
mentions at all. That row is the most useful one in the report, and the old
denominator could not produce it.

Every candidate is carried, `covered` included. Emitting only the non-covered
rows would remove the check that catches a technique counted twice or dropped
-- the partition over the whole candidate set is what makes the headline
counts verifiable.

Precedence, most specific first:

    covered                 a deployed rule claims it AND a table it reads
                            holds data, so it can actually fire
    needs_confirmation      a deployed rule claims it and NO table it reads
                            holds data. Neither covered nor a gap: the rule
                            exists, and whether it works cannot be seen here
    no_content              no rule, and no installed template mentions it.
                            Closing it needs authored KQL or a solution that
                            is not installed
    available_not_deployed  no rule, a template exists, the data is there.
                            The cheapest gap: deploy, do not author
    no_data_no_rule         no rule, a template exists, no telemetry. Fixing
                            it starts with logging, not with a detection

A technique outside the platform set is still carried if a deployed rule or an
installed template claims it -- dropping it would make this report disagree
with the tenant -- and its basis says why ATT&CK did not select it.

`data_no_rule` stays empty: it needs a technique with data mapped to it and no
rule, which `available_not_deployed` already names. It is left declared so a
consumer sees a partition with a hole rather than a missing value.

The two Defender verdicts -- `covered_by_product` and
`plan_available_not_enabled` -- are NOT assigned from the plan list.
`covered_by_product` is assigned only from an observed alert. Deciding either
from the plans alone needs a map from a Defender plan to the techniques it
detects, and nothing read here provides one.
"""

from __future__ import annotations

import collections

from . import mitre
from .text import plural


# WHETHER A RULE CAN ACTUALLY FIRE, in three answers rather than two.
#
# `gapscan` used to ignore this entirely. A technique was covered if any
# deployed rule claimed it and one table that rule reads holds data -- and
# nothing looked at `_enabled` or at the verdict the health leg produced two
# steps earlier in the same scan. Measured against a real tenant: 12 techniques
# reported covered, 4 of them claimed ONLY by rules Pylon itself had rated
# `never-fires`. T1078 Valid Accounts, Initial Access, three rules, all dead.
#
# The third answer is the one that keeps this honest. Health is an optional
# leg: on a run where it did not execute every rule carries
# `rule_health_status: None`, and treating that as "cannot fire" would collapse
# coverage to zero and report a limitation of the scan as a fact about the
# tenant. Unknown means unknown, the rule still counts, and the basis says the
# claim was not verified.
CANNOT_FIRE = frozenset({"never-fires", "broken"})


def can_fire(rule: dict) -> bool | None:
    """True, False, or None for "this scan did not establish it".

    `_enabled` is checked first and on its own: it comes from the rule's own
    properties, so a rule someone switched off is known to be dead even on a
    run where the health leg never executed.
    """
    if rule.get("_enabled") is False:
        return False
    status = rule.get("rule_health_status")
    if status in CANNOT_FIRE:
        return False
    if status == "fires":
        return True
    return None


def _why_dead(rule: dict) -> str:
    if rule.get("_enabled") is False:
        return "disabled"
    return rule.get("rule_health_status") or "not established"


def build(index: dict[str, list[str]], deployed_rules: list[dict],
          live_tables: set[str],
          product_coverage: dict[str, list[str]] | None = None,
          candidates: dict[str, dict] | None = None
          ) -> tuple[list[dict], dict]:
    """(Gap rows, read state).

    `candidates` is the denominator: every technique that applies to the
    platforms this tenant runs, from `platforms.universe`. It is passed in
    rather than derived here because deriving it from `index` -- the installed
    templates -- is the circularity this argument is about.
    """
    # technique -> tables that could detect it, from the installed templates.
    # This is now only the CONTENT map. It no longer decides which techniques
    # get asked about.
    by_technique: dict[str, set[str]] = collections.defaultdict(set)
    for table, techs in index.items():
        for tech in techs:
            by_technique[tech].add(table)

    # technique -> deployed rules claiming it
    claimed: dict[str, list[dict]] = collections.defaultdict(list)
    for rule in deployed_rules:
        for tech in rule.get("_techniques") or []:
            claimed[tech].append(rule)

    # Every technique that applies here, plus anything a deployed rule or a
    # template claims that the platform filter did not select. The second half
    # matters: dropping a technique your own rule claims would make the report
    # disagree with the tenant, so it is carried and its basis says why ATT&CK
    # did not select it.
    universe = dict(candidates or {})
    extra = (set(by_technique) | set(claimed)) - set(universe)

    rows = []
    for tech in sorted(set(universe) | extra):
        tables = sorted(by_technique[tech])
        fed = sorted(t for t in tables if t in live_tables)
        rules_here = claimed.get(tech, [])
        products = (product_coverage or {}).get(tech)

        if products:
            # Takes precedence over a deployed rule, because it changes the
            # recommendation: something is already catching this, so a
            # detection for it should not be suggested. The rule, if there is
            # one, is named rather than lost.
            gap_type = "covered_by_product"
            basis = (f"{', '.join(products)} has alerted on {tech} in this "
                     "tenant within the window"
                     + (f"; {plural(len(rules_here), 'deployed rule')} also "
                        f"{'claims' if len(rules_here) == 1 else 'claim'} it"
                        if rules_here else ""))
        elif rules_here:
            # Only rules that can still fire count as coverage. A disabled rule,
            # or one the health leg rated never-fires or broken, is a detection
            # somebody believes they have.
            alive = [r for r in rules_here if can_fire(r) is not False]
            dead = [r for r in rules_here if can_fire(r) is False]
            unverified = [r for r in alive if can_fire(r) is None]
            # A rule's OWN tables decide whether it can fire, not every table
            # that could theoretically detect the technique.
            rule_fed = sorted({t for r in alive
                               for t in r.get("tables_referenced", [])
                               if t in live_tables})
            if not alive:
                gap_type = "rule_cannot_fire"
                basis = (f"{plural(len(dead), 'deployed rule')} "
                         f"{'claims' if len(dead) == 1 else 'claim'} {tech} and none can "
                         f"fire: " + ", ".join(sorted(
                             f"{r.get('name') or 'unnamed'} ({_why_dead(r)})"
                             for r in dead)))
            elif rule_fed:
                gap_type = "covered"
                basis = (f"{plural(len(alive), 'deployed rule')} "
                         f"{'claims' if len(alive) == 1 else 'claim'} {tech}; "
                         f"reading {', '.join(rule_fed)} which hold data")
                if unverified:
                    basis += (f"; {len(unverified)} of them was not health "
                              "checked on this run, so this is unverified")
                if dead:
                    basis += (f"; {plural(len(dead), 'further rule')} "
                              f"{'claims' if len(dead) == 1 else 'claim'} it and "
                              "cannot fire")
            else:
                gap_type = "needs_confirmation"
                basis = (f"{plural(len(alive), 'deployed rule')} "
                         f"{'claims' if len(alive) == 1 else 'claim'} {tech} but no "
                         "table they read holds data, so the rule cannot fire")
        elif not tables:
            # No installed template mentions it, so there is nothing to deploy
            # and no logging change that reaches it. Closing this needs
            # authored KQL or a Content Hub solution that is not installed.
            gap_type = "no_content"
            basis = (f"no deployed rule claims {tech} and no installed template "
                     "mentions it, so no table maps to it here")
        elif fed:
            gap_type = "available_not_deployed"
            basis = (f"no deployed rule claims {tech}; a template exists and "
                     f"{', '.join(fed[:4])} hold data")
        else:
            gap_type = "no_data_no_rule"
            basis = (f"no deployed rule claims {tech}, and none of "
                     f"{', '.join(tables[:4])} hold data")

        # Ground the id before reporting it. A template's technique is
        # Microsoft's claim; this is MITRE's answer, and where they disagree
        # the disagreement belongs in the basis rather than being smoothed over.
        grounded = mitre.ground(tech)
        if not grounded["usable"]:
            basis = f"{basis}. NOTE: {grounded['note']}"
        elif candidates is not None and tech not in universe:
            basis = (f"{basis}. NOTE: carried because content in this tenant "
                     "claims it, though it does not apply to any platform "
                     "measured here")
        rows.append({"technique_id": tech, "technique_name": grounded["name"],
                     "gap_type": gap_type, "basis": basis,
                     "supporting_tables": tables,
                     "tactics": grounded.get("tactics") or []})

    tally = collections.Counter(r["gap_type"] for r in rows)
    _ = product_coverage
    ungrounded = [r["technique_id"] for r in rows
                  if not mitre.ground(r["technique_id"])["usable"]]
    return rows, {"ran": True,
                  "detail": (f"{mitre.version_note()}; "
                             + (f"{len(ungrounded)} id(s) did not ground cleanly: "
                                f"{', '.join(sorted(ungrounded)[:8])}. "
                                if ungrounded else "every id grounded. ")
                             ) + f"{len(rows)} candidate technique(s): "
                            + ", ".join(f"{n} {k}" for k, n in tally.most_common())
                            + (f". The candidate set is ATT&CK narrowed to the "
                               f"platforms measured here ({len(universe)} technique(s)), "
                               f"plus {len(extra)} that content in this tenant claims "
                               "outside it -- NOT the installed template list, which "
                               "would measure Content Hub against itself."
                               if candidates is not None else
                               ". Candidates are techniques the installed templates "
                               "mention, which measures Content Hub against itself.")
                            + " `covered_by_product` is observed from SecurityAlert; "
                              "`plan_available_not_enabled` stays unassigned, because "
                              "a plan that is off produces no alerts to observe."}
