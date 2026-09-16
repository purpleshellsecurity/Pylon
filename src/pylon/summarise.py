"""Headline counts, computed once so no renderer computes them again.

Two rules the model states and this enforces.

Counts whose leg is optional are None when it did not run; the
always-measured core stays an int. A zero and a not-measured are different
claims and a renderer cannot tell them apart after the fact.

`techniques_covered`, `_ambiguous` and `_uncovered` PARTITION the candidate
set, and `techniques_no_telemetry` is deliberately kept out of the three: a
technique this tenant produces no telemetry for is not a candidate that went
uncovered, it is not a candidate. Folding it in is how an uncovered count
doubles overnight because logging was switched off somewhere.
"""

from __future__ import annotations

import collections
from datetime import datetime, timezone

BILLABLE_TIERS = {"Basic", "Auxiliary"}


def build(resources, rules, tables, gaps, coverage_gaps, fresh_days: int) -> dict:
    out: dict = {}

    # -- always measured -------------------------------------------------
    now = datetime.now(timezone.utc)
    fresh = 0
    for t in tables:
        if not t.last_ingest:
            continue
        seen = t.last_ingest
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        if (now - seen).total_seconds() <= fresh_days * 86400:
            fresh += 1
    out["fresh_tables"] = fresh
    # A table holding data that the technique index has no opinion on. Named
    # for the field that already ships; it is a worklist for the index, not a
    # finding about the tenant.
    out["unindexed_tables"] = sum(1 for t in tables if t.is_gap)

    by_type = collections.Counter(g.gap_type for g in gaps)
    # A technique a product is already detecting is covered. Counting only
    # rule-covered ones leaves the three-way partition short by exactly the
    # product-covered set, which is the arithmetic the model relies on.
    out["techniques_covered"] = by_type["covered"] + by_type["covered_by_product"]
    out["techniques_ambiguous"] = by_type["needs_confirmation"]
    # `rule_cannot_fire` is uncovered, not covered. Nothing is watching the
    # technique; the difference from `available_not_deployed` is that here the
    # detection was already built and is not running, which is a different fix
    # and a worse surprise.
    out["techniques_uncovered"] = (by_type["available_not_deployed"]
                                   + by_type["data_no_rule"]
                                   + by_type["rule_cannot_fire"])
    out["techniques_no_telemetry"] = by_type["no_data_no_rule"]
    out["rules_total"] = len(rules)

    # -- optional legs ---------------------------------------------------
    health = collections.Counter(r.rule_health_status for r in rules
                                 if r.rule_health_status)
    if health:
        out["rules_executed"] = sum(health.values())
        out["fires"] = health.get("fires", 0)
        out["never_fires"] = health.get("never-fires", 0)
        out["inconclusive"] = health.get("inconclusive", 0)
        out["unreadable"] = health.get("unreadable", 0)
        out["broken_rules"] = health.get("broken", 0)
        out["not_run_billable"] = health.get("not-assessed", 0)
        # The subset only running the rule reveals: its table HAS data and it
        # still returns nothing, so no static check could have found it.
        fed = {t.table_name for t in tables}
        out["never_fires_on_live_tables"] = sum(
            1 for r in rules if r.rule_health_status == "never-fires"
            and any(t in fed for t in r.tables_referenced))

    resource_rows = [r for r in resources if r.scope == "resource"]
    if resource_rows:
        out["resources"] = len(resource_rows)
        out["resource_types"] = len({r.resource_type for r in resource_rows})
        out["dark_resources"] = sum(1 for r in resource_rows
                                    if r.logging_status == "not-enabled")
        out["loggable_resources"] = sum(1 for r in resource_rows
                                        if r.assessment_status == "assessed")
    if tables:
        out["tables_checked"] = len(tables)
        out["tables_billable"] = sum(1 for t in tables
                                     if t.table_tier in BILLABLE_TIERS)

    # The uncovered technique with the most tables able to detect it: the one
    # with the least excuse, since the telemetry is already there.
    candidates = [g for g in gaps if g.gap_type in ("available_not_deployed",
                                                    "data_no_rule")]
    if candidates:
        heaviest = max(candidates, key=lambda g: (len(g.supporting_tables),
                                                  g.technique_id))
        out["heaviest_gap"] = heaviest.technique_id
        out["heaviest_gap_name"] = heaviest.technique_name or None
    return out
