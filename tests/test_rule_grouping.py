"""Rules that cannot fire, grouped by the empty tables they read.

Twenty-six rows one per rule made a reader count thirteen problems where the
tenant had two empty tables. Grouping says it once.

Grouped by FACT, not by cause. The key is "the tables this rule reads that
hold no data" — measured. Writing "8 rules cannot fire BECAUSE AKSAudit is
empty" is true for a rule reading one empty table and a guess for a rule
reading two, where the other may be full of rows that simply do not match.
"""

from pylon.report import group_dead_rules


def rule(name, status, tables):
    return {"name": name, "rule_health_status": status,
            "tables_referenced": list(tables)}


def test_rules_reading_the_same_empty_table_become_one_group():
    rules = [rule(f"K8s {i}", "never-fires", ["AKSAudit"]) for i in range(8)]
    out = group_dead_rules(rules, with_data={"AzureActivity"})
    assert len(out) == 1
    assert out[0]["count"] == 8 and out[0]["tables"] == ["AKSAudit"]


def test_different_empty_tables_stay_separate():
    """Two empty tables are two findings with two different fixes."""
    rules = ([rule(f"K8s {i}", "never-fires", ["AKSAudit"]) for i in range(8)]
             + [rule(f"Blob {i}", "never-fires", ["StorageBlobLogs"]) for i in range(5)])
    out = group_dead_rules(rules, with_data=set())
    assert [g["tables"] for g in out] == [["AKSAudit"], ["StorageBlobLogs"]]
    assert [g["count"] for g in out] == [8, 5]


def test_a_rule_whose_tables_all_have_data_is_kept_apart():
    """The case where nothing shared explains it. Folding it in with the
    others would invent a cause for the one rule where none is known."""
    rules = [rule("K8s", "never-fires", ["AKSAudit"]),
             rule("Keys listed", "never-fires", ["AzureActivity"])]
    out = group_dead_rules(rules, with_data={"AzureActivity"})
    unexplained = [g for g in out if g["unexplained"]]
    assert len(unexplained) == 1
    assert unexplained[0]["names"] == ["Keys listed"]


def test_the_unexplained_group_sorts_last():
    """It is the one with no shared fix behind it, so it does not lead."""
    rules = ([rule("Keys listed", "never-fires", ["AzureActivity"])]
             + [rule(f"K8s {i}", "never-fires", ["AKSAudit"]) for i in range(3)])
    out = group_dead_rules(rules, with_data={"AzureActivity"})
    assert out[-1]["unexplained"] is True


def test_a_rule_reading_two_tables_groups_on_the_empty_ones_only():
    """The key is which of its tables hold nothing — a table that HAS data is
    not part of why this rule is quiet, so it does not belong in the key."""
    rules = [rule("Mixed", "never-fires", ["AzureActivity", "AKSAudit"])]
    out = group_dead_rules(rules, with_data={"AzureActivity"})
    assert out[0]["tables"] == ["AKSAudit"]


def test_only_rules_that_cannot_fire_are_grouped():
    """A working rule is not a finding, and a rejected query is a different
    one with its own message."""
    rules = [rule("Works", "fires", ["AzureActivity"]),
             rule("Rejected", "broken", ["AKSAudit"]),
             rule("Untested", "unreadable", ["AKSAudit"]),
             rule("Dead", "never-fires", ["AKSAudit"])]
    out = group_dead_rules(rules, with_data=set())
    assert sum(g["count"] for g in out) == 1
    assert out[0]["names"] == ["Dead"]


def test_no_dead_rules_is_an_empty_list():
    assert group_dead_rules([rule("Works", "fires", ["AzureActivity"])],
                            with_data={"AzureActivity"}) == []


def test_names_are_sorted_so_two_runs_read_alike():
    rules = [rule("Zebra", "never-fires", ["AKSAudit"]),
             rule("Alpha", "never-fires", ["AKSAudit"])]
    out = group_dead_rules(rules, with_data=set())
    assert out[0]["names"] == ["Alpha", "Zebra"]
