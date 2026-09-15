"""A rule reading no table the scan could name is not a rule reading full ones.

`group_dead_rules` keyed on "the tables this rule reads that hold no data", and
two different situations produce an empty tuple there:

  * every table the rule reads has data arriving -- a real finding, and the
    report says so: "matched nothing, and every table it reads holds data";
  * no table was resolved at all.

The second is common rather than exotic. A rule whose query calls a saved KQL
function -- an ASIM parser, a Content Hub solution's parser -- names no table in
its own text, and Microsoft's own guidance is to write rules that way. The scan
reads rule text and does not open function bodies.

Filing the second under the first tells a reader every table is arriving when
the scan identified none. The rules table one section above is careful about
exactly this: `_reads_cell` distinguishes "no KQL" from "not resolved" for the
same reason.
"""

from pylon.report import build, group_dead_rules

WITH_DATA = {"AzureActivity", "SigninLogs"}


def dead(name, tables):
    return {"name": name, "rule_health_status": "never-fires",
            "tables_referenced": tables, "_query": "Whatever | count"}


def test_an_unresolved_rule_is_not_called_fully_fed():
    groups = group_dead_rules([dead("ASIM parser rule", [])], WITH_DATA)
    assert len(groups) == 1
    assert groups[0]["unresolved"] is True
    assert groups[0]["unexplained"] is False, (
        "claims every table it reads holds data, having resolved none")


def test_a_genuinely_fed_rule_still_says_so():
    groups = group_dead_rules([dead("Fed rule", ["AzureActivity"])], WITH_DATA)
    assert groups[0]["unexplained"] is True
    assert groups[0]["unresolved"] is False


def test_the_two_do_not_share_a_group():
    groups = group_dead_rules(
        [dead("ASIM parser rule", []), dead("Fed rule", ["SigninLogs"])], WITH_DATA)
    assert len(groups) == 2, groups
    assert [g["names"] for g in groups] == [["Fed rule"], ["ASIM parser rule"]]


def test_an_empty_table_group_is_unaffected():
    groups = group_dead_rules(
        [dead("A", ["AKSAudit"]), dead("B", ["AKSAudit"])], WITH_DATA)
    assert groups[0]["tables"] == ["AKSAudit"]
    assert groups[0]["count"] == 2
    assert groups[0]["unexplained"] is False and groups[0]["unresolved"] is False


def test_the_unresolved_group_sorts_last():
    """Nothing was established about it, so it is not where a reader starts."""
    groups = group_dead_rules(
        [dead("Unresolved", []), dead("Fed", ["AzureActivity"]),
         dead("Empty", ["AKSAudit"])], WITH_DATA)
    assert [g["names"][0] for g in groups] == ["Empty", "Fed", "Unresolved"]


def test_the_rendered_heading_says_the_scan_could_not_tell():
    html = build(
        {"generated_at": "2026-09-08T00:00:00Z", "window_days": 30,
         "scope": "/subscriptions/0", "workspace": "w", "summary": {},
         "reads": {}, "resources": [], "rules": [], "coverage_gaps": [],
         "tables": [{"table_name": "AzureActivity", "table_tier": "Analytics",
                     "last_ingest": "2026-09-08T00:00:00Z", "megabytes": 1.0}]},
        None, None, None, [dead("ASIM parser rule", [])],
    )
    assert "could not tell which table it reads" in html, html[:0] or "heading missing"
    assert "every table it reads holds data" not in html
