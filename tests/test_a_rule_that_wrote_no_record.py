"""Three reasons a deployed rule wrote no execution record, and one sentence.

The Rule execution section listed every deployed rule that Sentinel's execution
records do not mention, under a single explanation:

    A Fusion rule has no KQL of its own and the service decides its health, so
    it reports none. That is expected, not a gap.

True of Fusion, and asserted over the whole list. A rule someone switched off
writes no record either. So does one created after the window began, and so
does every rule on a workspace where health monitoring was switched on partway
through it -- which is the common case, because it is off by default and
collects only from the moment it is turned on.

"That is expected, not a gap" over a rule that is silently not being scheduled
is the report answering a question it did not ask.
"""

import re

from pylon.report import build

WORKSPACE = {
    "generated_at": "2026-09-08T00:00:00Z", "window_days": 30,
    "scope": "/subscriptions/0", "workspace": "w", "summary": {},
    "reads": {}, "resources": [], "rules": [], "coverage_gaps": [],
    "tables": [{"table_name": "AzureActivity", "table_tier": "Analytics",
                "last_ingest": "2026-09-08T00:00:00Z", "megabytes": 1.0}],
}


def rule(name, *, query="AzureActivity | count", enabled=True, kind="Scheduled"):
    return {"name": name, "rule_health_status": "fires",
            "tables_referenced": ["AzureActivity"] if query else [],
            "health_detail": "", "_query": query, "_enabled": enabled,
            "_kind": kind, "_template": None}


def _render(rule_detail, runs):
    health = {"enabled": True, "rule_runs_read": True, "rule_runs": runs}
    return build({**WORKSPACE, "sentinel_health": health}, None, None, None,
                 rule_detail)


RAN = [{"rule": "Ran", "runs": 100, "failed": 0, "newest": "2026-09-08T00:00:00Z"}]


def test_fusion_keeps_its_explanation():
    html = _render([rule("Ran"), rule("Fusion one", query=None, kind="Fusion")], RAN)
    assert "Fusion one" in html
    assert "expected, not a gap" in html


def test_a_disabled_rule_is_not_called_expected():
    html = _render([rule("Ran"), rule("Turned off", enabled=False)], RAN)
    assert "switched off in the workspace" in html
    assert "expected, not a gap" not in html, (
        "a rule someone disabled was explained as a Fusion rule")


def test_an_enabled_rule_with_a_query_gets_no_invented_cause():
    """The one that matters. It is enabled, it has KQL, and nothing recorded it
    running -- which this scan cannot tell from a rule created yesterday."""
    html = _render([rule("Ran"), rule("Silent", enabled=True)], RAN)
    assert "Silent" in html
    assert "expected, not a gap" not in html
    assert "cannot tell those from a rule that is not being scheduled" in html


def test_the_three_are_not_merged_into_one_sentence():
    html = _render(
        [rule("Ran"), rule("Fusion one", query=None, kind="Fusion"),
         rule("Turned off", enabled=False), rule("Silent")], RAN)
    notes = re.findall(r"wrote no execution record", html)
    assert len(notes) == 3, f"expected one note per cause, got {len(notes)}"


def test_a_workspace_where_everything_ran_says_nothing():
    html = _render([rule("Ran")], RAN)
    assert "wrote no execution record" not in html


def test_a_zero_run_record_does_not_end_the_report():
    """"x% of all rule execution" divided by a total that can be zero.

    An execution record with a run count of zero is enough: the finding still
    renders, and the division took the whole document down with it.
    """
    runs = [{"rule": "Never ran", "runs": 0, "failed": 0, "newest": None}]
    detail = [{**rule("Never ran"), "tables_referenced": ["NotATable"],
               "rule_health_status": "never-fires"}]
    html = _render(detail, runs)
    assert "searched a table with no data" in html
    assert "% of all rule execution" not in html, (
        "claimed a share of an execution total of zero")
