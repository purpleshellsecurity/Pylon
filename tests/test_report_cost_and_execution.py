"""The two sections that say what the telemetry costs and whether it is watched.

Both exist because the report could previously go quiet at the moment a
customer most wanted an answer:

    COST        the unread-ingestion section printed megabytes and stopped.
                Megabytes are not money. On the tenant this was written
                against, most of the volume nothing read was data Microsoft
                does not charge for, and the single largest entry was both
                free AND read by this scan.

    EXECUTION   every health finding rendered only on a fault, so a workspace
                where nothing had failed got a blank page where the proof
                should be -- and no way to see that two fifths of all rule
                execution was searching a table with no data in it.
"""

import re

import pytest

from pylon import report

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"


def _res():
    return {"resource_id": f"{SUB}/resourceGroups/rg/providers/microsoft.foo/bars/x",
            "resource_type": "microsoft.foo/bars", "scope": "resource",
            "logging_status": "fully-enabled", "assessment_status": "assessed",
            "surfaces": [], "expected_tables": [], "unmapped_categories": [],
            "basis": "synthetic", "privileged_role_assignments": [],
            "exposure": "unknown", "exposure_source": "unrated"}


def _doc(**over):
    doc = {
        "generated_at": "2026-09-12T00:00:00Z", "scope": SUB, "window_days": 30,
        "workspace": "example-workspace",
        "reads": {"inventory": {"ran": True, "detail": ""},
                  "rules": {"ran": True, "detail": ""},
                  "table_activity": {"ran": True, "detail": ""},
                  "sentinel_health": {"ran": True, "detail": ""}},
        "summary": {"resources": 1, "resource_types": 1, "dark_resources": 0,
                    "loggable_resources": 1, "rules_total": 2,
                    "tables_checked": 3},
        "resources": [_res()], "rules": [], "coverage_gaps": [],
        "tables": [
            {"table_name": "GraphActivity", "table_tier": "Analytics",
             "last_ingest": "2026-09-12T00:00:00Z", "megabytes": 111.9,
             "billable_megabytes": 111.9, "billable": True},
            {"table_name": "SecurityAlert", "table_tier": "Analytics",
             "last_ingest": "2026-09-12T00:00:00Z", "megabytes": 15.7,
             "billable_megabytes": 0.0, "billable": False},
        ],
        "workspace_plan": {"sku": "PerGB2018", "commitment_gb_per_day": None,
                           "retention_days": 30},
    }
    doc.update(over)
    return doc


def _section(html, eyebrow):
    found = re.search(rf'<div class="eyebrow">{eyebrow}</div>.*?</section>',
                      html, re.S)
    return found.group(0) if found else ""


# ── cost ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def unread(monkeypatch):
    monkeypatch.setenv("PYLON_PRICE_GB", "4.00")
    return _section(report.build(_doc(), None, None, None, None),
                    "Unread ingestion")


def test_the_heading_states_the_billable_share_not_the_raw_volume(unread):
    """127.6 MB arrives; 111.9 MB of it is charged for. A heading quoting the
    first number invoices the customer for data Microsoft gives away."""
    assert "112 MB of it billable" in unread
    assert "$0.44" in unread          # 111.9 MB at $4.00/GB


def test_a_free_source_is_labelled_free_rather_than_priced_at_zero(unread):
    row = re.search(r"SecurityAlert.*?</tr>", unread, re.S).group(0)
    assert "free" in row
    assert "$0.00" not in row


def test_the_rate_and_the_plan_it_applies_to_are_both_stated(unread):
    """A per-GB figure with no stated basis is unfalsifiable: the reader cannot
    tell whether it applies to them."""
    assert "$4.00/GB" in unread
    assert "PerGB2018" in unread
    assert "PYLON_PRICE_GB" in unread


def test_a_workspace_whose_plan_could_not_be_read_says_so(monkeypatch):
    monkeypatch.setenv("PYLON_PRICE_GB", "4.00")
    unread = _section(report.build(_doc(workspace_plan=None), None, None, None, None),
                      "Unread ingestion")
    assert "could not be read" in unread
    assert "PerGB2018" not in unread


def test_a_commitment_tier_is_named_because_it_is_bought_below_list(monkeypatch):
    monkeypatch.setenv("PYLON_PRICE_GB", "4.00")
    unread = _section(report.build(_doc(workspace_plan={
        "sku": "CapacityReservation", "commitment_gb_per_day": 100,
        "retention_days": 90}), None, None, None, None), "Unread ingestion")
    assert "100 GB/day" in unread
    assert "below list" in unread


# ── execution ────────────────────────────────────────────────────────────────

RULES = [
    {"rule_id": "1", "name": "Watches a dead table", "rule_severity": "High",
     "rule_health_status": "never-fires", "health_detail": "",
     "technique_mapping_confidence": "none", "techniques": [],
     "tables_referenced": ["AKSAudit"]},
    {"rule_id": "2", "name": "Watches a live table", "rule_severity": "High",
     "rule_health_status": "fires", "health_detail": "",
     "technique_mapping_confidence": "none", "techniques": [],
     "tables_referenced": ["GraphActivity"]},
    {"rule_id": "BuiltInFusion", "name": "Advanced Multistage Attack Detection",
     "rule_severity": "High", "rule_health_status": "not-assessed",
     "health_detail": "", "technique_mapping_confidence": "none",
     "techniques": [], "tables_referenced": []},
]

HEALTH = {
    "enabled": True, "days": 30, "connectors": {}, "rule_events": {},
    "audit_enabled": True, "audit_rows": 2, "audit_newest": "2026-08-30T19:09:50Z",
    "rule_failures": [], "below_threshold": [], "entity_drops": [],
    "skipped_windows": [], "tuning_read": True, "skipped_read": True,
    "rule_runs_read": True,
    "rule_runs": [
        {"rule": "Watches a dead table", "runs": 8640, "failed": 0,
         "newest": "2026-09-12T04:26:07Z"},
        {"rule": "Watches a live table", "runs": 2880, "failed": 0,
         "newest": "2026-09-12T04:17:16Z"}],
}


def _execution(**health_over):
    health = {**HEALTH, **health_over}
    return _section(report.build(_doc(sentinel_health=health), None, None, None,
                                 RULES), "Rule execution")


def test_a_healthy_workspace_still_gets_a_section(monkeypatch):
    """The whole point. Every other health block renders only on a fault, so a
    tenant with nothing wrong got no proof that anything was running."""
    out = _execution()
    assert "2 of 3 analytics rules ran 11,520 times" in out
    assert "None failed." in out


def test_runs_against_a_table_with_no_data_are_counted_and_named(monkeypatch):
    """Success means the query ran, not that the rule can ever fire. This is
    the finding the coverage half of the report cannot make."""
    out = _execution()
    assert "8,640 of those runs" in out
    assert "75% of all rule execution" in out
    assert "Watches a dead table" in out


def test_a_rule_reading_one_live_table_and_one_dead_one_is_not_counted_wasted():
    """It can still fire. Counting it as wasted execution overstates the
    finding, and this section only works if its number is defensible."""
    rules = RULES + [{"rule_id": "4", "name": "Mixed", "rule_severity": "High",
                      "rule_health_status": "fires", "health_detail": "",
                      "technique_mapping_confidence": "none", "techniques": [],
                      "tables_referenced": ["GraphActivity", "AKSAudit"]}]
    health = {**HEALTH, "rule_runs": HEALTH["rule_runs"] + [
        {"rule": "Mixed", "runs": 1000, "failed": 0,
         "newest": "2026-09-12T04:00:00Z"}]}
    out = _section(report.build(_doc(sentinel_health=health), None, None, None,
                                rules), "Rule execution")
    assert "8,640 of those runs" in out
    wasted = re.search(r"searched a table with no data</h4>.*?</div>", out, re.S)
    assert "Mixed" not in wasted.group(0)


def test_a_rule_with_no_execution_record_is_explained_not_flagged():
    """Fusion has no KQL of its own, so the service decides its health and it
    writes nothing here. Reading that absence as a fault is wrong."""
    out = _execution()
    assert "Advanced Multistage Attack Detection" in out
    assert "expected, not a gap" in out


def test_failed_runs_replace_the_none_failed_claim():
    out = _execution(rule_runs=[{"rule": "Watches a live table", "runs": 100,
                                 "failed": 7, "newest": "2026-09-12T04:00:00Z"}])
    assert "7 of those runs failed" in out
    assert "None failed." not in out


def test_a_read_that_did_not_run_renders_no_section():
    """An empty `rule_runs` from a failed query must not render "0 rules ran"."""
    assert _execution(rule_runs=[], rule_runs_read=False) == ""


# ── connectors ───────────────────────────────────────────────────────────────

def _connectors(**health_over):
    health = {**HEALTH, "connectors": {
        "Office365-Exchange": {"events": 684, "newest": "2026-09-12T03:38:49Z",
                               "statuses": {"Success": 682, "Informational": 2},
                               "kind": "Office365"},
        "MCAS-Alerts": {"events": 10, "newest": "2026-09-01T00:00:00Z",
                        "statuses": {"Failure": 10}, "kind": "MCAS"}},
        **health_over}
    return _section(report.build(_doc(sentinel_health=health), None, None, None,
                                 RULES), "Connector health")


def test_each_connector_reports_when_it_last_said_anything():
    out = _connectors()
    assert "2 connectors reporting in" in out
    assert "2026-09-12 03:38" in out


def test_a_failing_connector_is_not_shown_as_healthy():
    out = _connectors()
    row = re.search(r"MCAS-Alerts.*?</tr>", out, re.S).group(0)
    assert "chip--none" in row and "Failure" in row


def test_an_audit_trail_that_is_off_is_stated_as_a_finding():
    """Changes to rules and connectors leaving no trail is worth saying, and it
    is a separate switch from health monitoring."""
    out = _connectors(audit_enabled=False, audit_rows=0, audit_newest=None)
    assert "leave no trail" in out
