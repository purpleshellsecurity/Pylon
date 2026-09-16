"""What `sentinelhealth.probe` reads out of SentinelHealth.

Every KQL field named here is checked against Microsoft's SentinelHealth table
reference. The three findings this file covers all live inside runs Sentinel
reports as SUCCESSFUL, which is why no failure count reaches them.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from pylon import sentinelhealth


def _proc(rows, code=0, err=""):
    return subprocess.CompletedProcess(
        [], code, stdout=json.dumps(rows), stderr=err)


class _Az:
    """Answers each query by matching a phrase in the KQL it is handed."""

    def __init__(self, answers: dict):
        self.answers = answers
        self.seen: list[str] = []

    def __call__(self, guid, kql, timeout=None):
        self.seen.append(kql)
        for phrase, rows in self.answers.items():
            if phrase in kql:
                return _proc(rows)
        return _proc([])


SUMMARY = [{"SentinelResourceType": "Analytics rule",
            "SentinelResourceName": "R", "SentinelResourceKind": "Scheduled",
            "Status": "Success", "events": 10, "newest": "2026-09-01T00:00:00Z"}]


def _probe(monkeypatch, answers):
    az = _Az({"summarize events=count()": SUMMARY, **answers})
    monkeypatch.setattr(sentinelhealth.azcli, "query", az)
    detail, read = sentinelhealth.probe("guid")
    return detail, read, az


def test_the_prebuilt_functions_are_used_not_the_raw_tables(monkeypatch):
    """Microsoft asks for `_SentinelHealth()` and `_SentinelAudit()` so a query
    survives a schema change. Querying the tables directly does not."""
    _d, _r, az = _probe(monkeypatch, {})
    assert az.seen, "no queries ran"
    for kql in az.seen:
        assert "_SentinelHealth()" in kql or "_SentinelAudit()" in kql
        assert not kql.startswith("SentinelHealth ")
        assert not kql.startswith("SentinelAudit ")


def test_resource_type_is_never_compared_case_sensitively(monkeypatch):
    """The schema reference says `Analytics rule`; every sample query on the
    monitoring page says `Analytics Rule`. `=~` is right either way."""
    _d, _r, az = _probe(monkeypatch, {})
    for kql in az.seen:
        assert "SentinelResourceType ==" not in kql


def test_a_connector_type_in_another_case_is_still_a_connector(monkeypatch):
    az = _Az({"summarize events=count()": [
        {"SentinelResourceType": "DATA CONNECTOR", "SentinelResourceName": "AzureAD",
         "SentinelResourceKind": "AzureActiveDirectory", "Status": "Success",
         "events": 5, "newest": "2026-09-01T00:00:00Z"}]})
    monkeypatch.setattr(sentinelhealth.azcli, "query", az)
    detail, _read = sentinelhealth.probe("guid")
    assert "AzureAD" in detail["connectors"]


TUNE = "sum(toint(p.QueryResultAmount))"


def test_matched_rows_with_no_alerts_is_a_threshold_finding(monkeypatch):
    detail, _r, _az = _probe(monkeypatch, {TUNE: [
        {"rule": "Rare process", "runs": 720, "ok": 720, "alerts": 0,
         "matched": 412, "dropped": 0, "threshold": 500, "op": "GreaterThan"}]})
    assert detail["below_threshold"] == [
        {"rule": "Rare process", "runs": 720, "matched": 412, "dropped": 0,
         "threshold": 500, "operator": "GreaterThan"}]
    assert detail["entity_drops"] == []


def test_dropped_entities_are_a_separate_finding_from_the_threshold_one(monkeypatch):
    detail, _r, _az = _probe(monkeypatch, {TUNE: [
        {"rule": "Suspicious logon", "runs": 30, "ok": 30, "alerts": 12,
         "matched": 90, "dropped": 47, "threshold": 1, "op": "GreaterThan"}]})
    assert [r["rule"] for r in detail["entity_drops"]] == ["Suspicious logon"]
    # It fired twelve alerts, so it is not a threshold problem.
    assert detail["below_threshold"] == []


def test_one_rule_can_be_both(monkeypatch):
    detail, _r, _az = _probe(monkeypatch, {TUNE: [
        {"rule": "Both", "runs": 5, "ok": 5, "alerts": 0, "matched": 9,
         "dropped": 2, "threshold": 20, "op": "GreaterThan"}]})
    assert [r["rule"] for r in detail["below_threshold"]] == ["Both"]
    assert [r["rule"] for r in detail["entity_drops"]] == ["Both"]


def test_a_rule_that_never_ran_successfully_is_not_a_threshold_finding(monkeypatch):
    """`ok == 0` means every run failed. That is the failure list's finding,
    and calling it a tuning problem would send the reader to the wrong fix."""
    detail, _r, _az = _probe(monkeypatch, {TUNE: [
        {"rule": "Broken", "runs": 5, "ok": 0, "alerts": 0, "matched": 3,
         "dropped": 0, "threshold": 1, "op": "GreaterThan"}]})
    assert detail["below_threshold"] == []


def test_six_failures_on_one_window_is_a_skipped_window(monkeypatch):
    detail, _r, _az = _probe(monkeypatch, {"failures >= 6": [
        {"rule": "Impossible travel", "windows": 3}]})
    assert detail["skipped_windows"] == [
        {"rule": "Impossible travel", "windows": 3}]


def test_the_skipped_window_query_counts_at_least_six_not_exactly_six(monkeypatch):
    """A scheduled rule gets six attempts on a window. Microsoft's sample tests
    `== 6`, which a duplicated health record would slip past."""
    _d, _r, az = _probe(monkeypatch, {})
    skip = [k for k in az.seen if "windows=count()" in k]
    assert skip and "failures >= 6" in skip[0]
    assert "SentinelResourceKind =~ 'scheduled'" in skip[0]


def test_a_query_that_errored_is_not_reported_as_nothing_found(monkeypatch):
    def az(guid, kql, timeout=None):
        if "summarize events=count()" in kql:
            return _proc(SUMMARY)
        return _proc([], code=1, err="query failed")
    monkeypatch.setattr(sentinelhealth.azcli, "query", az)
    detail, _read = sentinelhealth.probe("guid")
    assert detail["tuning_read"] is False and detail["skipped_read"] is False
    assert detail["below_threshold"] == [] and detail["skipped_windows"] == []


def test_no_rows_at_all_means_the_feature_is_off_not_that_all_is_well(monkeypatch):
    monkeypatch.setattr(sentinelhealth.azcli, "query",
                        lambda guid, kql, timeout=None: _proc([]))
    detail, read = sentinelhealth.probe("guid")
    assert detail == {"enabled": False, "days": 30}
    assert read["ran"] is False and "off" in read["detail"]


@pytest.mark.parametrize("field", [
    "AlertsGeneratedAmount", "QueryResultAmount", "TriggerThreshold",
    "TriggerOperator", "EntitiesDroppedDueToMappingIssuesAmount",
    "QueryStartTimeUTC",
])
def test_every_extended_property_read_is_one_microsoft_documents(monkeypatch, field):
    """Guards against a field name drifting to something plausible that the
    health table does not actually carry, which would read as zero findings."""
    _d, _r, az = _probe(monkeypatch, {})
    assert any(field in kql for kql in az.seen), field


# ── how often each rule ran, not just how many runs succeeded ────────────────
# `rule_events` counts Success against Failure across the whole workspace, so
# it can only ever produce a finding when something is wrong. A tenant where
# nothing is wrong gets silence from every block on the page -- exactly when it
# wants the opposite. Per-rule counts also make the sharp finding possible: a
# rule that ran thousands of times, reported success every time, and was
# searching a table with no data in it.

PER_RULE = "by rule=SentinelResourceName"


def test_each_rule_reports_its_own_run_count(monkeypatch):
    detail, _r, _az = _probe(monkeypatch, {PER_RULE: [
        {"rule": "Busy", "runs": 8640, "failed": 0, "newest": "2026-09-12T04:00:00Z"},
        {"rule": "Quiet", "runs": 7, "failed": 0, "newest": "2026-09-11T20:00:00Z"}]})
    assert [r["rule"] for r in detail["rule_runs"]] == ["Busy", "Quiet"]
    assert detail["rule_runs"][0]["runs"] == 8640
    assert detail["rule_runs_read"] is True


def test_failed_runs_are_counted_per_rule_not_only_workspace_wide(monkeypatch):
    """A rule failing every run and a workspace with one bad hour produce the
    same total. Which rule it is, is the part a reader can act on."""
    detail, _r, _az = _probe(monkeypatch, {PER_RULE: [
        {"rule": "Broken", "runs": 100, "failed": 100,
         "newest": "2026-09-12T04:00:00Z"}]})
    assert detail["rule_runs"][0]["failed"] == 100


def test_a_query_that_did_not_run_is_not_a_workspace_where_nothing_ran(monkeypatch):
    """The distinction the whole module exists to keep. An empty `rule_runs`
    with `rule_runs_read` false means the read failed; the report must not
    render "0 rules ran"."""
    az = _Az({"summarize events=count()": SUMMARY})
    def _fail(guid, kql, timeout=None):
        if PER_RULE in kql:
            return _proc([], code=1, err="query failed")
        return az(guid, kql)
    monkeypatch.setattr(sentinelhealth.azcli, "query", _fail)
    detail, _read = sentinelhealth.probe("guid")
    assert detail["rule_runs"] == [] and detail["rule_runs_read"] is False


def test_the_per_rule_read_uses_the_prebuilt_function_too(monkeypatch):
    _d, _r, az = _probe(monkeypatch, {PER_RULE: []})
    per_rule = [k for k in az.seen if PER_RULE in k]
    assert per_rule, "the per-rule query never ran"
    assert "_SentinelHealth()" in per_rule[0]
    assert "SentinelResourceType =~" in per_rule[0]
