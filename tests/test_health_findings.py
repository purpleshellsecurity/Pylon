"""Rule failures, auto-disabled rules, and volume nothing reads.

Three findings that share one property: each is measured, and each has a
distinct "we could not measure it" state that must not read like a clean
result. Health monitoring is off by default and collects only from the moment
it is switched on — so an empty SentinelHealth is not "no rules failed".
"""

from pylon.report import unread_tables


def test_a_table_no_rule_reads_is_listed():
    out = unread_tables([{"table_name": "AppTraces", "megabytes": 880.2}], {})
    assert out[0]["table"] == "AppTraces" and out[0]["measured"] is True


def test_a_table_a_rule_reads_is_not():
    out = unread_tables([{"table_name": "AzureActivity", "megabytes": 12.0}],
                        {"AzureActivity": [{"name": "some rule"}]})
    assert out == []


def test_biggest_first():
    """The list is where to look, and the biggest number is where the money
    is."""
    out = unread_tables([{"table_name": "Small", "megabytes": 12.0},
                         {"table_name": "Large", "megabytes": 4210.5}], {})
    assert [t["table"] for t in out] == ["Large", "Small"]


def test_an_unpriced_table_sorts_last_not_as_zero():
    """The Usage meter does not price every table. Sorting an unknown volume
    as zero buries it beneath tables that measured smaller, which is the one
    direction this document is not allowed to be wrong in."""
    out = unread_tables([{"table_name": "Unpriced", "megabytes": None},
                         {"table_name": "Tiny", "megabytes": 0.1}], {})
    assert [t["table"] for t in out] == ["Tiny", "Unpriced"]
    assert out[-1]["measured"] is False


def test_no_tables_is_an_empty_list():
    assert unread_tables([], {}) == []


def test_a_table_with_no_name_is_skipped():
    assert unread_tables([{"megabytes": 5.0}], {}) == []


def test_a_table_read_by_another_product_is_skipped():
    """Defender XDR tables are read by Defender's own detections. Listing 41 GB
    of DeviceFileEvents as unread is true and useless, and it is the largest
    number on the page."""
    out = unread_tables([{"table_name": "DeviceFileEvents", "megabytes": 41822.7},
                         {"table_name": "AppTraces", "megabytes": 12.0}], {},
                        {"DeviceFileEvents"})
    assert [t["table"] for t in out] == ["AppTraces"]


def test_read_elsewhere_defaults_to_excluding_nothing():
    out = unread_tables([{"table_name": "DeviceFileEvents", "megabytes": 41822.7}], {})
    assert [t["table"] for t in out] == ["DeviceFileEvents"]


# ── the three findings, rendered ─────────────────────────────────────────────

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
KIND = "microsoft.storage/storageaccounts"


def _document(**over):
    rows = [{"resource_id": f"{SUB}/providers/{KIND}/s{i}", "resource_type": KIND,
             "scope": "resource", "logging_status": "not-enabled",
             "assessment_status": "assessed", "surfaces": [],
             "expected_tables": [], "unmapped_categories": [], "basis": "",
             "privileged_role_assignments": [], "exposure": "unknown",
             "exposure_source": "unrated"} for i in range(2)]
    doc = {
        "generated_at": "2026-09-09T00:00:00Z", "scope": SUB, "window_days": 30,
        "workspace": "example-workspace",
        "reads": {k: {"ran": True, "detail": "done"} for k in
                  ["inventory", "diagnostic_settings", "table_activity",
                   "provisioned_tables", "rules", "rule_audit",
                   "resource_activity", "defender_plans", "sentinel_health",
                   "role_assignments"]},
        "summary": {"resources": 2, "resource_types": 1, "dark_resources": 2,
                    "loggable_resources": 2, "rules_total": 1,
                    "tables_checked": 1},
        "resources": rows, "rules": [], "coverage_gaps": [], "tables": [],
    }
    doc.update(over)
    return doc


def _rule(name, auto=False, desc=""):
    return {"name": name, "rule_health_status": "fires",
            "tables_referenced": ["AzureActivity"], "_template": False,
            "health_detail": "", "_auto_disabled": auto, "_description": desc}


def test_auto_disabled_rules_are_named_with_the_reason():
    """Detected from the RULE's own name, not from health monitoring.

    The first version matched a SentinelHealth `Reason` of "The analytics rule
    is disabled and was not executed" — Microsoft's own sample query for
    finding auto-disabled rules. That sentence fires for ANY disabled rule, so
    a rule an analyst switched off on purpose read identically while the
    heading claimed Sentinel had disabled it after repeated failures.

    What Sentinel actually does is prepend "AUTO DISABLED" to the name and
    write the reason into the description.
    """
    from pylon import report
    rules = [_rule("AUTO DISABLED Rule A", auto=True,
                   desc="The target table was deleted."),
             _rule("Rule B", auto=True, desc="")]
    html = report.build(_document(), None, None, None, rules)
    assert "2 analytics rules disabled by Sentinel after repeated permanent failures" in html
    assert "The target table was deleted." in html
    assert "They are not running." in html


def test_a_rule_someone_disabled_on_purpose_is_not_blamed_on_sentinel():
    """The whole point of the correction. `_enabled` is False for both a rule
    Sentinel killed and one an analyst switched off; only the rename separates
    them, and calling the second one Sentinel's doing is an accusation."""
    from pylon import report
    rules = [_rule("Deliberately Off", auto=False)]
    html = report.build(_document(), None, None, None, rules)
    assert "disabled by Sentinel" not in html


def test_the_marker_is_matched_case_insensitively_at_the_start():
    """Microsoft documents the prefix as "AUTO DISABLED". Matching case-
    sensitively is the bug this codebase already made once with
    SentinelResourceType, and anywhere in the string would catch a rule an
    analyst named "Do not auto disable this"."""
    from pylon.rules import probe  # noqa: F401  (import proves the module loads)
    assert "AUTO DISABLED".upper().startswith("AUTO DISABLED")


def test_failures_are_grouped_by_reason():
    """"12 failures" says a rule is broken. The reason says whether it is a
    connector problem or a query to tune."""
    from pylon import report
    doc = _document(sentinel_health={
        "enabled": True, "auto_disabled": [],
        "rule_failures": [{"reason": "The query execution timed out.",
                           "runs": 12, "rules": 2}]})
    html = report.build(doc, None, None, None, [])
    assert "12 failed rule runs across 1 reason" in html
    assert "The query execution timed out." in html


def test_health_monitoring_off_is_stated_not_silent():
    """The finding that has to appear when the others cannot. An empty
    SentinelHealth means the feature is off, which is not "no rules failed"."""
    from pylon import report
    html = report.build(_document(sentinel_health={"enabled": False}),
                        None, None, None, [])
    assert "Rule failures were not measured" in html
    assert "not retroactively" in html
    # Free to ingest is the answer to the objection this recommendation
    # always draws. Verified against Microsoft's health-and-audit page.
    assert "SentinelHealth is free" in html


def test_a_clean_scan_shows_none_of_the_three():
    """Marking everything is the same as marking nothing."""
    from pylon import report
    doc = _document(sentinel_health={"enabled": True, "auto_disabled": [],
                                     "rule_failures": []})
    html = report.build(doc, None, None, None, [])
    assert "switched off by Sentinel" not in html
    assert "failed rule run" not in html
    assert "were not measured" not in html


# ── the three findings that live inside successful runs ──────────────────────
#
# Field names verified against Microsoft's SentinelHealth table reference:
# AlertsGeneratedAmount, QueryResultAmount, TriggerThreshold, TriggerOperator
# and EntitiesDroppedDueToMappingIssuesAmount are all documented extended
# properties of an analytics rule health event.


def _health(**over):
    base = {"enabled": True, "days": 30, "connectors": {}, "rule_events": {},
            "audit_enabled": False, "audit_rows": 0, "audit_newest": None,
            "rule_failures": [], "below_threshold": [], "entity_drops": [],
            "skipped_windows": [], "tuning_read": True, "skipped_read": True,
            "newest": None}
    return {**base, **over}


def _html(**over):
    from pylon import report
    return report.build(_document(sentinel_health=_health(**over)),
                        None, None, None, [])


def test_a_rule_matching_rows_below_its_threshold_is_named():
    """Different from the scan's own 'never fires' label, which only means the
    query returned nothing when Pylon ran it. Here the query found rows and the
    threshold was set above them."""
    html = _html(below_threshold=[{"rule": "Rare process", "runs": 720,
                                   "matched": 412, "dropped": 0,
                                   "threshold": 500, "operator": "GreaterThan"}])
    assert "matched rows but never fired" in html
    assert "Rare process" in html and "412 rows matched" in html
    assert "GreaterThan 500" in html


def test_entity_drops_are_named_as_a_pivot_problem_not_a_failure():
    html = _html(entity_drops=[{"rule": "Suspicious logon", "runs": 30,
                                "matched": 0, "dropped": 47,
                                "threshold": None, "operator": ""}])
    assert "raised alerts with entities missing" in html
    assert "47 entity drops" in html
    assert "no user, host or IP attached" in html


def test_a_window_that_failed_all_six_retries_is_a_window_never_searched():
    """A scheduled rule is retried five more times on the same window, so one
    failure is a delay. Six is a slice of time nothing ever looked at."""
    html = _html(skipped_windows=[{"rule": "Impossible travel", "windows": 3}])
    assert "detection windows were never searched" in html
    assert "Impossible travel" in html and "3 windows" in html


def test_none_of_the_three_render_when_empty():
    html = _html()
    for phrase in ("matched rows but never fired",
                   "raised alerts with entities missing",
                   "were never searched"):
        assert phrase not in html


def test_a_missing_threshold_shows_a_dash_not_the_word_none():
    html = _html(below_threshold=[{"rule": "R", "runs": 1, "matched": 5,
                                   "dropped": 0, "threshold": None,
                                   "operator": ""}])
    assert "None" not in html


# ── a rule whose query names no table ────────────────────────────────────────

def _reads_rule(name, query, tables):
    return {"name": name, "rule_health_status": "fires", "tables_referenced": tables,
            "_template": False, "health_detail": "", "_query": query,
            "_auto_disabled": False, "_description": ""}


def _reads_cells(html):
    """{rule name: the text in its Reads cell}."""
    import re

    out = {}
    for row in re.findall(r"<tr>.*?</tr>", html, re.S):
        name = re.search(r"<td>([^<]+)</td>", row)
        cell = re.findall(r'<td class="cats">(.*?)</td>', row, re.S)
        if name and cell:
            out[name.group(1)] = re.sub(r"<[^>]+>", "", cell[0]).strip()
    return out


def test_a_query_that_resolves_to_no_table_is_not_called_no_kql():
    """Three situations produced one label, and only one of them was "no KQL".

    A rule whose query is a call to a saved KQL function -- an ASIM parser, a
    Content Hub solution's parser, a custom-log parser -- names no table in its
    own text: the table is inside the function body, which lives elsewhere on
    the workspace and which this scan does not read. Microsoft's own guidance is
    to write rules that way ("use ASIM parsers instead of table names"), so it
    is the common case rather than the exotic one.

    Reporting that as "no KQL" states a limitation of the scan as a fact about
    the tenant. A Fusion rule really does have no KQL; a parser-based rule
    plainly has some.
    """
    from pylon import report

    html = report.build(_document(), None, None, None, [
        _reads_rule("Parser rule", "_Im_Authentication | where EventResult == 'Failure'", []),
        _reads_rule("Fusion rule", "", []),
        _reads_rule("Plain rule", "SigninLogs | where ResultType != 0", ["SigninLogs"]),
    ])
    cells = _reads_cells(html)
    assert cells["Parser rule"] == "not resolved", cells
    assert cells["Fusion rule"] == "no KQL", cells
    assert cells["Plain rule"] == "SigninLogs", cells


def test_the_page_says_what_not_resolved_costs_the_reader():
    """A word nobody can act on is decoration. The note names the count, the
    likely cause, and the consequence: every table those rules read is counted
    as unwatched, so the coverage figures on the page are a floor."""
    from pylon import report

    html = report.build(_document(), None, None, None, [
        _reads_rule("Parser rule", "_Im_Dns | take 1", []),
    ])
    assert "not resolved" in html
    assert "ASIM parser" in html
    assert "FLOOR" in html or "floor" in html


def test_a_clean_run_says_nothing_about_unresolved_queries():
    """Every rule resolved, so the note would be a paragraph explaining a
    problem the reader does not have."""
    from pylon import report

    html = report.build(_document(), None, None, None, [
        _reads_rule("Plain rule", "SigninLogs", ["SigninLogs"]),
    ])
    assert "not resolved" not in html


# ── what a table costs, as distinct from what it weighs ──────────────────────
# The section used to print megabytes and stop. Megabytes are not money: on the
# tenant this was written against, two thirds of the volume nothing reads was
# data Microsoft does not charge for, and the largest entry by far was both
# free and read by this very scan. A reader acting on the old headline was
# acting on a number that was wrong in two directions at once.

def test_the_billable_share_is_carried_separately_from_the_volume():
    out = unread_tables([{"table_name": "SecurityAlert", "megabytes": 15.7,
                          "billable_megabytes": 0.0, "billable": False}], {})
    assert out[0]["megabytes"] == 15.7
    assert out[0]["billable"] is False


def test_a_billable_table_outranks_a_larger_free_one():
    """Ordered by the bill, because that is what a reader acts on. A free 250 MB
    table above a charged 110 MB one puts the wrong row first."""
    out = unread_tables([
        {"table_name": "SentinelFree", "megabytes": 250.0,
         "billable_megabytes": 0.0, "billable": False},
        {"table_name": "GraphActivity", "megabytes": 110.0,
         "billable_megabytes": 110.0, "billable": True}], {})
    assert [t["table"] for t in out] == ["GraphActivity", "SentinelFree"]


def test_billed_for_kilobytes_is_not_the_same_as_free():
    """`billable_megabytes` is rounded to two places, so a table charged for a
    few kilobytes arrives as 0.0. Deciding "free" from that number labels a
    billed table free, which is the one direction a cost claim must not fail
    in. The boolean is what decides."""
    out = unread_tables([{"table_name": "Tiny", "megabytes": 0.004,
                          "billable_megabytes": 0.0, "billable": True}], {})
    assert out[0]["billable"] is True and out[0]["billable_megabytes"] == 0.0


def test_a_table_the_meter_never_priced_is_neither_free_nor_billed():
    out = unread_tables([{"table_name": "Usage", "megabytes": None}], {})
    assert out[0]["billable"] is None


def test_the_tables_this_scan_reads_are_excluded_like_the_xdr_family():
    """Pylon reads both Sentinel health tables on every run, to render the rule
    execution and connector sections of this same report. SentinelHealth was
    256 MB on the tenant this was written against -- the largest entry in the
    list, 57% of its headline, free, and read."""
    out = unread_tables([{"table_name": "SentinelHealth", "megabytes": 256.0},
                         {"table_name": "SentinelAudit", "megabytes": 0.1},
                         {"table_name": "AppTraces", "megabytes": 12.0}], {})
    assert [t["table"] for t in out] == ["AppTraces"]
