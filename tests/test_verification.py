"""Measuring a detection against the events it claims to detect.

Three checks already ask whether a query is well FORMED -- the static validator
reads its text, the offline engine resolves its columns, the workspace confirms
it executes. A detection passed all three and could never fire:

    Update service principal    30 real events    0 rows

It filtered `modifiedProperties` display names against the Graph API's schema
names, where the log writes `Included Updated Properties`. Nothing in the query
text says that. It is a fact about the data.

The asymmetry is the load-bearing idea. Fewer rows than events is often right --
these detections exclude failures and known Microsoft apps deliberately. More
rows than events is never right, because no filter can add matches.
"""

import pytest

from pylon.models import DetectionVerification
from pylon.verification import DEFECTS, summarise, verdict, widen


class TestVerdict:
    def test_equal_counts_are_exact(self):
        assert verdict(41, 41)[0] == "exact"

    def test_no_rows_against_real_events_is_dead(self):
        """The failure this module exists for."""
        call, detail = verdict(30, 0)
        assert call == "dead"
        assert "30" in detail

    def test_more_rows_than_events_is_a_defect_not_a_question(self):
        """A filter cannot add matches, so this needs no interpretation."""
        call, detail = verdict(2, 4)
        assert call == "over"
        assert "x2.00" in detail

    def test_fewer_rows_than_events_is_a_question_not_a_defect(self):
        """Excluding failed operations and known Microsoft apps is the point."""
        call, _ = verdict(70, 49)
        assert call == "under"
        assert "under" not in DEFECTS

    def test_no_events_is_not_a_pass(self):
        """A quiet workspace looks exactly like a detection that cannot fire."""
        call, _ = verdict(0, 0)
        assert call == "no-ground-truth"
        assert call not in DEFECTS, "untested must never count as passed"

    def test_a_query_that_did_not_run_is_an_error(self):
        assert verdict(5, None)[0] == "error"


class TestWiden:
    def test_the_detections_own_bound_is_replaced(self):
        """Bounded to an hour, a detection is invisible to a 30-day comparison:
        the window can narrow its bound, never widen it."""
        got, changed = widen("AuditLogs | where TimeGenerated > ago(1h)", "30d")
        assert got.endswith("ago(30d)") and changed

    @pytest.mark.parametrize("bound", ["ago(1h)", "ago( 24h )", "ago(30m)", "ago(7d)"])
    def test_every_duration_shape_is_caught(self, bound):
        got, changed = widen(f"T | where TimeGenerated > {bound}", "30d")
        assert changed and "ago(30d)" in got

    def test_a_query_with_no_bound_is_reported_unchanged(self):
        got, changed = widen("AuditLogs | take 1", "30d")
        assert got == "AuditLogs | take 1" and not changed


def test_the_summary_counts_every_verdict():
    rows = [DetectionVerification(vector_name=str(i), operation="o", verdict=v)
            for i, v in enumerate(["exact", "exact", "over", "dead"])]
    assert summarise(rows) == {"exact": 2, "over": 1, "dead": 1}


# --- ground truth must be counted on the column the TABLE uses ---------------
# The harness counted `OperationName` on every table. AuditLogs and the
# data-plane tables carry that column; AzureActivity carries OperationNameValue
# and leaves OperationName empty. So an ARM detection reported "no events of this
# operation" for a role assignment triggered an hour earlier -- the ground truth
# counted zero and the verdict became no-ground-truth, which is the unfalsifiable
# pass this whole module refuses to issue. Once counted on the right column the
# same detection reads: 136 real events, 0 rows, dead.

import pytest

from pylon.services import operation_column


@pytest.mark.parametrize("table,column", [
    ("AuditLogs", "OperationName"),
    ("AZKVAuditLogs", "OperationName"),
    ("AzureActivity", "OperationNameValue"),
])
def test_each_table_is_counted_on_its_own_operation_column(table, column):
    assert operation_column(table) == column


def test_the_arm_table_does_not_use_the_auditlogs_spelling():
    """The specific confusion that produced a silent zero."""
    assert operation_column("AzureActivity") != operation_column("AuditLogs")


# --- three ways this harness reported a defect that was not there ------------
# Every one produced a `dead` or an `error` on a detection that was fine, which
# is the same sin the harness exists to catch in the detections themselves.

from pylon.verification import aggregates


class TestWidenReachesBoundWindows:
    """Most generated detections bind the duration first.

        let lookback = 1h;
        AZKVAuditLogs | where TimeGenerated >= ago(lookback)

    Rewriting only a literal `ago(1h)` left those on their own one-hour window
    against month-old events. Six of seven Key Vault detections read `dead`.
    """

    def test_a_bound_window_is_widened(self):
        got, changed = widen("let lookback = 1h;\nT | where TimeGenerated >= ago(lookback)", "30d")
        assert changed and "let lookback = 30d;" in got

    def test_a_threshold_is_not_mistaken_for_a_window(self):
        """`let threshold = 5;` is a count, and rewriting it to 30d is nonsense."""
        got, changed = widen("let threshold = 5;\nT | where n >= threshold", "30d")
        assert not changed and "threshold = 5" in got

    def test_a_window_and_a_threshold_together(self):
        kql = ("let lookback = 24h;\nlet threshold = 5;\n"
               "T | where TimeGenerated >= ago(lookback) | where n >= threshold")
        got, changed = widen(kql, "30d")
        assert changed
        assert "lookback = 30d" in got and "threshold = 5" in got


class TestAggregatingDetectionsAreNotDefects:
    """A detection that groups returns GROUPS. Comparing that to an event count
    is a category error, and it reported two correct threshold rules as dead."""

    def test_a_summarizing_query_is_recognised(self):
        assert aggregates("T | summarize n=count() by X | where n >= 5")

    def test_a_plain_filter_is_not(self):
        assert not aggregates('T | where OperationName == "SecretPurge" | project X')

    def test_zero_rows_from_an_aggregate_is_not_dead(self):
        call, _ = verdict(8, 0, groups=True)
        assert call == "aggregates"
        assert call not in DEFECTS, "a threshold rule quiet on benign data is correct"


# The two classes here tested `operation_for`, which matched a detection back
# to its plan entry by name through three successive fallbacks. It is gone, and
# so are they: the name is not a key, and `design verify` now reads the
# operation the detection records. See the note where the function used to live.


# --- a dedupe is not an aggregation -----------------------------------------
# AzureActivity is commonly written twice, by an export and a connector sharing
# an EventDataId. A detection that joins Start to Success must collapse that or
# one grant becomes four alerts. The collapse is spelled `summarize take_any(*)
# by EventDataId`, and reading it as a grouping made a correct ARM detection
# unmeasurable -- it reported `aggregates` on a query with one row per event.

DEDUPE = "| summarize take_any(*) by EventDataId"


def test_a_dedupe_alone_is_not_an_aggregation():
    assert not aggregates(f'AzureActivity | where X == "y" {DEDUPE} | project A')


def test_a_real_aggregation_is_still_caught_alongside_a_dedupe():
    """Only the dedupe is exempt; a genuine grouping after it still counts."""
    assert aggregates(f"AzureActivity {DEDUPE} | summarize n=count() by Caller | where n >= 5")


def test_a_plain_aggregation_is_unaffected():
    assert aggregates("AuditLogs | summarize n=count() by X | where n >= 5")


# --- the queries inside a playbook ------------------------------------------
# A playbook carries six to ten queries a responder pastes under pressure and
# nothing had ever run one. `check_playbook` validates the document against its
# template -- fourteen sections, fenced queries, no unfilled blank -- and passes
# on a playbook whose KQL cannot execute. Same gap as the detections: well
# formed is not working.
#
# The blocks are NOT independent. The first is a prelude of `let` statements and
# every later block reads it, so running them one at a time reports failures on
# a document that is fine. That mistake was made twice before this existed.

from pylon.verification import RESPONDER_FILLS, blocks, runnable

PLAYBOOK = """# IR Playbook: X

## Fill these in first
```kql
let AlertTime   = datetime([FROM ALERT: TimeGenerated]);
let AlertActor  = "[FROM ALERT: ActorUpn]";
let AllowedActors = _GetWatchlist('ApprovedAutomation') | project SearchKey;
```

## Triage
```kql
AZKVAuditLogs
| where TimeGenerated > AlertTime
| where tostring(Identity.claim.upn) == AlertActor
```

## Validation
```kql
let ContainmentTime = datetime([TIME YOU RAN CONTAINMENT]);
AZKVAuditLogs | where TimeGenerated > ContainmentTime | count
```
"""

VALUES = {"time": "2026-09-11T18:43:30Z", "actor": "a@b.com", "actor_id": "oid",
          "src_ip": "1.2.3.4", "target": "/subscriptions/x", "correlation_id": "c",
          "window": "24h"}


def test_the_prelude_is_not_run_as_a_query():
    """It is only `let` statements. Reporting it as a failure says nothing."""
    assert len(blocks(PLAYBOOK)) == 3
    assert len(runnable(PLAYBOOK, VALUES)) == 2


def test_every_query_carries_the_prelude_it_reads():
    """Run alone, these fail on an unresolved AlertTime -- which is how this was
    first reported as six broken playbook queries."""
    for query in runnable(PLAYBOOK, VALUES):
        assert "let AlertTime" in query


def test_the_responder_blanks_are_filled():
    for query in runnable(PLAYBOOK, VALUES):
        assert "[FROM ALERT" not in query
        assert "2026-09-11T18:43:30Z" in query


def test_a_containment_time_is_filled_bare():
    """The template already writes `datetime([TIME YOU RAN CONTAINMENT])`.
    Substituting `datetime(...)` yields `datetime(datetime(...))` and a parse
    error that reads as a playbook bug. It was one."""
    query = runnable(PLAYBOOK, VALUES)[1]
    assert "datetime(datetime(" not in query
    assert "datetime(2026-09-11T18:43:30Z)" in query


def test_sentinel_only_functions_are_swapped():
    """`_GetWatchlist` is Sentinel, not KQL, and the prelude reaches every query."""
    for query in runnable(PLAYBOOK, VALUES):
        assert "_GetWatchlist" not in query


def test_a_document_with_only_a_prelude_yields_nothing():
    assert runnable("# X\n```kql\nlet A = 1;\n```\n", VALUES) == []


def test_every_declared_blank_maps_to_an_alert_field():
    assert all(RESPONDER_FILLS.values()), "a blank mapped to nothing fills with ''"


# --- coverage must count a run by what it was ASKED for ---------------------
# `report.service` holds the TABLE on the Entra path: an `Entra RoleManagement`
# run records "AuditLogs" there, which matches no target in the catalogue. Nine
# runs counted as seven, and the two it dropped were the only Entra ones -- so
# the number under-reported exactly the plane it could not name. The plan
# records what was asked for, and that is a target on every path.

def test_the_entra_path_records_a_table_not_a_target():
    """The reason coverage cannot match on report.service alone."""
    import json
    from pathlib import Path

    for plan_path in Path(".").glob("*/plan.json"):
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        report_path = plan_path.with_name("report.json")
        if not report_path.is_file():
            continue
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if (plan.get("target") or "").startswith("Entra"):
            assert report.get("service") == "AuditLogs", (
                "if this ever holds the target, the plan fallback can go")
            assert plan["target"] != report["service"], (
                "the two fields disagree, which is why coverage reads the plan")
            return
    import pytest
    pytest.skip("no Entra run in this working tree to check against")
