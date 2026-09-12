"""`pylon validate` -- searching the workspace for a written detection's hits.

Was `prove.py`, which recorded whether a NAMED RULE had raised an alert. That
direction was dropped; this is the one that was wanted. The module also had no
tests of its own -- the file named for it exercised a function in `sentinel`.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from pylon import validate

class _Ran:
    """A finished subprocess, shaped like the ones `az` returns.

    Stubbed at `azcli.subprocess.run`, beneath the runner rather than in place
    of it, so these still exercise azcli's own handling -- a timeout and a
    missing `az` become failed calls there, and a test that replaced `azcli.run`
    would never see that."""

    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


@pytest.mark.parametrize("spec,iso", [
    ("7d", "P7D"), ("24h", "PT24H"), ("30m", "PT30M"), ("90s", "PT90S"),
    (" 7d ", "P7D"),
])
def test_a_kql_duration_becomes_a_timespan(spec, iso):
    assert validate.parse_window(spec) == iso


@pytest.mark.parametrize("spec", ["7", "d", "7 days", "-1d", "0d", ""])
def test_a_window_that_cannot_be_read_is_refused_not_guessed(spec):
    """Guessing here searches a window the operator did not ask for and reports
    the result as if they had."""
    with pytest.raises(validate.BadWindow):
        validate.parse_window(spec)


def test_an_explicit_window_becomes_an_interval():
    start = datetime(2026, 9, 1, tzinfo=timezone.utc)
    end = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    assert validate.timespan_between(start, end) == (
        "2026-09-01T00:00:00Z/2026-09-07T12:00:00Z"
    )


def test_an_end_before_its_start_is_refused():
    start = datetime(2026, 9, 7, tzinfo=timezone.utc)
    with pytest.raises(validate.BadWindow):
        validate.timespan_between(start, start - timedelta(days=1))


def test_a_search_that_failed_is_not_a_detection_that_found_nothing(monkeypatch):
    """Same distinction `observe` keeps. A broken query read as an empty result
    is how a bad detection gets called quiet."""
    monkeypatch.setattr(validate, "_sdk", lambda: None)  # CLI path
    monkeypatch.setattr(validate.azcli.subprocess, "run",
                        lambda *a, **k: _Ran(1, stderr="BadArgumentError"))
    hits, sample, detail = validate.hunt("AzureActivity", "guid", "P7D")
    assert hits is None, "a failed search must not read as zero hits"
    assert sample == []
    assert "did not run" in detail


def test_zero_rows_is_a_real_empty(monkeypatch):
    monkeypatch.setattr(validate, "_sdk", lambda: None)  # CLI path
    monkeypatch.setattr(validate.azcli.subprocess, "run",
                        lambda *a, **k: _Ran(0, stdout='[{"Count": 0}]'))
    hits, sample, _ = validate.hunt("AzureActivity", "guid", "P7D")
    assert (hits, sample) == (0, [])


def test_hits_come_back_with_a_capped_sample(monkeypatch):
    """A detection matching a million rows is a finding; printing them is not
    the way to deliver it."""
    calls = []

    def _fake(cmd, **kwargs):
        query = cmd[cmd.index("--analytics-query") + 1]
        calls.append(query)
        if query.endswith("| count"):
            return _Ran(0, stdout='[{"Count": 1000000}]')
        return _Ran(0, stdout=json.dumps([{"n": i} for i in range(validate.SAMPLE_ROWS)]))

    monkeypatch.setattr(validate, "_sdk", lambda: None)  # CLI path
    monkeypatch.setattr(validate.azcli.subprocess, "run", _fake)
    hits, sample, detail = validate.hunt("AzureActivity", "guid", "P7D")
    assert hits == 1000000
    assert len(sample) == validate.SAMPLE_ROWS
    assert "showing 5" in detail
    assert f"| take {validate.SAMPLE_ROWS}" in calls[1]


def test_the_window_reaches_the_query(monkeypatch):
    seen = {}

    def _fake(cmd, **kwargs):
        seen["timespan"] = cmd[cmd.index("--timespan") + 1]
        return _Ran(0, stdout='[{"Count": 0}]')

    monkeypatch.setattr(validate, "_sdk", lambda: None)  # CLI path
    monkeypatch.setattr(validate.azcli.subprocess, "run", _fake)
    validate.hunt("AzureActivity", "guid", "P7D")
    assert seen["timespan"] == "P7D"


@pytest.mark.parametrize("kql", [
    "AzureActivity | where TimeGenerated > ago(1h)",
    "let t = 1h; AzureActivity | where TimeGenerated >= ago(t)",
    "AzureActivity | where TimeGenerated between (ago(14d) .. ago(1d))",
])
def test_a_detection_that_bounds_its_own_time_earns_a_caveat(kql):
    """`--timespan` can narrow a query's own window, never widen it. So an empty
    result from a 1h detection means quiet in ITS hour, not across the 7 days
    the operator asked about."""
    assert validate.residual_time_bound(kql)


def test_an_unbounded_detection_needs_no_caveat():
    assert validate.residual_time_bound('AzureActivity | where Op =~ "x"') == ""


# ── how a matched row is shown ───────────────────────────────────────────────

from pylon.cli import _row_line  # noqa: E402


def test_the_columns_a_person_reads_first_come_first():
    """The first real run printed rows alphabetically, so `ActivityStatus` and
    `ActivitySubstatus` -- both blank -- ate the width and when/who/what fell off
    the end."""
    line = _row_line({
        "ActivityStatus": "", "ActivitySubstatus": "",
        "ActivityStatusValue": "Success",
        "Caller": "a@b.com", "TimeGenerated": "2026-09-07T09:41:02Z",
        "OperationNameValue": "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
    })
    assert line.startswith("TimeGenerated=")
    assert line.index("OperationNameValue=") < line.index("Caller=")


def test_blank_columns_are_dropped():
    """A blank column says nothing about why the row matched, and costs the
    width a populated one needs."""
    line = _row_line({"Empty": "", "Null": None, "Nothing": [], "Caller": "a@b.com"})
    assert line == "Caller=a@b.com"


def test_a_long_value_does_not_crowd_out_every_other_column():
    """`Authorization` on an AzureActivity row is a JSON blob longer than the
    whole line budget."""
    line = _row_line({
        "TimeGenerated": "2026-09-07T09:41:02Z",
        "Authorization": "x" * 4000,
        "Caller": "a@b.com",
    })
    assert "Caller=a@b.com" in line
    assert "..." in line
    assert len(line) < 300


def test_the_line_stays_within_its_budget_and_says_what_it_dropped():
    row = {f"Field{i:02d}": f"value-{i}" for i in range(40)}
    line = _row_line(row, width=120)
    assert len(line) <= 140  # the budget, plus the "(+N more)" marker
    assert "more)" in line


def test_a_row_that_is_not_a_mapping_still_prints():
    assert _row_line("scalar") == "scalar"


# --- an operator must be appendable to a compliant query --------------------
# The house rules require a let-statement query to END WITH A SEMICOLON, and
# `hunt` appends `| count` to search for it. Against a real workspace that is:
#     Query could not be parsed at '|' on line [60,1]
# reported all the way up as "the count query did not run" -- so the tool could
# not search for exactly the detections that followed the rule, and said only
# that the search had failed.

from pylon.validate import _pipeable


def test_a_trailing_terminator_is_removed_so_an_operator_can_follow():
    assert _pipeable("AuditLogs\n| project X;") == "AuditLogs\n| project X"


def test_only_the_trailing_terminator_goes():
    """The semicolons between let statements are part of the query."""
    kql = "let A = dynamic([]);\nlet B = 1h;\nAuditLogs\n| take 1;"
    assert _pipeable(kql) == "let A = dynamic([]);\nlet B = 1h;\nAuditLogs\n| take 1"


def test_a_query_without_a_terminator_is_unchanged():
    kql = "AzureActivity\n| take 1"
    assert _pipeable(kql) == kql


def test_trailing_whitespace_after_the_terminator_is_handled():
    assert _pipeable("AuditLogs\n| take 1;  \n\n") == "AuditLogs\n| take 1"
