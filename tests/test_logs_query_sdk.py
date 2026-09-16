"""The SDK query path, and the reason it exists.

`validate` shells out to `az monitor log-analytics query`, which is deliberate:
free commands must run on a base install. It costs 115 MB and 1.7 s per query,
which is nothing for the two queries a `validate` run makes and expensive for a
sweep -- ten detections verified is twenty processes.

It also DISCARDS why a query failed. Azure said

    Query could not be parsed at '|' on line [60,1]

and the caller kept only a non-zero exit code, so the tool reported "the count
query did not run" and nothing that would lead anyone to the semicolon.

Both paths ship, so both are tested. The SDK is preferred when installed; the
CLI runs when it is not.
"""

from datetime import datetime, timedelta, timezone

import pytest

from pylon import validate

pytest.importorskip("azure.monitor.query", reason="SDK is in the `design` extra")

from pylon import logs_query  # noqa: E402


class _Err(Exception):
    """Shaped like a REAL HttpResponseError, captured from the service.

    The first link is an object with attributes; everything below it is a plain
    dict. An earlier version of this stub made the whole chain objects, so it
    passed while the real thing returned only "The request had some invalid
    properties" -- a stub that agreed with the code instead of with Azure.
    """

    class _Top:
        def __init__(self, message, innererror):
            self.message, self.innererror = message, innererror

    def __init__(self):
        super().__init__("The request had some invalid properties")
        self.error = self._Top(
            "The request had some invalid properties",
            {"code": "SyntaxError",
             "message": "A recognition error occurred in the query.",
             "innererror": {"code": "SYN0002",
                            "message": "Query could not be parsed at '|' on line [60,1]",
                            "line": 60, "pos": 1}})


@pytest.mark.parametrize("spec,want", [
    ("P30D", timedelta(days=30)), ("PT1H", timedelta(hours=1)),
    ("PT30M", timedelta(minutes=30)), ("PT10S", timedelta(seconds=10)),
])
def test_a_window_becomes_the_duration_the_sdk_wants(spec, want):
    assert logs_query.to_timespan(spec) == want


def test_an_explicit_interval_becomes_a_datetime_pair():
    got = logs_query.to_timespan("2026-09-01T00:00:00Z/2026-09-02T00:00:00Z")
    assert got == (datetime(2026, 9, 1, tzinfo=timezone.utc),
                   datetime(2026, 9, 2, tzinfo=timezone.utc))


def test_a_window_that_is_neither_is_refused():
    with pytest.raises(logs_query.BadTimespan):
        logs_query.to_timespan("last tuesday")


def test_the_nested_explanation_is_what_surfaces():
    """The top-level message names nothing; the answer is two levels down."""
    got = logs_query._reason(_Err())
    assert "line [60,1]" in got, got
    assert got.startswith("Query could not be parsed"), (
        "the sentence naming the line must LEAD; burying it behind two useless "
        "ones is how the CLI path hid it: " + got)


def test_a_failed_query_carries_azures_words_up_to_the_caller(monkeypatch):
    monkeypatch.setattr(validate, "_sdk", lambda: _StubSdk(fail=True))
    hits, sample, detail = validate.hunt("AuditLogs", "guid", "P7D")
    assert hits is None, "a failed search must never read as zero hits"
    assert sample == []
    assert "line [60,1]" in detail, detail


def test_rows_come_back_as_dicts(monkeypatch):
    monkeypatch.setattr(validate, "_sdk", lambda: _StubSdk(count=3))
    hits, _sample, _detail = validate.hunt("AuditLogs", "guid", "P7D")
    assert hits == 3


class _StubSdk:
    """Stands in for `logs_query`, which is the seam validate imports through."""

    def __init__(self, fail=False, count=0):
        self.fail, self.count = fail, count

    def query(self, guid, kql, timespan):
        if self.fail:
            return None, logs_query._reason(_Err())
        if kql.rstrip().endswith("| count"):
            return [{"Count": self.count}], ""
        return [{"TimeGenerated": "x"}] * self.count, ""
