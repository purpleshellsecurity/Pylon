"""Log Analytics queries go through `az rest`, not through the extension.

`az monitor log-analytics query` rejects valid KQL. On a real tenant it
refused every rule that opens with a `let` statement — 24 of 26 — and each was
reported as `broken`, which reads as an accusation about the customer's
detections. It is a defect in the CLI: Azure/azure-cli-extensions#5147, open
and in Microsoft's backlog.

These hold the two things that matter: the KQL never reaches a command line,
and the row shape every other leg parses is unchanged.
"""

import json
import subprocess
from unittest import mock

import pytest

from pylon import azcli

LET_QUERY = "let w = 1d;\nAzureActivity\n| where TimeGenerated > ago(w)\n| count"

RESPONSE = json.dumps({"tables": [{"name": "PrimaryResult",
                                   "columns": [{"name": "T"}, {"name": "n"}],
                                   "rows": [["AzureActivity", 5]]}]})


@pytest.fixture
def ran():
    with mock.patch.object(azcli, "run") as fake:
        fake.return_value = subprocess.CompletedProcess([], 0, RESPONSE, "")
        yield fake


def test_the_kql_never_appears_on_the_command_line(ran):
    """The whole fix. A query with quotes, newlines and semicolons has no
    business as a command-line argument — it is the argument that broke."""
    azcli.query("guid", LET_QUERY)
    args = ran.call_args[0][0]
    assert not any("let w" in str(a) for a in args)
    assert not any("AzureActivity" in str(a) for a in args)


def test_the_kql_is_sent_as_a_json_body_file(ran):
    """Captured mid-call: the file is deleted before `query` returns, so
    reading it afterwards would find nothing."""
    seen = {}

    def capture(args, **kw):
        body = [a for a in args if str(a).startswith("@")][0]
        seen["query"] = json.load(open(str(body)[1:], encoding="utf-8"))["query"]
        return subprocess.CompletedProcess([], 0, RESPONSE, "")

    ran.side_effect = capture
    azcli.query("guid", LET_QUERY)
    assert seen["query"] == LET_QUERY


def test_the_temp_file_does_not_survive_the_call(ran):
    """One file per query, twelve legs, hundreds of queries. Leaving them
    behind fills a disk slowly enough that nobody connects the two."""
    paths = []

    def capture(args, **kw):
        paths.extend(str(a)[1:] for a in args if str(a).startswith("@"))
        return subprocess.CompletedProcess([], 0, RESPONSE, "")

    ran.side_effect = capture
    azcli.query("guid", "AzureActivity | count")
    import os
    assert paths and not any(os.path.exists(p) for p in paths)


def test_it_targets_the_logs_api_with_the_right_audience(ran):
    """`--resource` decides which audience the token is minted for. Without it
    az sends an ARM token, which this endpoint rejects."""
    azcli.query("the-guid", "AzureActivity | count")
    args = " ".join(str(a) for a in ran.call_args[0][0])
    assert "api.loganalytics.io/v1/workspaces/the-guid/query" in args
    assert "--resource https://api.loganalytics.io" in args


def test_callers_still_get_row_dicts(ran):
    """Twelve legs parse the shape the old command produced. Converting here
    is why none of them had to learn a second one."""
    out = azcli.query("guid", "AzureActivity | count")
    assert json.loads(out.stdout) == [{"T": "AzureActivity", "n": 5}]
    assert out.returncode == 0


def test_a_failed_call_is_passed_through_untouched(ran):
    """Its stderr is the reason a leg reports, so rewriting it would lose the
    explanation."""
    ran.return_value = subprocess.CompletedProcess([], 1, "", "not logged in")
    out = azcli.query("guid", "AzureActivity | count")
    assert out.returncode == 1 and out.stderr == "not logged in"


def test_a_zero_exit_with_unparseable_output_becomes_a_failure(ran):
    """Not a traceback, and not an empty result either — an empty result would
    read as "the tenant has none of this"."""
    ran.return_value = subprocess.CompletedProcess([], 0, "not json at all", "")
    out = azcli.query("guid", "AzureActivity | count")
    assert out.returncode != 0 and out.stderr


def test_an_empty_result_set_is_an_empty_list(ran):
    """A query that matched nothing is a real answer and must not look like a
    failure."""
    ran.return_value = subprocess.CompletedProcess(
        [], 0, json.dumps({"tables": [{"columns": [{"name": "T"}], "rows": []}]}), "")
    assert json.loads(azcli.query("guid", "X | count").stdout) == []


def test_a_response_with_no_tables_is_an_empty_list(ran):
    ran.return_value = subprocess.CompletedProcess([], 0, json.dumps({}), "")
    assert json.loads(azcli.query("guid", "X | count").stdout) == []
