"""`design survey` must count what a detection can MATCH, not what happened.

Blob storage recorded 95 `ListContainers` events in thirty days and not one of
them under OAuth -- 92% of that table authenticates with an account key, a SAS,
or Azure's own internal service, none of which name a principal. The KQL rules
require a detection to gate on `AuthenticationType == "OAuth"` before reporting
an actor, so such a detection can never match one of those 95 rows.

Survey counted the 95 and called the vector gradable. The money was spent, the
detection came back `no-match`, and the zero only became visible afterwards --
which is the exact waste survey exists to prevent, arriving through survey.

Tables with no attribution gate count as they always did: `countif(true)`.
"""
import argparse

import pytest

from pylon import cli


class _Recorder:
    """Captures the KQL survey runs, and answers with fixed counts."""

    def __init__(self, rows):
        self.queries = []
        self._rows = rows

    def __call__(self, kql, _guid, _window):
        self.queries.append(kql)
        return self._rows


@pytest.fixture
def _plan(tmp_path):
    import json

    (tmp_path / "plan.json").write_text(json.dumps({
        "target": "Microsoft.Storage/storageAccounts/blobServices",
        "attack_vectors": [
            {"name": "Container enumeration", "operation": "ListContainers",
             "log_table": "StorageBlobLogs"},
            {"name": "Blob download", "operation": "GetBlob",
             "log_table": "StorageBlobLogs"},
        ],
    }), encoding="utf-8")
    return tmp_path


def _run(monkeypatch, plan_dir, rows, capsys):
    from pylon import validate as validate_mod

    rec = _Recorder(rows)
    monkeypatch.setattr(validate_mod, "_run_kql", rec)
    monkeypatch.setattr(validate_mod, "resolve", lambda _w: ("t", "a", "guid"))
    monkeypatch.setattr(validate_mod, "parse_window", lambda w: w)
    code = cli._design_survey(argparse.Namespace(
        source=str(plan_dir), workspace="ws", window="30d"))
    out = capsys.readouterr()
    return code, out.out + out.err, rec


def test_the_query_counts_reachable_rows_separately(monkeypatch, _plan, capsys):
    _code, _text, rec = _run(monkeypatch, _plan, [
        {"Op": "ListContainers", "n": 95, "reachable": 0},
        {"Op": "GetBlob", "n": 16, "reachable": 3},
    ], capsys)
    assert rec.queries, "survey ran no query"
    q = rec.queries[0]
    assert "countif(" in q, q
    assert 'AuthenticationType == "OAuth"' in q, (
        "the contract's attribution gate is not in the count")


def test_an_operation_that_never_names_anybody_is_not_gradable(monkeypatch, _plan, capsys):
    _code, text, _rec = _run(monkeypatch, _plan, [
        {"Op": "ListContainers", "n": 95, "reachable": 0},
        {"Op": "GetBlob", "n": 16, "reachable": 3},
    ], capsys)
    assert "1 of 2 can be graded" in text, text
    # And the --pick line must not offer the unreachable one. Vector 1 is
    # ListContainers, vector 2 is GetBlob.
    pick = [ln for ln in text.splitlines() if "--pick" in ln]
    assert pick, text
    assert '"2"' in pick[0], pick[0]


def test_both_numbers_are_shown_because_the_gap_is_the_finding(monkeypatch, _plan, capsys):
    """A bare 0 reads as a quiet tenant. "95 events, 0 reachable" says the
    operation runs constantly and never attributably."""
    _code, text, _rec = _run(monkeypatch, _plan, [
        {"Op": "ListContainers", "n": 95, "reachable": 0},
        {"Op": "GetBlob", "n": 16, "reachable": 3},
    ], capsys)
    assert "reachable" in text
    assert "95" in text and "16" in text
    assert "DID happen and were never attributable" in text, text


def test_a_table_with_no_gate_counts_exactly_as_before(monkeypatch, tmp_path, capsys):
    """AZKVAuditLogs has no attribution gate, so `countif(true)` and the
    reachable column is not shown at all."""
    import json

    (tmp_path / "plan.json").write_text(json.dumps({
        "target": "Microsoft.KeyVault/vaults",
        "attack_vectors": [{"name": "Secret read", "operation": "SecretGet",
                            "log_table": "AZKVAuditLogs"}],
    }), encoding="utf-8")
    _code, text, rec = _run(monkeypatch, tmp_path,
                            [{"Op": "SecretGet", "n": 7, "reachable": 7}], capsys)
    assert "countif(true)" in rec.queries[0], rec.queries[0]
    assert "reachable" not in text, "a gateless table should not grow a column"
    assert "1 of 1 can be graded" in text
