"""Knowing what you can prove, and then proving it without a tenant.

Two gaps closed together, and they were the same gap in different places.

`design detections --pick all` built a service's whole operation vocabulary
while a tenant exercises a handful of it -- 39 of 169 planned operations had
ever happened, so 130 were bought at full price and returned `no-ground-truth`.
One query per table says so first, and costs nothing.

`design record` then wrote fixtures and NOTHING IN THE PRODUCT READ THEM.
`evaluate_fixture` worked and had no caller: the identical mistake as the
offline KQL engine being built and never wired, made again in the same session.
A module nobody can run is a feature nobody has.
"""

import argparse
import json

import pytest

from pylon import cli


def _plan(tmp_path, vectors):
    (tmp_path / "plan.json").write_text(json.dumps({
        "service": "Microsoft.KeyVault/vaults", "platform": "resource",
        "executive_summary": "s", "attack_vectors": vectors}))


def _vector(name, operation, table="AZKVAuditLogs"):
    return {"name": name, "priority": "high", "mitre_technique": "T1555.006",
            "operation": operation, "log_table": table,
            "alert_condition": "c", "rationale": "r r."}


@pytest.fixture
def workspace(monkeypatch):
    """A workspace where SecretGet happened and SecretPurge never did."""
    from pylon import validate

    monkeypatch.setattr(validate, "resolve", lambda w: ("t", "a", "guid"))
    monkeypatch.setattr(validate, "_run_kql",
                        lambda kql, guid, window: [{"Op": "SecretGet", "n": 7}])


def _survey(tmp_path):
    return cli._design_survey(argparse.Namespace(
        source=str(tmp_path), workspace="ws", window="30d"))


def test_it_separates_what_can_be_graded_from_what_cannot(tmp_path, workspace, capsys):
    _plan(tmp_path, [_vector("SecretGet (read secret)", "SecretGet"),
                     _vector("SecretPurge (destroy secret)", "SecretPurge")])
    assert _survey(tmp_path) == 0
    err = capsys.readouterr().err
    assert "1 of 2 can be graded" in err


def test_it_says_what_building_the_rest_buys_you(tmp_path, workspace, capsys):
    """`no-ground-truth` is not a pass, and a reader about to spend money is
    the one person who can act on that."""
    _plan(tmp_path, [_vector("a", "SecretGet"), _vector("b", "SecretPurge")])
    _survey(tmp_path)
    err = capsys.readouterr().err
    assert "no-ground-truth" in err and "not a pass" in err


def test_it_hands_back_the_pick_string(tmp_path, workspace, capsys):
    """Choosing what to build becomes a measurement instead of a guess."""
    _plan(tmp_path, [_vector("a", "SecretPurge"), _vector("b", "SecretGet"),
                     _vector("c", "SecretGet")])
    _survey(tmp_path)
    assert '--pick "2,3"' in capsys.readouterr().err


def test_a_table_that_could_not_be_read_grades_nothing_rather_than_everything(
        tmp_path, monkeypatch, capsys):
    """A failed read must not read as "no events", which would report every
    vector as unprovable and send someone triggering things that already
    happened."""
    from pylon import validate

    monkeypatch.setattr(validate, "resolve", lambda w: ("t", "a", "guid"))
    monkeypatch.setattr(validate, "_run_kql", lambda *a: None)
    _plan(tmp_path, [_vector("a", "SecretGet")])
    _survey(tmp_path)
    assert "could not be read" in capsys.readouterr().err


def test_one_query_per_table_not_one_per_vector(tmp_path, monkeypatch):
    """A plan of 54 vectors over one table is one round trip."""
    from pylon import validate

    calls = []
    monkeypatch.setattr(validate, "resolve", lambda w: ("t", "a", "guid"))
    monkeypatch.setattr(validate, "_run_kql",
                        lambda kql, g, w: calls.append(kql) or [])
    _plan(tmp_path, [_vector(f"v{i}", f"Op{i}") for i in range(20)])
    _survey(tmp_path)
    assert len(calls) == 1, f"{len(calls)} queries for one table"


def test_a_plan_that_was_never_written_is_refused(tmp_path):
    assert _survey(tmp_path) == 2


# ── grade ────────────────────────────────────────────────────────────────────

def test_grading_without_an_engine_says_how_to_get_one(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("PYLON_KUSTAINER_URL", raising=False)
    code = cli._design_grade(argparse.Namespace(fixtures=str(tmp_path)))
    assert code == 2
    assert "kustainer" in capsys.readouterr().err


def test_grading_an_empty_directory_points_at_record(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PYLON_KUSTAINER_URL", "http://localhost:8080")
    code = cli._design_grade(argparse.Namespace(fixtures=str(tmp_path)))
    assert code == 2
    assert "design record" in capsys.readouterr().err


def test_the_golden_harness_is_reachable_from_the_cli():
    """It was parked as "scripts/eval.py only", and being parked is what let it
    sit unreachable while `design record` wrote fixtures nothing consumed."""
    import inspect

    assert "golden_eval" in inspect.getsource(cli._design_grade)


def test_grading_real_fixtures_reaches_the_table(tmp_path, monkeypatch, capsys):
    """The rendering path EXECUTES, on more than one fixture.

    Round eight reported `design grade` crashing on a stale 3-way unpack of a
    5-tuple, with the exact line. Round nine hit the identical crash on the
    identical line after a full release cycle, because every test here either
    returned before reaching it -- no engine, or an empty directory -- or read
    the source as text with `inspect.getsource`. Four tests named the function
    and none ran it.

    TWO fixtures, not one: the faulty line sits behind `if len(rows) > 1`, so a
    single fixture leaves `shared` empty and skips it. A one-fixture test would
    have gone green on the broken code and reported this bug fixed.
    """
    import yaml as _yaml

    monkeypatch.setenv("PYLON_KUSTAINER_URL", "http://localhost:8080")
    for name in ("blob-download-oauth", "blob-delete-mass"):
        (tmp_path / f"{name}.yaml").write_text(_yaml.safe_dump({
            "name": name, "table": "StorageBlobLogs",
            "query": 'StorageBlobLogs | where AuthenticationType == "OAuth"',
            "anchored": False,
            "measured": {"verdict": "under", "observed": 3},
            "events": [{"_outcome": "attack", "AuthenticationType": "OAuth"},
                       {"_outcome": "benign", "AuthenticationType": "SAS"}],
        }), encoding="utf-8")

    code = cli._design_grade(argparse.Namespace(fixtures=str(tmp_path)))
    out = capsys.readouterr()
    assert code != 2, "returned the no-fixtures code with two fixtures present"
    # The header only prints once the unpack at the labels line has succeeded.
    assert "fixture" in out.out and "verdict" in out.out, out.out + out.err
