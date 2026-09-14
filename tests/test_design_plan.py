"""See what it would build before paying to build it.

Phase 2 is the whole bill. A measured Key Vault run made 102 model calls and 101
were per-vector work on a list nobody had looked at: $5.83 and fifty-five minutes
to find out what was on offer. `design plan` shows the offer for one call, and
`design detections --from` builds only the picks.

It also makes run-to-run drift cheap to see rather than expensive to discover.
The same target enumerated 55 vectors one run and 40 the next on identical input,
so two plans can be diffed instead of two bills.
"""

import argparse
import io
from contextlib import redirect_stderr

import pytest

from pylon import cli, deployed, engine
from pylon.engine import _selected_vectors
from pylon.models import AttackVector, ThreatAnalysis


def _plan(*names) -> ThreatAnalysis:
    return ThreatAnalysis(
        service="Microsoft.KeyVault/vaults", platform="resource",
        executive_summary="x", mitre_verification="verified",
        attack_vectors=[
            AttackVector(name=n, priority="high", mitre_technique=tech,
                         operation=op, log_table="AZKVAuditLogs",
                         alert_condition="x", rationale="x")
            for n, tech, op in names])


_PLAN = _plan(("Secret read (SecretGet)", "T1555.006", "SecretGet"),
              ("Secret purge (irrecoverable)", "T1485", "SecretPurge"),
              ("Vault access policy change", "T1098", "VaultPut"))


def _written(tmp_path) -> argparse.Namespace:
    (tmp_path / "plan.json").write_text(_PLAN.model_dump_json(), encoding="utf-8")
    return argparse.Namespace(
        target="", source=str(tmp_path), pick="", out=None,
        max_cost=1.0, max_tokens=0, unconfirmed_tables=True)


def test_the_selection_is_applied_before_the_fan_out():
    """Narrowing after generation would save nothing -- the calls are the cost."""
    kept = _selected_vectors("T1485", list(_PLAN.attack_vectors))
    assert [v.name for v in kept] == ["Secret purge (irrecoverable)"]


def test_a_pick_means_the_same_thing_before_and_after_the_money():
    """`_resolve_picks` matches a number, a technique id, or part of a name. It
    took ValidatedDetections only, so a plan would have needed a second rule that
    could disagree about what `--pick purge` selects."""
    for term, expected in (("purge", ["Secret purge (irrecoverable)"]),
                           ("T1555.006", ["Secret read (SecretGet)"]),
                           ("2", ["Secret purge (irrecoverable)"]),
                           ("all", [v.name for v in _PLAN.attack_vectors])):
        kept = _selected_vectors(term, list(_PLAN.attack_vectors))
        assert [v.name for v in kept] == expected, term


def test_none_stops_after_phase_one():
    assert _selected_vectors("none", list(_PLAN.attack_vectors)) == []


def test_a_plan_carries_its_own_target(tmp_path, monkeypatch):
    """A plan built for one resource cannot be applied to another, so `--from`
    does not ask and the saved value wins."""
    built = {}

    class _Stub:
        EngineRequest = engine.EngineRequest

        class pylon:
            @staticmethod
            def run(request):
                built["request"] = request
                raise SystemExit(0)

    monkeypatch.setattr(cli, "_engine", lambda: _Stub)
    monkeypatch.setattr(deployed, "from_analysis", lambda: (None, "not checked"))
    args = _written(tmp_path)
    args.pick = "purge"
    with pytest.raises(SystemExit):
        cli._design_detections(args)

    request = built["request"]
    assert request.resource == "Microsoft.KeyVault/vaults"
    assert request.vector_selection == "purge"
    assert request.analysis is not None, "phase 1 would have been paid for twice"
    assert len(request.analysis.attack_vectors) == 3


def test_from_without_a_pick_prints_the_plan_and_refuses(tmp_path):
    """Silently building all of it is the expensive default this command exists
    to remove."""
    args = _written(tmp_path)
    err = io.StringIO()
    with redirect_stderr(err):
        assert cli._design_detections(args) == 2
    out = err.getvalue()
    assert "--pick is required" in out
    for v in _PLAN.attack_vectors:
        assert v.name in out
    assert "T1485" in out and "AZKVAuditLogs" in out


def test_a_missing_or_unreadable_plan_is_refused_by_name(tmp_path):
    args = argparse.Namespace(target="", source=str(tmp_path), pick="all", out=None,
                              max_cost=1.0, max_tokens=0)
    err = io.StringIO()
    with redirect_stderr(err):
        assert cli._design_detections(args) == 2
    assert "no plan.json" in err.getvalue()

    (tmp_path / "plan.json").write_text("{ not json", encoding="utf-8")
    err = io.StringIO()
    with redirect_stderr(err):
        assert cli._design_detections(args) == 2
    assert "not a readable plan" in err.getvalue()


def test_design_plan_stops_after_phase_one(monkeypatch, tmp_path):
    built = {}

    class _Stub:
        EngineRequest = engine.EngineRequest

        class pylon:
            @staticmethod
            def run(request):
                built["request"] = request
                raise SystemExit(0)

    monkeypatch.setattr(cli, "_engine", lambda: _Stub)
    monkeypatch.setattr(deployed, "from_analysis", lambda: (None, "not checked"))
    args = argparse.Namespace(target="Microsoft.KeyVault/vaults", source="",
                              out=str(tmp_path), max_cost=1.0, max_tokens=0)
    with pytest.raises(SystemExit):
        cli._design_plan(args)

    request = built["request"]
    assert request.vector_selection == "none"
    assert request.analysis is None


def _fake_report(n_vectors: int):
    """An EngineReport shaped like a `design plan` run: vectors, no detections."""
    from pylon.models import EngineReport

    return EngineReport(
        service="Microsoft.KeyVault/vaults", platform="resource",
        analysis=_plan(*[(f"Vector {i}", "T1555.006", f"Op{i}")
                         for i in range(n_vectors)]),
        detections=[], generation_yield=0, critical_gaps=[])


def test_a_plan_run_does_not_report_itself_as_a_failure(capsys):
    """It built nothing on purpose. The detections summary read that as total
    failure -- "0 produced a valid detection", "0% coverage" -- when the run had
    done its whole job for one model call."""
    cli._print_report(_fake_report(3), plan_only=True)
    out = capsys.readouterr().out
    assert "PLAN" in out
    assert "3  vectors enumerated" in out
    assert "produced a valid detection" not in out
    assert "COVERAGE" not in out


def test_a_real_run_still_gets_the_detections_summary(capsys):
    cli._print_report(_fake_report(3), plan_only=False)
    out = capsys.readouterr().out
    assert "DETECTIONS" in out
    assert "PLAN" not in out


def test_a_plan_run_writes_the_plan_and_no_detections_page(tmp_path, capsys):
    cli._write_detections(_fake_report(2), str(tmp_path), plan_only=True)
    assert (tmp_path / "plan.json").is_file()
    assert not (tmp_path / "detections.html").exists(), (
        "a page of no detections reads as a failed run rather than a cheap one")
    out = capsys.readouterr().out
    assert "plan.json" in out and "--from" in out


def test_the_detection_phase_makes_no_calls_when_nothing_is_selected():
    """The saving is the calls, so an empty selection must not reach the agent."""
    import asyncio

    from pylon.engine import run_detection_phase

    empty = _plan()
    request = engine.EngineRequest(resource="Microsoft.KeyVault/vaults")
    assert asyncio.run(run_detection_phase(request, "", empty)) == []


def _built(planned: int, built: int, valid: int):
    """A report shaped like a `--pick` run: a large plan, a few detections."""
    from pylon.models import Detection, EngineReport, ValidatedDetection

    def vd(i):
        return ValidatedDetection(
            detection=Detection(vector_name=f"Built {i}", mitre_technique="T1485",
                                kql="AZKVAuditLogs | take 1", tuning_guidance="x",
                                false_positive_notes="x"),
            log_table="AZKVAuditLogs", valid=i < valid, errors=[], warnings=[],
            retried=False, operation="Op", rationale="x", priority="high")

    return EngineReport(
        service="Microsoft.KeyVault/vaults", platform="resource",
        analysis=_plan(*[(f"V{i}", "T1485", f"Op{i}") for i in range(planned)]),
        detections=[vd(i) for i in range(built)],
        generation_yield=100, vectors_planned=planned, critical_gaps=[])


def test_a_pick_run_counts_what_it_built_not_what_it_skipped(capsys):
    """It said "55 attack vectors enumerated / 8 produced a valid detection",
    which reads as forty-seven failures when forty-seven were never attempted."""
    cli._print_report(_built(planned=55, built=8, valid=8))
    out = capsys.readouterr().out
    assert "8  vectors built from a plan of 55" in out
    assert "47  not picked" in out


def test_the_yield_is_scored_against_the_picks(capsys):
    """A run that picked eight and got eight is 100%, not 10%. The forty-seven it
    was never asked to build are not failures."""
    cli._print_report(_built(planned=55, built=8, valid=8))
    out = capsys.readouterr().out
    # Counted against the PICKS. The percentage this used to assert was
    # computed over distinct weight-scored technique ids, not over vectors, so
    # it could read 100% on a run where half the detections failed.
    assert "8 of 8 picked vectors produced a valid detection" in out
    assert "of the 55 enumerated" not in out


def test_a_full_run_still_reads_the_old_way(capsys):
    """Nothing narrowed, so enumerated and built are the same number and the
    wording should not change under a reader who never uses --pick."""
    cli._print_report(_built(planned=6, built=6, valid=6))
    out = capsys.readouterr().out
    assert "6  attack vectors enumerated" in out
    assert "not picked" not in out
    assert "enumerated vectors produced a valid detection" in out


def test_a_plan_only_run_leaves_no_report_claiming_zero_detections(tmp_path):
    """report.json is the claim "detections were built". A plan-only run wrote an
    empty one, so `design playbooks` answered "0 detection(s) available" -- a run
    that produced nothing, rather than a step not yet taken."""
    cli._write_detections(_built(planned=3, built=0, valid=0),
                          str(tmp_path), plan_only=True)
    assert (tmp_path / "plan.json").is_file()
    assert not (tmp_path / "report.json").exists()


def test_a_full_run_still_writes_the_report(tmp_path):
    """The guard above must not cost the normal path its report."""
    cli._write_detections(_built(planned=3, built=3, valid=3), str(tmp_path))
    assert (tmp_path / "report.json").is_file()
    assert (tmp_path / "plan.json").is_file()


def test_playbooks_on_a_plan_only_directory_names_the_missing_step(tmp_path):
    """The directory is not broken; Phase 2 has not run. Point at the command."""
    (tmp_path / "plan.json").write_text(_PLAN.model_dump_json(), encoding="utf-8")
    err = io.StringIO()
    with redirect_stderr(err):
        rc = cli._design_playbooks(argparse.Namespace(
            source=str(tmp_path), pick="all", max_cost=1.0, max_tokens=0))
    assert rc == 2
    text = err.getvalue()
    assert "holds a plan but no detections" in text
    assert "pylon design detections --from" in text


def test_an_out_of_range_number_says_so(capsys):
    """`--pick 51` against a 20-detection report picked nothing and said nothing,
    so a number aimed at the plan's numbering looked like a failed match."""
    with redirect_stderr(io.StringIO()) as err:
        assert cli._resolve_picks("51", list(_PLAN.attack_vectors)) == []
    assert "only 3 detection(s) here" in err.getvalue()


def test_design_list_falls_back_to_the_plan(tmp_path, capsys):
    """One step earlier in the same directory. Showing the plan beats refusing,
    and its numbering is what `design detections --pick` counts against."""
    (tmp_path / "plan.json").write_text(_PLAN.model_dump_json(), encoding="utf-8")
    rc = cli._design_list(argparse.Namespace(source=str(tmp_path), target=[]))
    assert rc == 0
    out = capsys.readouterr().out
    assert "no detections built yet" in out
    assert "Secret purge (irrecoverable)" in out
