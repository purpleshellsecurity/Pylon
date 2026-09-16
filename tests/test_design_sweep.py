"""Walking every target in one command, resumably, under one budget.

This was a thirty-line shell script I hand-wrote to drive nine directories, and
the hand-writing was the point: the loop already closed around ONE detection --
generate, check it against the regexes, the KQL engine and the workspace,
correct once -- and then stopped, because deciding what to run next was a
person's job. Sixteen of twenty-five targets had never been run and nothing
recorded which.
"""

import argparse
import json

import pytest

from pylon import cli


def _args(tmp_path, **over):
    ns = argparse.Namespace(
        targets=[], out_root=str(tmp_path), workspace="ws", window="30d",
        pick="all", stages=["detections"], max_cost=25.0, force=False)
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


@pytest.fixture
def stages(monkeypatch):
    """Record what the sweep asked for, without running any of it."""
    calls = []

    def _stage(stage, target, out, args):
        calls.append((stage, target, str(out)))
        return 0, 1.0          # exit 0, one dollar
    monkeypatch.setattr(cli, "_sweep_stage", _stage)
    return calls


def test_a_directory_name_is_stable_and_readable():
    """The sweep resumes into the same place it left, and `ls` answers what was
    run."""
    assert cli._slug("Microsoft.Authorization/roleAssignments") == \
        "microsoft-authorization-roleassignments"
    assert cli._slug("Entra ApplicationManagement") == "entra-applicationmanagement"


def test_every_target_runs_when_none_is_named(tmp_path, stages):
    cli._design_sweep(_args(tmp_path))
    assert len(stages) >= 20, "the sweep should walk the whole catalogue"


def test_a_target_is_accepted_in_the_case_the_other_commands_print(tmp_path, stages):
    """`design list` prints `Microsoft.Authorization/roleAssignments`; matching
    the catalogue's lowercase keys instead rejected exactly that."""
    cli._design_sweep(_args(tmp_path, targets=["Microsoft.Authorization/roleAssignments"]))
    assert len(stages) == 1
    assert stages[0][1] == "Microsoft.Authorization/roleAssignments"


def test_an_unknown_target_is_refused_before_anything_runs(tmp_path, stages):
    code = cli._design_sweep(_args(tmp_path, targets=["Nonsense/thing"]))
    assert code == 2 and stages == []


def test_verifying_without_a_workspace_is_refused_up_front(tmp_path, stages):
    """Not after twenty targets of generation."""
    code = cli._design_sweep(_args(tmp_path, workspace=None,
                                   stages=["detections", "verify"]))
    assert code == 2 and stages == []


def test_finished_work_is_not_redone(tmp_path, stages):
    """The expensive half is model calls, and a sweep that cannot be
    interrupted is a sweep nobody starts."""
    target = ["Microsoft.Authorization/roleAssignments"]
    cli._design_sweep(_args(tmp_path, targets=target))
    cli._design_sweep(_args(tmp_path, targets=target))
    assert len(stages) == 1, "the second run should have skipped"


def test_force_redoes_it(tmp_path, stages):
    target = ["Microsoft.Authorization/roleAssignments"]
    cli._design_sweep(_args(tmp_path, targets=target))
    cli._design_sweep(_args(tmp_path, targets=target, force=True))
    assert len(stages) == 2


def test_the_budget_is_spent_across_targets_not_per_target(tmp_path, stages):
    """25 targets at $5 each is $125. The cap has to mean the real number."""
    cli._design_sweep(_args(tmp_path, max_cost=3.0))   # stage stub spends $1
    assert len(stages) == 3, f"spent past the cap: {len(stages)} stages"


def test_the_spend_survives_an_interrupted_sweep(tmp_path, stages):
    cli._design_sweep(_args(tmp_path, max_cost=2.0))
    state = json.loads((tmp_path / ".sweep.json").read_text(encoding="utf-8"))
    assert state["_spent"] == pytest.approx(2.0)
    # A resumed sweep starts from what was already spent, not from zero.
    cli._design_sweep(_args(tmp_path, max_cost=2.0))
    assert len(stages) == 2, "the resume spent more than the remaining budget"


def test_one_target_failing_does_not_stop_the_sweep(tmp_path, monkeypatch):
    seen = []

    def _stage(stage, target, out, args):
        seen.append(target)
        return (1, 0.0) if len(seen) == 1 else (0, 0.0)
    monkeypatch.setattr(cli, "_sweep_stage", _stage)
    cli._design_sweep(_args(tmp_path))
    assert len(seen) > 1, "the sweep stopped at the first failure"


def test_a_failed_stage_is_recorded_so_a_rerun_retries_only_that(tmp_path,
                                                                 monkeypatch):
    monkeypatch.setattr(cli, "_sweep_stage", lambda *a: (1, 0.0))
    cli._design_sweep(_args(tmp_path, targets=["Microsoft.Compute/virtualMachines"]))
    state = json.loads((tmp_path / ".sweep.json").read_text(encoding="utf-8"))
    row = state["microsoft-compute-virtualmachines"]
    assert row["detections"].startswith("failed"), row
