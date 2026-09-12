"""What the playbooks command REPORTS about what it did.

Three faults, all found on one live ARM run and none visible to any test:

  * every playbook in the run was discarded and the command still exited 0, so
    nothing scripting it could tell a finished run from a total loss
  * the .md files landed and report.json still said `playbooks: []`, so the
    report denied the existence of documents sitting beside it
  * the chain serving AuditLogs was named `graph`, and the id is written into
    report.json -- renaming it to `entra` breaks every directory produced
    before the rename unless the old name still resolves

The first two are about the command's own honesty, which no unit test on the
engine can see, because each half is individually correct.
"""

import argparse
import json

import pytest

from pylon import cli, engine
from pylon.models import (
    AttackVector, Detection, EngineReport, ThreatAnalysis, ValidatedDetection,
)

TABLE = "AzureActivity"


def _args(**kw):
    base = dict(target="", source="", pick="", out=None, max_cost=1.0, max_tokens=0)
    return argparse.Namespace(**{**base, **kw})


def _report(platform: str = "resource") -> EngineReport:
    vector = AttackVector(
        name="Vector one", priority="high", mitre_technique="T1098.003",
        operation="MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
        log_table=TABLE, alert_condition="x", rationale="x")
    return EngineReport(
        service="Microsoft.Authorization/roleAssignments",
        platform=platform,
        analysis=ThreatAnalysis(
            service=TABLE, platform=platform, executive_summary="x",
            mitre_verification="verified", attack_vectors=[vector]),
        detections=[ValidatedDetection(
            detection=Detection(
                vector_name="Vector one", mitre_technique="T1098.003",
                kql=f"{TABLE}\n| where TimeGenerated > ago(1h)\n| take 1",
                tuning_guidance="t", false_positive_notes="automation"),
            log_table=TABLE, valid=True, errors=[], warnings=[], retried=False)],
        generation_yield=100, critical_gaps=[])


@pytest.fixture
def source(tmp_path):
    def build(platform="resource"):
        (tmp_path / "report.json").write_text(_report(platform).model_dump_json(indent=2))
        return str(tmp_path)
    return build


def test_a_run_that_wrote_nothing_does_not_exit_zero(tmp_path, source, monkeypatch):
    """Every playbook failing used to print FAILED and return 0."""
    monkeypatch.setattr(engine, "run_playbook_phase",
                        lambda *a, **k: (_ for _ in ()).throw(ValueError("rejected")))
    rc = cli._design_playbooks(_args(source=source(), pick="all"))

    assert rc != 0, "a run that wrote no playbook reported success"
    assert not list(tmp_path.glob("*-playbook.md"))


def test_what_was_written_is_recorded_in_the_report(tmp_path, source, monkeypatch):
    """The .md landed and report.json said no playbook existed."""
    async def fake(request, target):
        return "# IR Playbook: Vector one\n\n## Playbook Metadata\n"

    monkeypatch.setattr(engine, "run_playbook_phase", fake)
    rc = cli._design_playbooks(_args(source=source(), pick="all"))
    assert rc == 0

    written = list(tmp_path.glob("*-playbook.md"))
    assert len(written) == 1, [p.name for p in written]

    recorded = json.loads((tmp_path / "report.json").read_text())["playbooks"]
    assert [p["target"] for p in recorded] == ["Vector one"], (
        "report.json denies the playbook sitting beside it")
    assert recorded[0]["text"] == written[0].read_text()
