"""The Entra chain was called `graph`, and the id outlives the rename.

`report.json` records the platform id, and `design playbooks --from` reads it
back to rebuild the request. Renaming the chain to `entra` therefore breaks every
output directory produced before the rename unless the old spelling still
resolves, and nothing about that failure would look like a rename: the directory
simply stops opening.
"""

import argparse

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


def test_a_directory_written_before_the_rename_still_opens(source, monkeypatch):
    """report.json carries the platform id, so `graph` must outlive itself."""
    seen = {}

    async def fake(request, target):
        seen["platform"] = request.platform
        return "# IR Playbook: Vector one\n\n## Playbook Metadata\n"

    monkeypatch.setattr(engine, "run_playbook_phase", fake)
    assert cli._design_playbooks(_args(source=source("graph"), pick="all")) == 0
    assert seen["platform"] == "graph", "the stored id is passed through as written"


@pytest.mark.parametrize("written_as", ["graph", "entra"])
def test_both_spellings_reach_the_entra_chain(written_as):
    from pylon.playbook import document_template
    from pylon.prompts import _chain_for, get_platform
    from pylon.prompts.constants import normalise_platform

    assert normalise_platform(written_as) == "entra"
    assert _chain_for(written_as, "AuditLogs") == "entra"
    assert get_platform(written_as).id == "entra"
    assert document_template(written_as, "AuditLogs", "X").startswith("# IR Playbook:")
