"""The three CLI commands, in order, against a stubbed model, on every plane.

Everything that went wrong tonight went wrong HERE and nowhere else. Each fault
passed its own unit test and failed on the first real run:

  * the workflow rebuilt EngineRequest field by field and dropped `target_key`,
    so a saved Entra plan recorded the table and could not be reopened
  * the playbook retry took `response.text` and threw the assembled document away
  * the data-plane playbook shipped Storage columns on a Key Vault table
  * the positive control read a `let` from the block below it

Unit tests cannot see any of those, because each one lives in the seam between
two things that are individually correct. This runs `design plan`, then
`design detections --from`, then `design playbooks --from`, the way a person
does, and reads what lands on disk.

No network: the model is a stub. What is being checked is the wiring, which is
what keeps breaking.
"""

import argparse
import asyncio
import json
import re
from types import SimpleNamespace

import pytest

from pylon import cli, engine
from pylon.models import AttackVector, Detection, ThreatAnalysis
from pylon.playbook import PlaybookFill, unfilled
from pylon.validation.playbook_check import check_playbook

# (target as a person types it, the table it resolves to, a real operation)
PLANES = [
    ("Microsoft.KeyVault/vaults", "AZKVAuditLogs", "SecretPurge"),
    ("Entra RoleManagement", "AuditLogs", "Add member to role"),
    ("Microsoft.Authorization/roleAssignments", "AzureActivity",
     "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"),
]

# Built from RAW fields per plane, not handed over pre-validated. A stub that
# returns a finished PlaybookFill skips every field validator, which is exactly
# how the ARM plane shipped a validator that rejected its own correct output:
# the counter treated the dot in `Microsoft.Authorization/roleAssignments` as a
# sentence ending, and no offline test ever fed it a dotted identifier. Each
# plane's text now says what that plane's model would really say.
_RAW_FILL = {
    "AZKVAuditLogs": dict(
        what_happened="The actor destroyed the secret beyond recovery.",
        attack_context="The actor purged a secret from Microsoft.KeyVault/vaults, "
                       "so soft-delete cannot bring it back. Every consumer "
                       "authenticating with it fails until it is reissued.",
        why_it_matters=["it cannot be undone", "every consumer is affected"],
        containment_role="Key Vault Secrets Officer"),
    "AuditLogs": dict(
        what_happened="The actor gave itself a standing directory role.",
        attack_context="The actor added a permanent member to a privileged "
                       "directory role outside PIM. The assignment persists "
                       "with no activation record and no expiry.",
        why_it_matters=["it outlives the session", "it bypasses PIM review"],
        containment_role="Privileged Role Administrator"),
    "AzureActivity": dict(
        what_happened="The actor granted itself Owner through "
                      "Microsoft.Authorization/roleAssignments.",
        attack_context="Using Microsoft.Authorization/roleAssignments the actor "
                       "granted Owner at subscription scope. Owner carries "
                       "control of every resource beneath that scope, including "
                       "Microsoft.KeyVault/vaults. The grant survives until "
                       "someone removes it.",
        why_it_matters=["it spans the whole subscription", "it persists"],
        containment_role="Owner"),
}


@pytest.fixture
def stub_model(monkeypatch):
    """One stub for all three phases, answering by response_format."""

    def install(table: str, operation: str):
        analysis = ThreatAnalysis(
            service=table, platform="graph", executive_summary="x",
            mitre_verification="verified",
            attack_vectors=[AttackVector(
                name="Vector one", priority="high", mitre_technique="T1098.003",
                operation=operation, log_table=table,
                alert_condition="x", rationale="x")])
        detection = Detection(
            vector_name="Vector one", mitre_technique="T1098.003",
            kql=f"{table}\n| where TimeGenerated > ago(1h)\n| take 1",
            tuning_guidance="t", false_positive_notes="automation")

        def factory(*a, **k):
            agent = SimpleNamespace()

            async def run(prompt, options=None):
                fmt = (options or {}).get("response_format")
                value = {ThreatAnalysis: analysis.model_copy(deep=True),
                         Detection: detection.model_copy(deep=True),
                         # Constructed HERE so the validators run, on this
                         # plane's own vocabulary.
                         PlaybookFill: lambda: PlaybookFill(**_RAW_FILL[table]),
                         }.get(fmt)
                if callable(value):
                    value = value()
                return SimpleNamespace(value=value, text="", usage_details=None)

            agent.run = run
            agent.as_agent = lambda **kw: agent
            return agent

        monkeypatch.setattr(engine, "make_chat_client", factory)
        monkeypatch.setattr(engine, "Agent", lambda **kw: factory())
        monkeypatch.setattr(engine, "table_schema_context",
                            lambda _t: asyncio.sleep(0, result=""))
        monkeypatch.setattr(engine, "mitre_technique_names",
                            lambda ids: asyncio.sleep(0, result={i: "x" for i in ids}))

    return install


def _args(**kw):
    base = dict(target="", source="", pick="", out=None, max_cost=1.0, max_tokens=0)
    return argparse.Namespace(**{**base, **kw})


@pytest.mark.parametrize("target,table,operation", PLANES,
                         ids=[p[1] for p in PLANES])
def test_plan_then_detections_then_playbook(tmp_path, stub_model, target, table,
                                            operation, capsys):
    stub_model(table, operation)
    out = str(tmp_path)

    # 1. design plan — writes plan.json and NO report.json.
    assert cli._design_plan(_args(target=target, out=out)) == 0
    plan = json.loads((tmp_path / "plan.json").read_text())
    assert not (tmp_path / "report.json").exists(), (
        "a plan-only run must not claim detections exist")
    assert plan["target"] == target, (
        "the plan must record what was ASKED for, or --from cannot reopen it")

    # 2. design detections --from — reopens the plan without being told the target.
    assert cli._design_detections(_args(source=out, pick="all", out=out)) == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["detections"], "no detection was built"

    # 3. design playbooks --from — assembles the document.
    assert cli._design_playbooks(_args(source=out, pick="all")) == 0
    written = sorted(tmp_path.glob("*-playbook.md"))
    assert len(written) == 1, [p.name for p in written]
    doc = written[0].read_text()

    # What lands on disk, judged as a responder would get it.
    assert doc.startswith("# IR Playbook:"), (
        "the document must open on its title -- stripping the GUIDE region left "
        "a blank first line on all three planes and nothing here noticed: "
        + repr(doc[:40]))
    heads = [h.strip() for h in re.findall(r"^## (.+)$", doc, re.M)]
    assert len(heads) == 14, heads
    assert heads[0] == "Playbook Metadata"
    assert heads.index("Preserve Evidence") < heads.index("Containment")
    assert unfilled(doc) == [], "a blank with no stated source shipped"
    assert check_playbook(doc, table).errors == []
    assert "```kql" in doc
    assert "__" not in doc.replace("__SERVICE__", ""), "an unsubstituted token shipped"


@pytest.mark.parametrize("target,table,operation", PLANES,
                         ids=[p[1] for p in PLANES])
def test_no_plane_reads_another_plane_s_columns(tmp_path, stub_model, target, table,
                                                operation):
    """The data-plane asset serves five tables with two column sets, and shipped
    the wrong one. Every plane, every time, from the file on disk."""
    stub_model(table, operation)
    out = str(tmp_path)
    cli._design_plan(_args(target=target, out=out))
    cli._design_detections(_args(source=out, pick="all", out=out))
    cli._design_playbooks(_args(source=out, pick="all"))
    doc = next(tmp_path.glob("*-playbook.md")).read_text()

    foreign = {"AZKVAuditLogs": ("RequesterUpn", "UserAgentHeader", 'StatusCode != "200"'),
               "AuditLogs": ("RequesterUpn", "HttpStatusCode"),
               "AzureActivity": ("RequesterUpn", "Identity.claim")}[table]
    for column in foreign:
        assert column not in doc, f"{table} playbook reads {column}"
