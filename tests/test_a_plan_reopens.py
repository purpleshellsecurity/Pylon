"""A saved plan must name a target `design detections --from` can resolve.

`pylon design plan "Entra RoleManagement"` wrote a plan whose `service` was
"AuditLogs", and the next command refused it:

    'AuditLogs' is not a target this tool can ground.

Two different facts were sharing one field. `service` is what the run RESOLVED
to — the table, on the Entra path — and the playbook phase needs exactly that.
The plan needs what was ASKED for, because that is the only string a user or a
`--from` can hand back. The resource path happened to work because a resource
type is both.

And `service` came from the MODEL's structured answer, so what a plan recorded
about itself depended on what a model echoed. Pylon knows what it was asked for.
"""

import json

import pytest

from pylon import cli
from pylon.models import AttackVector, ThreatAnalysis
from pylon.services import resolve_target


def _plan(**kw) -> ThreatAnalysis:
    base = dict(service="AuditLogs", platform="graph", target="Entra RoleManagement",
                executive_summary="x", mitre_verification="verified",
                attack_vectors=[AttackVector(
                    name="Add member to role", priority="high",
                    mitre_technique="T1098.003", operation="Add member to role",
                    log_table="AuditLogs", alert_condition="x", rationale="x")])
    return ThreatAnalysis(**{**base, **kw})


@pytest.mark.parametrize("target", ["Entra RoleManagement", "Microsoft.KeyVault/vaults"])
def test_the_target_a_plan_records_can_be_resolved_again(tmp_path, target):
    (tmp_path / "plan.json").write_text(_plan(target=target).model_dump_json(), encoding="utf-8")
    peek = cli._load_plan(str(tmp_path))
    again = getattr(peek, "target", "") or peek.service
    assert again == target
    assert resolve_target(again) is not None, f"--from cannot reopen {target!r}"


def test_the_table_is_still_recorded_for_the_playbook_phase():
    """`service` must keep meaning the table: `design playbooks` builds its
    request from it, and a playbook for AuditLogs needs AuditLogs."""
    plan = _plan()
    assert plan.service == "AuditLogs"
    assert plan.target != plan.service


def test_a_plan_written_before_the_field_still_loads(tmp_path):
    """Someone has plan.json files on disk already. A new required field would
    have made every one of them unreadable."""
    raw = json.loads(_plan().model_dump_json())
    raw.pop("target")
    (tmp_path / "plan.json").write_text(json.dumps(raw), encoding="utf-8")
    peek = cli._load_plan(str(tmp_path))
    assert peek is not None
    assert (getattr(peek, "target", "") or peek.service) == "AuditLogs"


def test_pylon_stamps_the_target_rather_than_reading_it_back():
    """The model fills `service`; it must not be the source of what the run was
    for. `run_threat_phase` overwrites `target` from the request."""
    import inspect

    from pylon import engine

    src = inspect.getsource(engine.run_threat_phase)
    assert "analysis.target = request.target_key or subject" in src


def test_both_cli_paths_pass_the_target_through():
    """Entra and resource mode both build an EngineRequest. A target_key set on
    one and forgotten on the other is the same bug on half the planes."""
    import inspect

    src = inspect.getsource(cli._design_detections)
    assert src.count("target_key=target.key") == 2, (
        "both the Entra branch and the resource branch must carry it")


def test_the_workflow_drops_no_field_of_the_request():
    """The workflow normalises the request on the way in. It did so by rebuilding
    EngineRequest field by field, and every field that rebuild forgot arrived as
    its default with no error anywhere.

    `target_key` was added, not listed there, and reached Phase 1 empty — so the
    Entra plan recorded "AuditLogs" again, three commits after the apparent fix,
    and the failure looked identical to the one already fixed.

    Only `service` is normalised. Everything else must arrive as it was sent.
    """
    import dataclasses

    from pylon.engine import EngineRequest

    sent = EngineRequest(
        platform="graph", service="AuditLogs", target_key="Entra RoleManagement",
        entra_category="RoleManagement", seed_context="seed", max_cost=1.5,
        max_tokens=99, vector_selection="none", playbook_selection="all",
        dynamic_schema=True, az_diag_provider="p", az_diag_categories=("c",),
        az_diag_samples=("s",), surfaces=("x",), resource="",
    )
    got = dataclasses.replace(sent, service=sent.service)
    for field in dataclasses.fields(EngineRequest):
        assert getattr(got, field.name) == getattr(sent, field.name), field.name


def test_the_normalisation_names_only_what_it_changes():
    """A copy that enumerates every field goes stale the next time someone adds
    one. `replace` cannot."""
    import inspect

    from pylon import engine

    src = inspect.getsource(engine.pylon)
    assert "dataclasses.replace(request" in src
    assert "EngineRequest(\n        platform=request.platform" not in src
