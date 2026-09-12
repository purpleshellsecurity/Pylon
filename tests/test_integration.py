"""End-to-end workflow tests with a stubbed model (no network, no API key).

These exercise how the pieces COMPOSE through the real workflow — per-vector
routing, the saved-list anchor reaching Phase 1, and the budget cap skipping
mid-run — which the per-module unit tests don't cover.
"""

import asyncio

from pylon import engine
from pylon.models import AttackVector, Detection, ThreatAnalysis

# Two vectors that must route to different AKS tables: a read (AKSAudit) and a
# write (AKSAuditAdmin).
_VECTORS = [
    AttackVector(
        name="Read Kubernetes secrets", priority="critical", mitre_technique="T1552.001",
        operation="get secrets", log_table="AKSAudit",
        alert_condition="secret read", rationale="Credential access. Facts only.",
    ),
    AttackVector(
        name="Create cluster-admin binding", priority="critical", mitre_technique="T1098.003",
        operation="create clusterrolebinding", log_table="AKSAuditAdmin",
        alert_condition="new binding", rationale="Privilege escalation. Facts only.",
    ),
]
_ANALYSIS = ThreatAnalysis(
    service="Microsoft.ContainerService/managedClusters", platform="resource",
    executive_summary="summary", attack_vectors=_VECTORS,
)


def _stub_factory(recorder=None, usage=None):
    """Returns a stub usable for both make_chat_client and Agent. Records the
    instructions each Agent is built with; emits table-appropriate KQL."""

    def factory(*args, instructions="", **kwargs):
        if recorder is not None:
            recorder.append(instructions)
        stub = _StubAgent(usage)
        return stub

    return factory


class _StubAgent:
    def __init__(self, usage):
        self._usage = usage

    def as_agent(self, **kwargs):
        return self

    async def run(self, prompt, options=None):
        return _StubResponse(prompt, options, self._usage)


class _StubResponse:
    def __init__(self, prompt, options, usage):
        fmt = (options or {}).get("response_format")
        self.usage_details = dict(usage) if usage else None
        if fmt is ThreatAnalysis:
            self.value = _ANALYSIS
        elif fmt is Detection:
            table = "AKSAuditAdmin" if "AKSAuditAdmin" in prompt else "AKSAudit"
            verb = "create" if table == "AKSAuditAdmin" else "get"
            self.value = Detection(
                vector_name="d", mitre_technique="T1552.001",
                kql=f'{table}\n| where TimeGenerated > ago(1h)\n| where Verb == "{verb}"',
                tuning_guidance="t", false_positive_notes="f",
            )
            self.text = ""
        else:
            # Phase 3 asks for three fields, not a document: Pylon assembles the
            # playbook itself. A fake returning prose here is a fake of the old
            # contract, and the phase now says so rather than accepting it.
            from pylon.playbook import PlaybookFill
            self.value = PlaybookFill(what_happened="The actor reached the object.", why_it_matters=["The material is now disclosed", "The actor still holds the access"], attack_context="The actor reached the object. It matters because the material is now disclosed.", containment_role="Key Vault Secrets Officer")
            self.text = ""


async def _drive(request, monkeypatch, recorder=None, usage=None, selection=engine.PLAYBOOK_PROMPT):
    import dataclasses

    monkeypatch.setattr(engine, "table_schema_context", lambda _t: _aret(""))
    monkeypatch.setattr(engine, "mitre_technique_names", lambda _ids: _aret({}))
    monkeypatch.setattr(engine, "make_chat_client", _stub_factory(recorder, usage))
    monkeypatch.setattr(engine, "Agent", _stub_factory(recorder, usage))

    request = dataclasses.replace(request, playbook_selection=selection)
    stream = engine.pylon.run(message=request, stream=True)
    async for _ in stream:
        pass
    result = await stream.get_final_response()
    events = result.get_request_info_events()
    if not events:  # no playbook phase -> run completes without a HITL pause
        return result.get_outputs()[0]
    [ev] = events
    stream2 = engine.pylon.run(stream=True, responses={ev.request_id: "0"})
    async for _ in stream2:
        pass
    return (await stream2.get_final_response()).get_outputs()[0]


async def _aret(v):
    return v


def test_resource_run_routes_each_vector_to_its_table(monkeypatch):
    report = asyncio.run(
        _drive(engine.EngineRequest(resource="Microsoft.ContainerService/managedClusters"), monkeypatch)
    )
    routed = {d.log_table for d in report.detections}
    assert routed == {"AKSAudit", "AKSAuditAdmin"}  # split across the two tables
    assert all(d.valid for d in report.detections)   # both pass the (real) validator
    # prerequisites came from the catalog per routed table
    prereqs = {d.log_table: d.prerequisite for d in report.detections}
    assert "kube-audit" in prereqs["AKSAudit"]
    assert "kube-audit-admin" in prereqs["AKSAuditAdmin"]


def test_saved_list_seed_reaches_phase1_prompt(monkeypatch):
    recorder = []
    req = engine.EngineRequest(
        resource="Microsoft.ContainerService/managedClusters",
        seed_context="\n<known_detections>\n- Prior detection (T1552, AKSAudit, op: get)\n</known_detections>",
    )
    asyncio.run(_drive(req, monkeypatch, recorder=recorder))
    # The Phase 1 (threat) agent's instructions must contain the seed anchor.
    assert any("<known_detections>" in instr for instr in recorder)


def test_budget_cap_skips_detections_in_a_real_run(monkeypatch):
    # Each call reports 200k output tokens; a 100k cap trips after the first.
    report = asyncio.run(
        _drive(
            engine.EngineRequest(
                resource="Microsoft.ContainerService/managedClusters", max_tokens=100_000
            ),
            monkeypatch,
            usage={"input_token_count": 0, "output_token_count": 200_000},
        )
    )
    skipped = [d for d in report.detections if not d.detection.kql]
    assert skipped, "expected at least one detection skipped by the budget cap"
    assert any("budget" in e for d in skipped for e in d.errors)


def test_base_run_skips_playbook_and_does_not_pause(monkeypatch):
    # Default (no --playbook): the run furnishes threat analysis + detections
    # only, with no HITL pause and no playbooks.
    report = asyncio.run(_drive(
        engine.EngineRequest(resource="Microsoft.ContainerService/managedClusters"),
        monkeypatch, selection="",
    ))
    assert report.detections            # detections still produced
    assert report.playbooks == []
    assert report.playbooks_skipped == []


def test_noninteractive_playbook_pick_generates_without_pause(monkeypatch):
    # --playbook 0 selects without prompting; a playbook is generated.
    report = asyncio.run(_drive(
        engine.EngineRequest(resource="Microsoft.ContainerService/managedClusters"),
        monkeypatch, selection="0",
    ))
    assert len(report.playbooks) == 1
    assert "# IR Playbook:" in report.playbooks[0].text
