"""Checkpointing: a fresh workflow run resumes from disk after an interrupt
and serves completed phases from the checkpoint instead of re-running them.

Uses stubbed agents (no network, no API key) so the test is deterministic —
it verifies the plumbing, not the model.
"""

import asyncio
from unittest.mock import MagicMock

from pylon import engine
from pylon.engine import make_checkpoint_storage
from pylon.models import AttackVector, Detection, ThreatAnalysis

_ANALYSIS = ThreatAnalysis(
    service="Key Vault",
    platform="resource",
    executive_summary="s",
    attack_vectors=[
        AttackVector(
            name="Secret read",
            priority="critical",
            mitre_technique="T1552.001",
            operation="SecretGet",
            log_table="AZKVAuditLogs",
            alert_condition="c",
            rationale="r.",
        ),
    ],
)


def _stub_agent(counters):
    def factory(*a, **k):
        m = MagicMock()

        async def run(prompt, options=None):
            r = MagicMock()
            fmt = (options or {}).get("response_format")
            if fmt is ThreatAnalysis:
                counters["threat"] += 1
                r.value = _ANALYSIS
            elif fmt is Detection:
                counters["detection"] += 1
                r.value = Detection(
                    vector_name="Secret read",
                    mitre_technique="T1552.001",
                    kql="AZKVAuditLogs\n| where TimeGenerated > ago(1h)",
                    tuning_guidance="t",
                    false_positive_notes="f",
                )
            else:
                from pylon.playbook import PlaybookFill
                r.value = PlaybookFill(what_happened="The actor reached the object.", why_it_matters=["The material is now disclosed", "The actor still holds the access"], attack_context="The actor reached the object. It matters because the material is now disclosed.", true_positive_indicators=["The principal has no prior data-plane history", "The read was followed by an export"], containment_role="Key Vault Secrets Officer")
            return r

        m.run = run
        m.as_agent = lambda **kw: m
        return m

    return factory


async def _scenario(tmp_path, monkeypatch):
    counters = {"threat": 0, "detection": 0, "grounding": 0}

    async def fake_grounding(_t):
        counters["grounding"] += 1
        return ""

    async def fake_mitre(_ids):
        return {}

    monkeypatch.setattr(engine, "table_schema_context", fake_grounding)
    monkeypatch.setattr(engine, "mitre_technique_names", fake_mitre)
    monkeypatch.setattr(engine, "make_chat_client", _stub_agent(counters))
    monkeypatch.setattr(engine, "Agent", _stub_agent(counters))

    store = make_checkpoint_storage(tmp_path / "ckpt")
    # Interactive playbook pick -> the run suspends at the HITL menu (the point
    # this test checkpoints and resumes from).
    req = engine.EngineRequest(
        resource="Microsoft.KeyVault/vaults", playbook_selection=engine.PLAYBOOK_PROMPT
    )

    # Run 1: to the HITL suspend, with checkpointing.
    s1 = engine.runnable().run(message=req, stream=True, checkpoint_storage=store)
    async for _ in s1:
        pass
    r1 = await s1.get_final_response()
    assert r1.get_final_state().name == "IDLE_WITH_PENDING_REQUESTS"
    [ev] = r1.get_request_info_events()
    assert counters["threat"] == 1
    assert counters["detection"] >= 1
    before = dict(counters)

    # Simulate a NEW process: fresh storage handle, resume from the latest
    # checkpoint, answer the pending pick.
    store2 = make_checkpoint_storage(tmp_path / "ckpt")
    latest = await store2.get_latest(workflow_name="pylon")
    assert latest is not None
    s2 = engine.runnable().run(
        stream=True,
        checkpoint_id=latest.checkpoint_id,
        responses={ev.request_id: "0"},
        checkpoint_storage=store2,
    )
    async for _ in s2:
        pass
    r2 = await s2.get_final_response()
    report = r2.get_outputs()[0]

    # The run completed...
    assert report.service == "Microsoft.KeyVault/vaults"
    assert len(report.detections) == 1
    # ...without re-running the threat/detection phases (served from checkpoint).
    assert counters["threat"] == before["threat"]
    assert counters["detection"] == before["detection"]


def test_resume_from_checkpoint_does_not_rerun_phases(tmp_path, monkeypatch):
    asyncio.run(_scenario(tmp_path, monkeypatch))


# ── the checkpoint allowlist must be transitively complete ───────────────────


def _resolve(entry: str):
    """"module:QualName" -> the class, as the checkpoint decoder resolves it."""
    import importlib

    module, _, name = entry.partition(":")
    return getattr(importlib.import_module(module), name)


def _models_in(annotation) -> list:
    """Every BaseModel class reachable from a type annotation.

    A TYPED walk rather than substring-matching `str(annotation)`. `get_args`
    unwraps `X | None`, `list[X]`, `dict[str, X]` and nests of those without
    anyone having to guess how they render as text — and a field whose type is
    spelled differently (an alias, a forward ref resolved elsewhere) cannot slip
    past by not containing the expected characters.
    """
    from typing import get_args

    from pydantic import BaseModel

    found = []
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        found.append(annotation)
    for arg in get_args(annotation):
        found.extend(_models_in(arg))
    return found


def _reachable_models(roots) -> dict:
    """{class: the checkpointed type it was reached from}, transitively.

    Two levels deep is exactly as unreadable as one: the decoder resolves every
    type it meets while rebuilding the object graph, so a model nested inside a
    nested model needs registering too.
    """
    from pydantic import BaseModel

    seen, out, queue = set(), {}, list(roots)
    while queue:
        model = queue.pop()
        if model in seen or not (isinstance(model, type) and issubclass(model, BaseModel)):
            continue
        seen.add(model)
        for info in model.model_fields.values():
            for nested in _models_in(info.annotation):
                out.setdefault(nested, model)
                queue.append(nested)
    return out


def test_the_allowlist_is_transitively_complete():
    """CHECKPOINT_ALLOWED_TYPES gates DESERIALIZATION for every checkpointed
    type, not just for ValidatedDetection. An unregistered model anywhere in the
    graph makes the checkpoint unreadable, and the run then silently re-executes
    the phase it should have replayed — paying again for exactly the calls
    --resume exists to skip. It warns on stderr and stops nothing.

    Six were missing at once when this was first written, every one a paid
    feature: LiveCheck (--verify-live), OfflineCheck (--verify-offline),
    TuneResult (--tune), and ProveResult and RetrohuntResult, which no
    hand-written list had counted.

    The first version of this guard walked ValidatedDetection alone — it fixed
    the instance that bit us and would have passed while EngineReport or
    ThreatAnalysis grew the identical bug. It now walks the allowlist itself.
    """
    from pylon.engine import CHECKPOINT_ALLOWED_TYPES

    allowed = set(CHECKPOINT_ALLOWED_TYPES)
    roots = [_resolve(e) for e in CHECKPOINT_ALLOWED_TYPES]
    missing = sorted(
        f"{model.__module__}:{model.__qualname__} (nested in {via.__qualname__})"
        for model, via in _reachable_models(roots).items()
        if f"{model.__module__}:{model.__qualname__}" not in allowed
    )
    assert not missing, "types a checkpoint cannot deserialize: " + ", ".join(missing)


def test_the_allowlist_guard_walks_everything_and_finds_something():
    """A derivation that visits nothing passes for ever, and one that visits
    only the type we already fixed passes for almost as long. Assert the walk
    reaches EVERY checkpointed root and finds a non-trivial graph beneath them —
    not a hardcoded list of the names that happened to be broken."""
    from pylon.engine import CHECKPOINT_ALLOWED_TYPES

    roots = [_resolve(e) for e in CHECKPOINT_ALLOWED_TYPES]
    assert len(roots) == len(CHECKPOINT_ALLOWED_TYPES), "every entry must resolve"

    reachable = _reachable_models(roots)
    assert len(reachable) >= 8, f"the walk found only {len(reachable)} nested models"
    # And it must reach beyond ValidatedDetection, which is what the first
    # version of this guard could not do.
    parents = {via.__qualname__ for via in reachable.values()}
    assert len(parents) >= 3, f"the walk only descended into {parents}"
