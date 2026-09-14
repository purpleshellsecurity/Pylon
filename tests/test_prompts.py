"""Prompt assembly checks — routing, token substitution, asset integrity."""

import re

import pytest

from pylon.prompts import (
    build_system_prompt,
    is_known_service,
    load_asset,
    table_context,
)


def test_arm_threat_prompt_contains_service_and_rules():
    prompt = build_system_prompt("arm", "Key Vault", "threat")
    assert "<service>Key Vault</service>" in prompt
    assert "OperationNameValue" in prompt
    assert "<role>" in prompt and "<task>" in prompt
    assert "__SERVICE__" not in prompt


def test_no_prompt_ships_an_unsubstituted_token():
    for plane, service in (("arm", "Key Vault"), ("entra", "AuditLogs"),
                           ("dataplane", "AZKVAuditLogs")):
        prompt = build_system_prompt(plane, service, "detection")
        assert "__QUERY_RULES__" not in prompt, plane
        assert "__SERVICE__" not in prompt, plane


# The claims that survived the merge, one per plane, quoted from the set that
# used to carry them. Two rule sets both reached the SAME detection prompt and
# stated the same rules in different words -- eight topics twice on ARM, eight
# on Entra, four on the data plane -- so a correctness fix had to be made in two
# files and sometimes was not. The duplicates are gone; these are the claims
# that existed in only one of the two, and losing them silently is the risk this
# guards.
MOVED = {
    "arm": ["Claims is a JSON STRING", "NORMALIZE OUTPUT"],
    "dataplane": ["never substitute AzureDiagnostics", "NORMALIZE OUTPUT"],
    "entra": ["OperationName MUST be matched", "NORMALIZE OUTPUT"],
}


@pytest.mark.parametrize("plane,service", [("arm", "Key Vault"),
                                           ("entra", "AuditLogs"),
                                           ("dataplane", "AZKVAuditLogs")])
def test_every_claim_that_survived_the_merge_still_reaches_a_prompt(plane, service):
    prompt = build_system_prompt(plane, service, "detection")
    for claim in MOVED[plane]:
        assert claim in prompt, f"{plane} lost {claim!r} in the merge"


@pytest.mark.parametrize("plane,service", [("arm", "Key Vault"),
                                           ("entra", "AuditLogs"),
                                           ("dataplane", "AZKVAuditLogs")])
def test_no_rule_is_stated_twice_in_one_prompt(plane, service):
    """The condition that made the merge necessary, asserted so it cannot come
    back. Each phrase below was in both rule sets, worded differently."""
    prompt = build_system_prompt(plane, service, "detection")
    for phrase in ("End let-statement queries with a semicolon",
                   "Time filter FIRST"):
        assert prompt.count(phrase) <= 1, f"{plane} states {phrase!r} twice"


def test_playbook_requires_target():
    with pytest.raises(ValueError):
        build_system_prompt("arm", "Key Vault", "playbook")


def test_playbook_substitutes_target():
    prompt = build_system_prompt("arm", "Key Vault", "playbook", playbook_target="Vault deletion")
    assert "Vault deletion" in prompt
    assert "__TARGET__" not in prompt


def test_dataplane_injects_per_table_context():
    prompt = build_system_prompt("dataplane", "StorageBlobLogs", "threat")
    assert "StorageBlobLogs" in prompt


def test_unknown_phase_raises():
    with pytest.raises(ValueError):
        build_system_prompt("arm", "Key Vault", "nonsense")


def test_all_assets_render_without_leftover_tokens():
    for platform, service in [
        ("arm", "Key Vault"),
        ("dataplane", "StorageBlobLogs"),
        ("graph", "AuditLogs"),
    ]:
        for phase in ("threat", "detection"):
            prompt = build_system_prompt(platform, service, phase)
            assert "__SERVICE__" not in prompt
            assert "__QUERY_RULES__" not in prompt
        prompt = build_system_prompt(platform, service, "playbook", playbook_target="x")
        assert "__TARGET__" not in prompt


def test_table_context_available_for_all_dataplane_tables():
    for table in [
        "StorageBlobLogs",
        "AZKVAuditLogs",
    ]:
        assert table_context(table), f"missing table context asset for {table}"


def test_the_service_gate_still_answers_for_the_one_path_that_uses_it():
    """`is_known_service` decides whether to spend a model call verifying that a
    target is real. Every ARM and data-plane run goes through resource mode now,
    where the engine skips the gate because the resource type came from this
    tool's own catalogue. Entra is the one path left that reaches it."""
    assert is_known_service("graph", "AuditLogs")
    assert not is_known_service("graph", "Totally Fake Service")


def test_assets_preserve_markdown_fences():
    # The extraction unescaped TS \` sequences — fences must survive verbatim.
    assert "```kql" in load_asset("arm/detection.md")


# ── The notes' length is capped in two places, so both are pinned ─────────────
# A live run returned three long tuning bullets where the asset asked for two.
# The asset is a template the model reads once; the field description sits on the
# field it is filling, and only that one rides in the response schema. Both now
# carry the cap, and both are checked here — one copy going stale silently is
# this codebase's recurring scar.


def test_every_detection_asset_caps_the_tuning_notes():
    import pathlib

    from pylon.prompts import _ASSETS

    assets = sorted(pathlib.Path(_ASSETS).glob("*/detection.md"))
    assert assets, "no detection assets found"
    for path in assets:
        text = path.read_text(encoding="utf-8")
        assert "**Tuning Notes:**" in text, path
        assert "Two bullets at most" in text, path
        assert "20 words or fewer" in text, path


def test_the_response_schema_caps_the_notes_too():
    """The cap has to be in the schema, not only the prose: the schema is what
    the model is handed alongside the field it is filling."""
    from pylon.models import Detection

    props = Detection.model_json_schema()["properties"]
    tuning = props["tuning_guidance"]["description"]
    fps = props["false_positive_notes"]["description"]
    assert "At most 2 bullet" in tuning and "20 words" in tuning
    assert "one sentence" in fps and "25 words" in fps


def test_the_summary_template_does_not_number_the_threat_headings():
    """A run rendered "1. RBAC Role Assignment", "2. Diagnostic Settings Deleted"
    under a page heading that already reads "1. Executive summary". The renderer
    was faithful — the template asked for the numbers."""
    import pathlib

    from pylon.prompts import _ASSETS

    for path in sorted(pathlib.Path(_ASSETS).glob("*/threat.md")):
        text = path.read_text(encoding="utf-8")
        assert "### 1. [Threat Name]" not in text, path
        assert "### 2. [Threat Name]" not in text, path


def test_the_summary_template_says_not_to_echo_its_own_heading():
    """executive_summary is a FIELD of a structured response, not a document, so
    a "Section 1: Executive Summary" line inside it duplicates the heading the
    page puts above it. The template read as if the model were writing one
    markdown file, which stopped being true when the output became structured."""
    import pathlib

    from pylon.prompts import _ASSETS

    for path in sorted(pathlib.Path(_ASSETS).glob("*/threat.md")):
        text = path.read_text(encoding="utf-8")
        assert "Do not repeat this heading" in text, path


# Every (platform, service) pair that reaches a distinct playbook asset, with a
# string only that asset carries, so a routing regression that sends a plane to
# the wrong template is caught here — and nowhere else, because the rendered
# prompt still looks entirely plausible.
_PLAYBOOK_ROUTES = [
    ("arm", "Key Vault", "Azure ARM"),
    ("dataplane", "StorageBlobLogs", "Azure Data Plane"),
    ("graph", "AuditLogs", "(Entra ID directory changes)"),
]

_PLAYBOOK_SECTIONS = (
    "## Quick Triage",
    "## Scope of Actor Activity",
    "## Investigation",
    "## Preserve Evidence",
    "## Containment",
    "## Eradication",
    "## Validation",
    "## Recovery Verification",
)


@pytest.mark.parametrize("platform,service,marker", _PLAYBOOK_ROUTES,
                         ids=lambda v: v if isinstance(v, str) else str(v))
def test_every_plane_renders_a_complete_playbook_prompt(platform, service, marker):
    """End to end through build_system_prompt, not render_playbook.

    test_playbook_assets.py renders each asset DIRECTLY, so it cannot see the
    routing layer at all — a plane could be sent to another plane's template and
    every assertion there would still pass. This is the one check that exercises
    the pair, and it needs no model, no tenant and no network.
    """
    prompt = build_system_prompt(platform, service, "playbook", playbook_target="Test Vector")
    assert marker in prompt, f"{platform}/{service} routed to the wrong asset"
    missing = [s for s in _PLAYBOOK_SECTIONS if s not in prompt]
    assert not missing, f"{platform}/{service} missing {missing}"
    assert "\\$" not in prompt, "PowerShell backslash-escape artifact"
    assert "CorrelationId == CorrelationId" not in prompt, "let/column shadowing tautology"
    assert not re.search(r"\|\s*take\s+\d+", prompt), "unordered take"
    assert "__SERVICE__" not in prompt and "__TARGET__" not in prompt
