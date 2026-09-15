from pylon.attack_paths import (
    Tag,
    derive_edges,
    normalize_tags,
    sinks,
    sources,
    tag_seed_context,
)
from pylon.models import AttackVector


def _vector(name, requires, enables, mitre="T1078.004"):
    return AttackVector(
        name=name,
        priority="high",
        mitre_technique=mitre,
        operation="OP",
        log_table="AzureActivity",
        alert_condition="cond",
        rationale="What it does. Why it matters.",
        requires=requires,
        enables=enables,
    )


# ── the token list ────────────────────────────────────────────────────────────


def test_tags_are_string_valued_and_unique():
    values = [t.value for t in Tag]
    assert len(values) == len(set(values))            # no dupes
    assert Tag.IDENTITY_APP_CREDENTIAL.value == "identity.app_credential"
    assert isinstance(Tag.PRIV_ADMIN, str)            # str-enum: compares as its value


# ── normalize_tags ────────────────────────────────────────────────────────────


def test_normalize_accepts_strings_and_tags():
    tags, dropped = normalize_tags(["identity.valid_session", Tag.PRIV_ADMIN])
    assert tags == [Tag.IDENTITY_VALID_SESSION, Tag.PRIV_ADMIN]
    assert dropped == []


def test_normalize_dedupes_preserving_order():
    tags, _ = normalize_tags(
        ["priv.admin", "identity.valid_session", "priv.admin"]
    )
    assert tags == [Tag.PRIV_ADMIN, Tag.IDENTITY_VALID_SESSION]


def test_normalize_drops_unknown_tokens():
    tags, dropped = normalize_tags(["identity.valid_session", "made.up.token", ""])
    assert tags == [Tag.IDENTITY_VALID_SESSION]
    assert dropped == ["made.up.token", ""]


# ── derive_edges ──────────────────────────────────────────────────────────────


def test_edge_forms_when_enables_meets_requires():
    a = _vector("add cred", [Tag.IDENTITY_VALID_SESSION], [Tag.IDENTITY_APP_CREDENTIAL])
    b = _vector("assign role", [Tag.IDENTITY_APP_CREDENTIAL], [Tag.PRIV_ROLE_ASSIGNED])
    edges = derive_edges([a, b])
    assert edges == [(0, 1, ["identity.app_credential"])]


def test_no_self_edges_and_no_edge_without_overlap():
    a = _vector("a", [], [Tag.DATA_STORAGE_READ])
    b = _vector("b", [Tag.PRIV_ADMIN], [Tag.IMPACT_EXFIL])   # requires something a doesn't enable
    assert derive_edges([a, b]) == []


def test_full_chain_links_consecutive_steps():
    steps = [
        _vector("steal token", [], [Tag.IDENTITY_VALID_SESSION]),
        _vector("add cred", [Tag.IDENTITY_VALID_SESSION], [Tag.IDENTITY_APP_CREDENTIAL]),
        _vector("assign role", [Tag.IDENTITY_APP_CREDENTIAL], [Tag.PRIV_ROLE_ASSIGNED]),
        _vector("snapshot", [Tag.PRIV_ROLE_ASSIGNED], [Tag.DATA_DISK_ACCESS]),
        _vector("exfil", [Tag.DATA_DISK_ACCESS], [Tag.IMPACT_EXFIL]),
    ]
    edges = derive_edges(steps)
    assert {(i, j) for i, j, _ in edges} == {(0, 1), (1, 2), (2, 3), (3, 4)}


def test_derive_edges_accepts_plain_string_values():
    # duck-typed units whose requires/enables are raw strings, not Tag
    class U:
        def __init__(self, requires, enables):
            self.requires, self.enables = requires, enables

    edges = derive_edges([U([], ["x"]), U(["x"], [])])
    assert edges == [(0, 1, ["x"])]


def test_sources_and_sinks():
    steps = [
        _vector("entry", [], [Tag.IDENTITY_VALID_SESSION]),
        _vector("mid", [Tag.IDENTITY_VALID_SESSION], [Tag.PRIV_ADMIN]),
        _vector("objective", [Tag.PRIV_ADMIN], []),
    ]
    assert sources(steps) == [0]
    assert sinks(steps) == [2]


# ── model integration ─────────────────────────────────────────────────────────


def test_attack_vector_defaults_to_empty_and_is_backward_compatible():
    v = AttackVector(
        name="x", priority="low", mitre_technique="T1530", operation="OP",
        log_table="StorageBlobLogs", alert_condition="c", rationale="a. b.",
    )
    assert v.requires == [] and v.enables == []


def test_attack_vector_coerces_string_tokens_to_tags():
    v = _vector("x", ["identity.valid_session"], ["priv.admin"])
    assert v.requires == [Tag.IDENTITY_VALID_SESSION]
    assert v.enables == [Tag.PRIV_ADMIN]


# ── prompt block ──────────────────────────────────────────────────────────────


def test_normalize_step_dedupes_vector_tags():
    import asyncio

    from pylon.engine import normalize_vector_tags
    from pylon.models import ThreatAnalysis

    v = _vector("x", [Tag.PRIV_ADMIN, Tag.PRIV_ADMIN], [Tag.IMPACT_EXFIL])
    ta = ThreatAnalysis(service="s", platform="arm", executive_summary="e", attack_vectors=[v])
    out = asyncio.run(normalize_vector_tags(ta))
    assert out.attack_vectors[0].requires == [Tag.PRIV_ADMIN]     # deduped
    assert out.attack_vectors[0].enables == [Tag.IMPACT_EXFIL]


def test_tag_seed_context_lists_every_token_and_both_fields():
    block = tag_seed_context()
    assert "<attacker_footholds>" in block and "</attacker_footholds>" in block
    assert "requires:" in block and "enables:" in block
    # every token appears so the model can only pick from the closed list
    for t in Tag:
        assert t.value in block
