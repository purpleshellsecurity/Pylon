"""A technique id that EXISTS and a technique id that is CURRENT.

`verify_mitre_ids` screened for the first and shipped the second wrong. MITRE
revokes ids and the revoked ones stay in the CTI bundle forever, so a bundle
membership test passes them. Seventeen vectors across seven targets carried
one: every anti-forensics vector this tool had written was labelled T1562.007
or T1562.008, ids MITRE retired in favour of T1686.001 and T1685.002.

The module that catches exactly this already existed and said so in its own
docstring. It was applied to Microsoft's rule templates and never to Pylon's
own output.
"""

import asyncio

import pytest

from pylon import engine, mitre
from pylon.models import AttackVector, ThreatAnalysis


def _vector(technique: str, name: str = "v") -> AttackVector:
    return AttackVector(
        name=name, priority="high", mitre_technique=technique,
        operation="op", log_table="AzureActivity",
        alert_condition="c", rationale="r r.")


def _analysis(*techniques: str) -> ThreatAnalysis:
    return ThreatAnalysis(
        service="X", platform="arm", executive_summary="s",
        attack_vectors=[_vector(t, f"v{i}") for i, t in enumerate(techniques)])


# ── the resolver ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("old,new", [
    ("T1562", "T1685"),
    ("T1562.007", "T1686.001"),
    ("T1562.008", "T1685.002"),
])
def test_a_revoked_id_resolves_to_its_replacement(old, new):
    """The three this tool was actually emitting."""
    got, why = mitre.current(old)
    assert got == new
    assert old in why and new in why


def test_a_current_id_is_returned_unchanged_with_no_explanation():
    assert mitre.current("T1555.006") == ("T1555.006", "")


def test_an_id_attack_has_never_heard_of_is_left_alone():
    """This resolves, it does not validate. `ground` is still the check, and
    the bundle screen upstream is what drops a fabricated id."""
    assert mitre.current("T9999.999") == ("T9999.999", "")


def test_the_replacement_is_itself_current():
    """A one-hop fix that lands on another revoked id would have moved the
    problem rather than fixed it."""
    for old in ("T1562", "T1562.007", "T1562.008"):
        new, _why = mitre.current(old)
        assert mitre.ground(new)["usable"], f"{old} -> {new} is not usable"


def test_a_revocation_with_no_stated_replacement_stops_rather_than_guessing(
        monkeypatch):
    monkeypatch.setitem(mitre.TECHNIQUES, "T0001", {
        "name": "x", "matrix": "enterprise", "tactics": [],
        "sub_technique": False, "revoked": True, "deprecated": False,
        "revoked_by": None})
    assert mitre.current("T0001") == ("T0001", "")


def test_a_revocation_cycle_terminates(monkeypatch):
    """A bad index must not hang the design phase."""
    for a, b in (("T0001", "T0002"), ("T0002", "T0001")):
        monkeypatch.setitem(mitre.TECHNIQUES, a, {
            "name": "x", "matrix": "enterprise", "tactics": [],
            "sub_technique": False, "revoked": True, "deprecated": False,
            "revoked_by": b})
    got, _why = mitre.current("T0001")
    assert got in ("T0001", "T0002")


# ── the gate ─────────────────────────────────────────────────────────────────

def _run(analysis, monkeypatch, verified=None):
    names = verified if verified is not None else {
        v.mitre_technique: "n" for v in analysis.attack_vectors}

    async def _names(_ids):
        return names
    monkeypatch.setattr(engine, "mitre_technique_names", _names)
    return asyncio.run(engine.verify_mitre_ids(analysis))


def test_a_revoked_vector_is_relabelled_not_dropped(monkeypatch):
    """The whole point. Dropping is what a pure validity check leads to, and it
    deletes a detection that was fine in order to fix its label."""
    out = _run(_analysis("T1562.008"), monkeypatch)
    assert len(out.attack_vectors) == 1
    assert out.attack_vectors[0].mitre_technique == "T1685.002"


def test_a_current_vector_is_untouched(monkeypatch):
    out = _run(_analysis("T1555.006"), monkeypatch)
    assert out.attack_vectors[0].mitre_technique == "T1555.006"


def test_every_vector_in_a_mixed_plan_is_handled(monkeypatch):
    out = _run(_analysis("T1562.007", "T1555.006", "T1562.008"), monkeypatch)
    assert [v.mitre_technique for v in out.attack_vectors] == [
        "T1686.001", "T1555.006", "T1685.002"]


def test_the_relabelling_is_announced(monkeypatch, capsys):
    """A silently relabelled vector changes what the document claims it
    detects."""
    _run(_analysis("T1562.008"), monkeypatch)
    err = capsys.readouterr().err
    assert "T1562.008" in err and "T1685.002" in err
    assert "relabelled 1 vector" in err


def test_a_fabricated_id_is_still_dropped(monkeypatch):
    """Relabelling must not become a way past the bundle screen."""
    out = _run(_analysis("T9999.999", "T1555.006"), monkeypatch,
               verified={"T1555.006": "n"})
    assert [v.mitre_technique for v in out.attack_vectors] == ["T1555.006"]


def test_an_unreachable_bundle_still_relabels_nothing(monkeypatch):
    """Fail-open keeps the vectors, and a run that could not verify must not
    then quietly rewrite their ids as if it had."""
    from pylon.grounding import MitreBundleUnavailable

    async def boom(_ids):
        raise MitreBundleUnavailable("bundle down")
    monkeypatch.setattr(engine, "mitre_technique_names", boom)
    out = asyncio.run(engine.verify_mitre_ids(_analysis("T1562.008")))
    assert out.mitre_verification == "unavailable"
    assert out.attack_vectors[0].mitre_technique == "T1562.008"
