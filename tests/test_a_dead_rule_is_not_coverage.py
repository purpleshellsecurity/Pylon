"""MITRE coverage counts only rules that can fire: not disabled, not
never-fires, not broken. Health that was never established still counts."""

import pytest

from pylon.analysis_model import GapType
from pylon.gapscan import build, can_fire

INDEX = {"SigninLogs": ["T1078"]}
CANDIDATES = {"T1078": {"name": "Valid Accounts", "tactics": ["Initial Access"]}}
LIVE = {"SigninLogs"}


def rule(name="R", *, enabled=True, health="fires"):
    return {"name": name, "_techniques": ["T1078"], "_enabled": enabled,
            "rule_health_status": health, "tables_referenced": ["SigninLogs"]}


def verdict(rules):
    rows, _ = build(INDEX, rules, LIVE, {}, CANDIDATES)
    return rows[0]["gap_type"], rows[0]["basis"]


# ── can_fire, the three answers ──────────────────────────────────────────────

def test_a_working_rule_can_fire():
    assert can_fire(rule()) is True


@pytest.mark.parametrize("health", ["never-fires", "broken"])
def test_a_rule_the_health_leg_condemned_cannot(health):
    assert can_fire(rule(health=health)) is False


def test_a_disabled_rule_cannot_fire_whatever_its_health_says():
    """`_enabled` comes from the rule itself, so it is known even when the
    health leg did not run."""
    assert can_fire(rule(enabled=False, health="fires")) is False
    assert can_fire(rule(enabled=False, health=None)) is False


@pytest.mark.parametrize("health", [None, "not-assessed", "unreadable", "inconclusive"])
def test_health_that_was_never_established_is_not_a_verdict(health):
    assert can_fire(rule(health=health)) is None


# ── the coverage verdict ─────────────────────────────────────────────────────

def test_a_live_rule_still_covers():
    kind, _ = verdict([rule()])
    assert kind == "covered"


@pytest.mark.parametrize("state", [
    {"enabled": False}, {"health": "never-fires"}, {"health": "broken"}])
def test_a_dead_rule_does_not_cover(state):
    kind, basis = verdict([rule(**state)])
    assert kind == "rule_cannot_fire", basis


def test_the_basis_names_every_dead_rule_and_why():
    """The basis names each dead rule and why it is dead."""
    _kind, basis = verdict([rule("Alpha", health="never-fires"),
                            rule("Beta", enabled=False)])
    assert "Alpha (never-fires)" in basis
    assert "Beta (disabled)" in basis


def test_one_live_rule_among_dead_ones_still_covers():
    kind, basis = verdict([rule("Live"), rule("Dead", health="never-fires")])
    assert kind == "covered"
    assert "1 further rule claims it and cannot fire" in basis


def test_a_run_without_health_does_not_collapse_coverage():
    """With no health verdicts at all, rules still count and the basis says
    unverified."""
    kind, basis = verdict([rule(health=None)])
    assert kind == "covered", "an unchecked rule was treated as a dead one"
    assert "not health checked" in basis, basis


def test_rule_cannot_fire_is_a_real_gap_type():
    assert "rule_cannot_fire" in GapType.__args__


def test_the_partition_still_adds_up():
    """`rule_cannot_fire` counts as uncovered, so the partition still covers
    every candidate."""
    from pylon.analysis_model import Gap
    from pylon.summarise import build as summarise

    gaps = [Gap(technique_id="T1078", technique_name="Valid Accounts",
                gap_type="rule_cannot_fire", basis="1 rule, dead")]
    out = summarise([], [], [], gaps, [], 3)
    assert out["techniques_uncovered"] == 1
    assert out["techniques_covered"] == 0
