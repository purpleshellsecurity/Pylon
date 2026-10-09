"""Regression tests for the offline grading exit contract."""
import pytest

from pylon.grading_policy import grade_exit_status


@pytest.mark.parametrize("kind", ["noisy", "errors", "unreadable"])
@pytest.mark.parametrize("strict", [False, True])
def test_defects_fail_in_every_profile(kind, strict):
    values = {"noisy": 0, "errors": 0, "unreadable": 0,
              "known_silent": 0, "inconclusive": 0}
    values[kind] = 1
    assert grade_exit_status(**values, strict=strict) == 1


@pytest.mark.parametrize("kind", ["known_silent", "inconclusive"])
def test_missing_behavioral_evidence_fails_strict_only(kind):
    values = {"noisy": 0, "errors": 0, "unreadable": 0,
              "known_silent": 0, "inconclusive": 0}
    values[kind] = 1
    assert grade_exit_status(**values, strict=True) == 1
    assert grade_exit_status(**values, strict=False) == 0


def test_all_passing_fixtures_succeed():
    assert grade_exit_status(noisy=0, errors=0, unreadable=0,
                             known_silent=0, inconclusive=0, strict=True) == 0


def test_invalid_counts_are_rejected():
    with pytest.raises(ValueError):
        grade_exit_status(noisy=0, errors=0, unreadable=-1,
                          known_silent=0, inconclusive=0)
