"""The generation half's types, made to mean what they say.

`analysis_model` was rewritten around a data model: `Strict` forbids unknown
fields, and `_legs_agree` makes "this section is populated but its read did not
run" unconstructible. `models.py` -- the same distinctions on the generation side
-- never got that pass. It had 13 classes, 0 validators and no config, so every
invariant its docstrings stated was constructible and one class of typo was
silent.

Each test below names a state that WAS accepted before this change. They are the
review's findings, turned into the thing that stops them coming back.
"""

import pytest
from pydantic import ValidationError

from pylon.models import (Detection, LiveCheck, OfflineCheck,
                          OperationCheck, ProveResult, RetrohuntResult,
                          TuneResult, ValidatedDetection)


# ── a misspelled field is no longer dropped on the floor ─────────────────────


@pytest.mark.parametrize("cls,kwargs", [
    (LiveCheck, {"ran": True, "rowcount": 99}),          # row_count
    (TuneResult, {"ran": True, "hitcount": 4}),          # hit_count
    (ProveResult, {"ran": True, "benignquiet": True}),   # benign_quiet
    (RetrohuntResult, {"ran": True, "requested_days": 1, "covered_days": 1,
                       "truncated": False, "hit": 3}),   # hits
])
def test_a_renamed_or_misspelled_field_is_refused(cls, kwargs):
    """Pydantic ignores unknown fields by default, so the real field silently
    took its default and the value went nowhere. `analysis_model.Strict` exists
    because that shipped once; this half was still doing it."""
    with pytest.raises(ValidationError):
        cls(**kwargs)


# ── ran=False means nothing was learned ──────────────────────────────────────


def test_a_query_that_did_not_run_cannot_report_rows():
    with pytest.raises(ValidationError, match="nothing was learned"):
        LiveCheck(ran=False, ok=True, row_count=7)


def test_a_query_that_did_not_run_cannot_report_ok():
    with pytest.raises(ValidationError, match="nothing was learned"):
        OfflineCheck(ran=False, ok=True)


def test_calibration_that_did_not_run_cannot_suggest_a_threshold():
    """A threshold nobody measured is worse than none: it is a number someone
    will deploy."""
    with pytest.raises(ValidationError, match="nothing was learned"):
        TuneResult(ran=False, p95_hourly=40, top_actors=["svc@corp.com"])


def test_a_proof_that_did_not_run_cannot_claim_the_detection_fired():
    with pytest.raises(ValidationError, match="nothing was learned"):
        ProveResult(ran=False, fired=True, benign_quiet=True)


def test_the_error_names_every_field_that_contradicts_ran():
    """A caller fixing this wants the whole list, not one per attempt."""
    with pytest.raises(ValidationError) as caught:
        ProveResult(ran=False, fired=True, baseline_hits=2)
    message = str(caught.value)
    assert "fired" in message and "baseline_hits" in message


@pytest.mark.parametrize("cls,kwargs", [
    (LiveCheck, {"ran": False, "error": "credential failure"}),
    (TuneResult, {"ran": False, "error": "could not execute"}),
    (ProveResult, {"ran": False, "error": "deadline"}),
])
def test_saying_why_it_did_not_run_is_still_allowed(cls, kwargs):
    """The point is not to forbid `ran=False` -- it is the honest outcome. An
    error string and the tiers that were skipped are records of the failure, not
    claims about the tenant."""
    assert cls(**kwargs).ran is False


# ── the retrohunt's numbers must agree with each other ───────────────────────


def test_a_truncated_window_cannot_claim_it_was_not():
    """5 of 90 days with truncated=False reads as 85 quiet days. That is the
    difference between "we looked and found nothing" and "we could not look"."""
    with pytest.raises(ValidationError, match="contradicts covered_days"):
        RetrohuntResult(ran=True, requested_days=90, covered_days=5,
                        truncated=False, hits=4)


def test_a_full_window_cannot_claim_truncation():
    with pytest.raises(ValidationError, match="contradicts covered_days"):
        RetrohuntResult(ran=True, requested_days=30, covered_days=30, truncated=True)


def test_history_cannot_be_longer_than_the_window_asked_for():
    with pytest.raises(ValidationError, match="cannot be longer"):
        RetrohuntResult(ran=True, requested_days=7, covered_days=90, truncated=False)


@pytest.mark.parametrize("requested,covered,truncated", [
    (90, 5, True), (30, 30, False), (7, 7, False), (90, 89, True),
])
def test_the_agreeing_combinations_are_accepted(requested, covered, truncated):
    result = RetrohuntResult(ran=True, requested_days=requested,
                             covered_days=covered, truncated=truncated)
    assert result.truncated is truncated


# ── the three-answer status ──────────────────────────────────────────────────


def test_an_operation_status_outside_the_three_is_refused():
    """The docstring names exactly three, and the third -- provider-absent --
    is the one that needed a name: the catalog cannot judge, which is not the
    same as the operation being suspect."""
    with pytest.raises(ValidationError):
        OperationCheck(status="banana", operation="Microsoft.KeyVault/vaults/write")


@pytest.mark.parametrize("status", ["known", "unknown", "provider-absent"])
def test_the_three_documented_answers_are_accepted(status):
    assert OperationCheck(status=status).status == status


# ── the gate's own contract ──────────────────────────────────────────────────


def _detection():
    return Detection(vector_name="RBAC role assignment",
                     mitre_technique="T1098.003",
                     kql="AzureActivity | where TimeGenerated > ago(1h)",
                     tuning_guidance="raise the threshold if a deployment pipeline "
                                     "assigns roles on a schedule",
                     false_positive_notes="a routine admin granting access")


def test_a_detection_cannot_be_valid_and_carry_errors():
    """Every consumer reads `valid` rather than the list, so this is a detection
    that failed validation and shipped anyway."""
    with pytest.raises(ValidationError, match="valid=True"):
        ValidatedDetection(detection=_detection(), log_table="AzureActivity",
                           retried=False, valid=True, warnings=[],
                           errors=["column CallerIpAddress does not exist"])


def test_a_detection_may_be_valid_with_warnings():
    """Warnings are advisory by design -- an operation the catalog could not
    confirm is not a reason to withhold the detection."""
    d = ValidatedDetection(detection=_detection(), log_table="AzureActivity",
                           retried=False, valid=True, errors=[],
                           warnings=["operation not in the catalog"])
    assert d.valid and d.warnings


def test_an_invalid_detection_carrying_its_errors_is_the_normal_case():
    d = ValidatedDetection(detection=_detection(), log_table="AzureActivity",
                           retried=False, valid=False, warnings=[],
                           errors=["no time filter"])
    assert not d.valid and d.errors


# ── zero is a measurement, not an absence ────────────────────────────────────
#
# The first version of `_nothing_learned` tested `not in (None, False, 0, "", [])`,
# so every falsy value read as "nothing claimed" and the validators below were
# half-built: they caught a check that did not run claiming SEVEN rows, and
# waved through the same check claiming ZERO. Zero is the dangerous one. It is
# the never-fires verdict, and a threshold of zero is the number most likely to
# be deployed.


@pytest.mark.parametrize("cls,kwargs,field", [
    (LiveCheck, {"ran": False, "row_count": 0}, "row_count"),
    (TuneResult, {"ran": False, "hit_count": 0}, "hit_count"),
    (TuneResult, {"ran": False, "p95_hourly": 0}, "p95_hourly"),
    (ProveResult, {"ran": False, "baseline_hits": 0}, "baseline_hits"),
    (ProveResult, {"ran": False, "fired": False}, "fired"),
    (RetrohuntResult, {"ran": False, "hits": 0}, "hits"),
    (RetrohuntResult, {"ran": False, "distinct_actors": 0}, "distinct_actors"),
])
def test_a_check_that_did_not_run_cannot_report_zero(cls, kwargs, field):
    with pytest.raises(ValidationError, match="nothing was learned") as caught:
        cls(**kwargs)
    assert field in str(caught.value)


def test_zero_is_still_a_legitimate_result_when_the_check_did_run():
    """The point is not that zero is forbidden. A query that ran and matched
    nothing is the most common honest outcome there is."""
    assert LiveCheck(ran=True, ok=True, row_count=0).row_count == 0
    assert RetrohuntResult(ran=True, requested_days=7, covered_days=7,
                           truncated=False, hits=0).hits == 0


def test_a_field_left_at_its_default_is_not_a_claim():
    """`ok` defaults to False and `row_count` to None. A check that did not run
    and says nothing else must construct cleanly, or the honest outcome becomes
    the one the model refuses."""
    assert LiveCheck(ran=False).ran is False
    assert TuneResult(ran=False, error="could not execute").ran is False


def test_a_document_survives_a_round_trip():
    """The predicate compares against declared defaults rather than asking which
    fields were explicitly set. Serialised JSON carries every field, including
    the ones sitting at their defaults, so a `model_fields_set` test would refuse
    a document it had just written."""
    original = LiveCheck(ran=False, error="credential failure")
    assert LiveCheck.model_validate_json(original.model_dump_json()) == original
