"""The two joins where a fabrication used to get through.

Phase 1's output is screened hard: a technique ID not in the MITRE bundle deletes
the vector, and the tag lists are normalised against a closed set. Phase 2's
output was screened softly at both of the places it can invent something.

Its technique ID was only reshaped by `normalize_technique_id` -- and that field
is what `threats_covered` is built from, so an ID recalled rather than chosen
inflated the coverage number with nothing to notice it. A recalled ID is a real
ID; reshaping a string is not verification.

Its operation name was checked and the finding was a warning, which meant a
detection filtering on a name the table never writes validated, shipped, and
counted. That was the right call while a vocabulary might be a partial sample. It
stopped being right when a target began requiring a complete partition.
"""

import asyncio

import pytest

from pylon.engine import _screen_detection_techniques
from pylon.models import AttackVector, Detection, ThreatAnalysis, ValidatedDetection
from pylon.services import vocabulary_is_closed
from pylon.validation.validate_kql import validate_kql


def _query(table: str, operation: str) -> str:
    column = "OperationName"
    return (f"{table}\n| where TimeGenerated > ago(1h)\n"
            f'| where {column} == "{operation}"\n'
            f"| project TimeGenerated, {column}")


def test_a_fabricated_operation_now_fails_the_detection():
    """It used to warn. A warning does not trigger the corrective retry that
    already exists, so the detection shipped with a filter that cannot match."""
    result = validate_kql(_query("AZKVAuditLogs", "SecretGett"), "AZKVAuditLogs")
    assert not result.valid
    assert any("SecretGett" in e for e in result.errors)
    assert not any("SecretGett" in w for w in result.warnings)


def test_a_real_operation_is_left_alone():
    result = validate_kql(_query("AZKVAuditLogs", "SecretGet"), "AZKVAuditLogs")
    assert result.valid
    assert result.errors == []


@pytest.mark.parametrize("table,fake", [
    ("StorageBlobLogs", "LeaseBlob"),          # the exact wrong name shipped once
    ("StorageQueueLogs", "ReadMessages"),
    ("StorageTableLogs", "SelectEntities"),
    ("StorageFileLogs", "ReadFile"),
])
def test_every_closed_vocabulary_refuses_a_name_it_does_not_hold(table, fake):
    assert vocabulary_is_closed(table)
    assert not validate_kql(_query(table, fake), table).valid


def test_azure_activity_stays_a_warning_because_the_table_cannot_judge():
    """Its vocabulary is per RESOURCE TYPE, not per table -- AzureActivity carries
    every provider in Azure. The table alone cannot say whether a name is real, so
    refusing on it would reject correct detections."""
    assert not vocabulary_is_closed("AzureActivity")


def _analysis(vector_technique: str) -> ThreatAnalysis:
    return ThreatAnalysis(
        service="Microsoft.KeyVault/vaults", platform="resource",
        executive_summary="x", mitre_verification="verified",
        attack_vectors=[AttackVector(
            name="Read a secret", priority="high", mitre_technique=vector_technique,
            operation="SecretGet", log_table="AZKVAuditLogs",
            alert_condition="x", rationale="x")],
    )


def _detection(technique: str) -> ValidatedDetection:
    return ValidatedDetection(
        detection=Detection(vector_name="Read a secret", mitre_technique=technique,
                            kql="AZKVAuditLogs | take 1", tuning_guidance="x",
                            false_positive_notes="x"),
        log_table="AZKVAuditLogs", valid=True, errors=[], warnings=[], retried=False,
        operation="SecretGet", rationale="x", priority="high")


def test_an_invented_phase_two_technique_falls_back_to_the_verified_one():
    out = asyncio.run(_screen_detection_techniques(
        [_detection("T9999.001")], _analysis("T1555.006")))
    assert out[0].detection.mitre_technique == "T1555.006"
    assert any("T9999.001" in w for w in out[0].warnings)


def test_a_real_phase_two_technique_is_untouched_and_unremarked():
    out = asyncio.run(_screen_detection_techniques(
        [_detection("T1555.006")], _analysis("T1555.006")))
    assert out[0].detection.mitre_technique == "T1555.006"
    assert out[0].warnings == []


def test_an_unscreened_analysis_does_not_get_screened_here_either():
    """When the bundle was unreachable in phase 1, nothing was verified. Screening
    against it now would report a verification that did not happen -- the same
    mistake as reading an unreachable checker as a pass."""
    analysis = _analysis("T1555.006")
    analysis.mitre_verification = "unavailable"
    out = asyncio.run(_screen_detection_techniques([_detection("T9999.001")], analysis))
    assert out[0].detection.mitre_technique == "T9999.001"
    assert out[0].warnings == []


def test_a_refusal_is_not_a_fabrication():
    """The bug this check shipped with, found on its first real run.

    MITRE_RULE asks the model, by name, to write "unmapped" when no technique in
    the prompt fits the vector. Two of 52 Key Vault detections did exactly that --
    Certificate Purge and Certificate Pending Update -- and the screen read the
    refusal as a bad ID and replaced it with the vector's technique, asserting a
    mapping the model had just declined to make.

    Overriding a model at the moment it refuses to guess is worse than the
    fabrication the check exists to catch: the fabrication is visible and this is
    not. `report_design` already treats the sentinel as a value, excluding it from
    the coverage count rather than counting it as covered.
    """
    from pylon.prompts import UNMAPPED

    out = asyncio.run(_screen_detection_techniques(
        [_detection(UNMAPPED)], _analysis("T1555.006")))
    assert out[0].detection.mitre_technique == UNMAPPED
    assert out[0].warnings == []


def test_a_vector_that_refused_is_not_used_as_a_fallback():
    """If phase 1 wrote "unmapped" too, there is nothing verified to fall back
    to, and substituting the sentinel for a bad ID would launder one unusable
    value into another."""
    from pylon.prompts import UNMAPPED

    out = asyncio.run(_screen_detection_techniques(
        [_detection("T9999.001")], _analysis(UNMAPPED)))
    assert out[0].detection.mitre_technique == "T9999.001"
    assert any("no verified technique" in w for w in out[0].warnings)


def test_an_invented_id_is_still_caught_beside_the_refusal():
    """The check still does its job; it just knows one string it must not touch."""
    from pylon.prompts import UNMAPPED

    out = asyncio.run(_screen_detection_techniques(
        [_detection("T9999.001"), _detection(UNMAPPED)], _analysis("T1555.006")))
    assert out[0].detection.mitre_technique == "T1555.006"
    assert out[1].detection.mitre_technique == UNMAPPED
