"""The maturity ladder: Sigma status derived from recorded evidence.

The point of the ladder is that a reader can tell a fresh model output from a
detection that has been measured. So the tests that matter are the ones proving
a status can never be claimed without the record to back it.
"""

import yaml

from pylon.library import (
    EXPERIMENTAL,
    LAB_PROVEN,
    RETROHUNT,
    STABLE,
    TEST,
    TUNED,
    derive_status,
    entry_from,
    load,
    save,
    with_derived_status,
    with_evidence,
)
from pylon.models import Detection, ValidatedDetection


def _vd(name="Key backup", technique="T1552.001", table="AZKVAuditLogs", op="KeyBackup"):
    return ValidatedDetection(
        detection=Detection(
            vector_name=name, mitre_technique=technique,
            kql=f"{table}\n| where TimeGenerated > ago(1h)",
            tuning_guidance="t", false_positive_notes="f",
        ),
        log_table=table, valid=True, errors=[], warnings=[], retried=False, operation=op,
    )


# --- what each status has to be earned by ------------------------------------


def test_a_generated_detection_is_experimental():
    # Nothing has measured it. Saying so is the whole point: a fresh generation
    # must not be indistinguishable from something that has been proven.
    assert entry_from(_vd())["status"] == EXPERIMENTAL
    assert entry_from(_vd())["evidence"] == {}


def test_measurement_against_real_data_earns_test():
    e = {"key": "k"}
    assert derive_status(with_evidence(e, TUNED, {"hits_30d": 12})) == TEST
    assert derive_status(with_evidence(e, RETROHUNT, {"hits": 3, "window_days": 90})) == TEST


def test_stable_requires_both_halves_of_a_lab_run():
    # Fired on the attack AND quiet on the benign baseline. A detection that
    # fires on everything is not proven, it is broken — grading that as
    # production-ready is the exact failure this ladder exists to prevent.
    e = {"key": "k"}
    proven = with_evidence(e, LAB_PROVEN, {"fired": True, "benign_quiet": True})
    assert derive_status(proven) == STABLE

    noisy = with_evidence(e, LAB_PROVEN, {"fired": True, "benign_quiet": False})
    assert derive_status(noisy) == TEST

    silent = with_evidence(e, LAB_PROVEN, {"fired": False, "benign_quiet": True})
    assert derive_status(silent) == TEST


def test_inconclusive_evidence_is_measured_not_absent():
    # A lab run that fired but recorded no benign check is inconclusive, not
    # missing. Grading it as `experimental` would discard real information.
    assert derive_status(with_evidence({"key": "k"}, LAB_PROVEN, {"fired": True})) == TEST


def test_an_empty_evidence_record_earns_nothing():
    assert derive_status(with_evidence({"key": "k"}, TUNED, {})) == EXPERIMENTAL


def test_malformed_evidence_falls_to_the_lower_status():
    # Never the higher one: a corrupt record must not read as a promotion.
    assert derive_status({"evidence": "not a dict"}) == EXPERIMENTAL
    assert derive_status({"evidence": {LAB_PROVEN: "not a dict"}}) == EXPERIMENTAL
    assert derive_status({}) == EXPERIMENTAL


# --- status is a view of the record, never a second source of truth ----------


def test_a_hand_edited_status_is_corrected_to_what_the_evidence_supports():
    # Someone editing the YAML cannot promote a detection by typing a word.
    lying = {"key": "k", "status": STABLE, "evidence": {}}
    assert with_derived_status(lying)["status"] == EXPERIMENTAL


def test_adding_evidence_rederives_the_status():
    e = entry_from(_vd())
    assert e["status"] == EXPERIMENTAL
    after = with_evidence(e, TUNED, {"hits_30d": 4})
    assert after["status"] == TEST


def test_with_evidence_does_not_mutate_the_original():
    e = entry_from(_vd())
    with_evidence(e, TUNED, {"hits_30d": 4})
    assert e["status"] == EXPERIMENTAL and e["evidence"] == {}


def test_evidence_records_accumulate_rather_than_replace():
    e = with_evidence(entry_from(_vd()), TUNED, {"hits_30d": 4})
    e = with_evidence(e, RETROHUNT, {"hits": 9})
    assert set(e["evidence"]) == {TUNED, RETROHUNT}


# --- back-compat with libraries committed before this existed ----------------


def test_a_library_written_before_this_field_still_loads(tmp_path):
    # The real risk in this change. An entry with no status/evidence must load,
    # and must come back as honestly unmeasured rather than unrated or crashing.
    old_format = {
        "target": "keyvault",
        "detections": [{
            "key": "t1552.001|azkvauditlogs|keybackup|key-backup",
            "name": "Key backup",
            "mitre_technique": "T1552.001",
            "log_table": "AZKVAuditLogs",
            "operation": "KeyBackup",
            "kql": "AZKVAuditLogs\n| where TimeGenerated > ago(1h)",
        }],
    }
    path = tmp_path / "keyvault.yaml"
    path.write_text(yaml.dump(old_format), encoding="utf-8")

    entries = load(tmp_path, "keyvault")
    assert len(entries) == 1
    assert entries[0]["status"] == EXPERIMENTAL
    assert entries[0]["kql"].startswith("AZKVAuditLogs")  # untouched


def test_saved_entries_round_trip_through_yaml(tmp_path):
    save(tmp_path, "keyvault", [_vd()])
    reloaded = load(tmp_path, "keyvault")
    assert reloaded[0]["status"] == EXPERIMENTAL
    assert reloaded[0]["evidence"] == {}


def test_evidence_survives_a_round_trip(tmp_path):
    save(tmp_path, "keyvault", [_vd()])
    entries = load(tmp_path, "keyvault")
    entries[0] = with_evidence(entries[0], LAB_PROVEN, {"fired": True, "benign_quiet": True})
    (tmp_path / "keyvault.yaml").write_text(
        yaml.dump({"target": "keyvault", "detections": entries}), encoding="utf-8"
    )
    assert load(tmp_path, "keyvault")[0]["status"] == STABLE


def test_status_values_are_the_sigma_vocabulary():
    # Sigma's spec, not words invented here, so the library stays legible to
    # anyone who reads detection content.
    assert {EXPERIMENTAL, TEST, STABLE} <= {
        "stable", "test", "experimental", "deprecated", "unsupported"
    }
