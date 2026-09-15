"""Saved list: matching key, save/load round-trip, and the new/same/missing diff."""

from pylon.library import (
    detection_key,
    diff,
    entry_from,
    list_path,
    load,
    save,
    target_slug,
)
from pylon.models import Detection, ValidatedDetection


def _vd(name, technique, table, operation, kql="AKSAudit\n| take 1", valid=True):
    return ValidatedDetection(
        detection=Detection(
            vector_name=name,
            mitre_technique=technique,
            kql=kql,
            tuning_guidance="t",
            false_positive_notes="f",
        ),
        log_table=table,
        valid=valid,
        errors=[],
        warnings=[],
        retried=False,
        operation=operation,
    )


def test_target_slug():
    assert target_slug("Microsoft.KeyVault/vaults") == "microsoft-keyvault-vaults"
    assert target_slug("Entra") == "entra"


def test_key_ignores_wording_matches_on_operation():
    # Same attack, different names — same operation => same key.
    a = detection_key("T1552", "AKSAudit", "list secrets", "Enumerate Kubernetes secrets (bulk read)")
    b = detection_key("T1552", "AKSAudit", "list secrets", "List Secrets cluster-wide")
    assert a == b


def test_key_normalizes_embellished_technique():
    a = detection_key("T1485 - Data Destruction", "AzureActivity", "DELETE")
    b = detection_key("T1485", "AzureActivity", "DELETE")
    assert a == b


def test_key_distinguishes_table_and_operation():
    assert detection_key("T1552", "AKSAudit", "list") != detection_key("T1552", "AKSAuditAdmin", "list")
    assert detection_key("T1552", "AKSAudit", "list") != detection_key("T1552", "AKSAudit", "read")


def test_save_load_round_trip(tmp_path):
    dets = [_vd("Read secrets", "T1552", "AKSAudit", "get secrets")]
    path = save(tmp_path, "Microsoft.ContainerService/managedClusters", dets)
    assert path == list_path(tmp_path, "Microsoft.ContainerService/managedClusters")
    loaded = load(tmp_path, "Microsoft.ContainerService/managedClusters")
    assert len(loaded) == 1
    assert loaded[0]["name"] == "Read secrets"
    assert loaded[0]["operation"] == "get secrets"


def test_save_skips_invalid_and_skipped(tmp_path):
    dets = [
        _vd("Good", "T1552", "AKSAudit", "get"),
        _vd("Bad", "T1552", "AKSAudit", "get", valid=False),
        _vd("Skipped", "T1485", "AKSAudit", "del", kql="", valid=False),
    ]
    save(tmp_path, "aks", dets)
    assert len(load(tmp_path, "aks")) == 1


def test_load_missing_file_returns_empty(tmp_path):
    assert load(tmp_path, "never-saved") == []


def test_diff_buckets_new_same_missing(tmp_path):
    baseline = [_vd("Read secrets", "T1552", "AKSAudit", "get secrets")]
    save(tmp_path, "aks", baseline)
    saved = load(tmp_path, "aks")

    run = [
        _vd("Get secret values", "T1552", "AKSAudit", "get secrets"),   # same key, reworded name
        _vd("Delete namespace", "T1485", "AKSAuditAdmin", "delete namespace"),  # new
    ]
    d = diff(saved, run)
    assert [v.detection.vector_name for v in d.new] == ["Delete namespace"]
    assert [v.detection.vector_name for v in d.same] == ["Get secret values"]
    assert [e["name"] for e in d.missing] == []


def test_diff_flags_missing(tmp_path):
    save(tmp_path, "aks", [_vd("Read secrets", "T1552", "AKSAudit", "get secrets"),
                           _vd("Delete ns", "T1485", "AKSAuditAdmin", "delete namespace")])
    saved = load(tmp_path, "aks")
    run = [_vd("Read secrets", "T1552", "AKSAudit", "get secrets")]  # didn't reproduce the delete
    d = diff(saved, run)
    assert [e["name"] for e in d.missing] == ["Delete ns"]


def test_entry_has_stable_key():
    e = entry_from(_vd("x", "T1552", "AKSAudit", "get secrets"))
    assert e["key"] == detection_key("T1552", "AKSAudit", "get secrets", "x")
