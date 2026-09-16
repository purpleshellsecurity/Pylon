"""Saved-list slice 2: append (grow) and seed_context (anchor Phase 1)."""

from pylon.library import append, load, save, seed_context
from pylon.models import Detection, ValidatedDetection


def _vd(name, technique, table, operation, kql="AKSAudit\n| take 1", valid=True):
    return ValidatedDetection(
        detection=Detection(
            vector_name=name, mitre_technique=technique, kql=kql,
            tuning_guidance="t", false_positive_notes="f",
        ),
        log_table=table, valid=valid, errors=[], warnings=[], retried=False,
        operation=operation,
    )


def test_seed_context_empty_without_saved():
    assert seed_context([]) == ""


def test_seed_context_lists_known_detections():
    save_list = [
        {"name": "Read secrets", "mitre_technique": "T1552", "log_table": "AKSAudit", "operation": "get secrets"},
    ]
    block = seed_context(save_list)
    assert "<known_detections>" in block
    assert "Read secrets (T1552, AKSAudit, op: get secrets)" in block
    assert "add any NEW attack vectors" in block


def test_append_adds_only_new(tmp_path):
    save(tmp_path, "aks", [_vd("Read secrets", "T1552", "AKSAudit", "get secrets")])
    # A later run: one repeat (same key), one genuinely new.
    run = [
        _vd("Get secret values", "T1552", "AKSAudit", "get secrets"),      # dup by key
        _vd("Delete namespace", "T1485", "AKSAuditAdmin", "delete namespace"),  # new
    ]
    _path, added = append(tmp_path, "aks", run)
    assert added == 1
    names = [e["name"] for e in load(tmp_path, "aks")]
    # existing entry kept (its reviewed wording), plus the new one
    assert names == ["Read secrets", "Delete namespace"]


def test_append_preserves_existing_kql(tmp_path):
    save(tmp_path, "aks", [_vd("Read secrets", "T1552", "AKSAudit", "get secrets", kql="REVIEWED\n| take 1")])
    append(tmp_path, "aks", [_vd("Read secrets", "T1552", "AKSAudit", "get secrets", kql="DIFFERENT\n| take 9")])
    saved = load(tmp_path, "aks")
    assert len(saved) == 1
    assert "REVIEWED" in saved[0]["kql"]  # existing reviewed entry not overwritten


def test_append_skips_invalid(tmp_path):
    _, added = append(tmp_path, "aks", [_vd("Bad", "T1552", "AKSAudit", "x", valid=False)])
    assert added == 0
