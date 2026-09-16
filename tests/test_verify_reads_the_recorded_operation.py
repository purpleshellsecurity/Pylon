"""Ground truth comes from what the detection RECORDS, not from its name.

`design verify` used to look the operation up in plan.json by matching the
detection's vector name back to the plan entry that asked for it. The detection
phase rewrites that name, and it rewrites it in more than one direction:

    SecretDelete (delete secret)      -> SecretDelete (Key Vault secret deletion)
    VM created or updated             -> VM created or updated via Microsoft...
    VaultPatch (patch vault config)   -> Key Vault configuration patched (VaultPatch)

Each rewrite bought one more matching rule and the next defeated it. The third
shares no leading word with the plan entry at all, so no amount of prefix
matching reaches it. Four Key Vault detections went unmeasured on the run that
settled it -- reported as `error`, sitting in the coverage line as defects
nobody could act on, while the operation they were built for was recorded on
each of them the whole time.
"""

import json

from pylon import cli


class _Args:
    def __init__(self, source, workspace="ws", window="30d"):
        self.source, self.workspace, self.window = source, workspace, window


def _report(operation: str, vector_name: str) -> dict:
    return {
        "service": "Microsoft.KeyVault/vaults", "platform": "resource",
        "generation_yield": 1, "critical_gaps": [],
        "analysis": {
            "service": "Microsoft.KeyVault/vaults", "platform": "resource",
            "executive_summary": "s", "attack_vectors": [],
        },
        "detections": [{
            "detection": {
                "vector_name": vector_name, "mitre_technique": "T1555.006",
                "kql": "AZKVAuditLogs | take 1", "tuning_guidance": "- x",
                "false_positive_notes": "y",
            },
            "log_table": "AZKVAuditLogs", "valid": True, "errors": [],
            "warnings": [], "retried": False, "operation": operation,
        }],
    }


def _run(tmp_path, monkeypatch, report: dict, plan: dict | None = None):
    """Run `design verify` with the workspace stubbed, and return the
    verification rows it wrote back into report.json."""
    (tmp_path / "report.json").write_text(json.dumps(report), encoding="utf-8")
    if plan is not None:
        (tmp_path / "plan.json").write_text(json.dumps(plan), encoding="utf-8")

    from pylon import validate, verification
    monkeypatch.setattr(validate, "resolve", lambda w: ("t", "a", "guid"))
    monkeypatch.setattr(verification, "blocks", lambda _t: [])
    # Every read of the workspace goes through here. Returning one row means a
    # count of 1 for both the ground truth and the detection, so a detection
    # that reaches the workspace at all gets a real verdict rather than an
    # error, and "error" in these tests always means the lookup, never the net.
    monkeypatch.setattr(validate, "_run_kql",
                        lambda kql, guid, window: [{"Count": 1}])

    code = cli._design_verify(_Args(str(tmp_path)))
    written = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    return code, written.get("verification") or []


def test_the_operation_is_taken_from_the_detection(tmp_path, monkeypatch):
    """This name shares no leading word with any plan entry, which is the case
    no prefix match can reach."""
    code, rows = _run(
        tmp_path, monkeypatch,
        _report("VaultPatch", "Key Vault configuration patched (VaultPatch)"))
    assert code == 0
    assert [r["operation"] for r in rows] == ["VaultPatch"]
    assert rows[0]["verdict"] != "error"


def test_a_stale_plan_does_not_override_what_the_detection_records(
        tmp_path, monkeypatch):
    """plan.json is no longer read. A plan left behind by an earlier run must
    not be able to point the count at a different operation."""
    code, rows = _run(
        tmp_path, monkeypatch,
        _report("SecretPurge", "SecretPurge (irreversibly destroy secret)"),
        plan={"attack_vectors": [
            {"name": "SecretPurge (irreversibly destroy secret)",
             "operation": "SomethingElse"}]})
    assert code == 0
    assert [r["operation"] for r in rows] == ["SecretPurge"]


def test_a_missing_plan_no_longer_refuses_the_run(tmp_path, monkeypatch):
    """The gate stood on a file the command does not open. A precondition that
    proves nothing is worse than none."""
    code, rows = _run(tmp_path, monkeypatch,
                      _report("SecretGet", "SecretGet (read secret)"))
    assert code == 0 and len(rows) == 1


def test_a_detection_with_no_recorded_operation_is_an_error_not_a_guess(
        tmp_path, monkeypatch):
    """Falling back to the name match would restore exactly the ambiguity this
    deletes. The error says which half is missing."""
    _code, rows = _run(tmp_path, monkeypatch,
                       _report("", "SecretGet (read secret)"))
    assert [r["verdict"] for r in rows] == ["error"]
    assert "records no operation" in (rows[0].get("detail") or "")
