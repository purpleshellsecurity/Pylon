"""The check that would have found today's bugs without a human reading JSON.

Every defect found on 2026-09-07 came from one move: put the scan's conclusion
about a resource next to the raw API response for that same resource. Three
premises died that way, and 998 tests had missed all three — because every
fixture was written by whoever wrote the premise, so the stub agreed with the
assumption it was meant to test.

`scripts/audit-against-azure.py` is that move, automated. These tests are about
the two properties that decide whether it is worth running:

  * it fires when the two sources disagree
  * it stays quiet when they agree

The second matters as much as the first. A checker that flags healthy resources
gets muted, and then it is worth less than nothing — the first draft did exactly
that, testing the expected table against the hand-maintained column catalogue
and flagging `Event`, a table every Windows VM writes.
"""

import importlib.util
import pathlib
import subprocess

import pytest

from pylon import azcli

_SRC = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "audit-against-azure.py"
_spec = importlib.util.spec_from_file_location("audit_against_azure", _SRC)
audit_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit_mod)

VM = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/lab-vm"
KV = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v1"


@pytest.fixture
def azure(monkeypatch):
    """Stub Azure. `os_type` answers `az vm show`; `settings` answers
    `diagnostic-settings list`."""
    state = {"os_type": "Linux", "settings": "[]", "rc": 0}

    def _run(args, **kwargs):
        if args[0] == "vm":
            return subprocess.CompletedProcess(args, state["rc"],
                                               f"{state['os_type']}\n", "")
        return subprocess.CompletedProcess(args, state["rc"], state["settings"],
                                           "AuthorizationFailed" if state["rc"] else "")

    monkeypatch.setattr(azcli, "run", _run)
    return state


def _doc(rtype, table, **gap):
    rid = VM if "virtualmachines" in rtype.lower() else KV
    return {"workspace": "my-law",
            "provisioned_tables": ["Event", "Syslog", "AZKVAuditLogs"],
            "resources": [{"resource_id": rid, "resource_type": rtype}],
            "coverage_gaps": [{"resource_id": rid, "expected_table": table,
                               "is_logging": False,
                               "dark_reason": "no diagnostic setting",
                               **gap}]}


# ── it fires when the sources disagree ───────────────────────────────────────


def test_a_linux_vm_expecting_event_is_caught(azure):
    """C11, found by hand. `Event` is documented "Windows Event Log on Windows
    computers", so naming it for a Linux machine is advice nobody can follow."""
    azure["os_type"] = "Linux"
    [problem] = audit_mod.audit(_doc("microsoft.compute/virtualmachines", "Event"), 50, "")
    assert problem["check"] == "VM table matches OS"
    assert "Syslog" in problem["azure"]


def test_the_os_comes_from_azure_not_the_resource_name(azure):
    """The first draft looked for "linux" in the resource name. The machine that
    started all this is named for its distro rather than its OS family -- and
    "ubuntu" is not spelled "linux", so the check never fired on the very case
    it was written for."""
    azure["os_type"] = "Windows"
    problems = audit_mod.audit(_doc("microsoft.compute/virtualmachines", "Event"), 50, "")
    assert problems == [], "a Windows VM expecting Event is correct"


def test_no_diagnostic_setting_is_checked_against_the_raw_response(azure):
    azure["settings"] = '[{"properties": {"workspaceId": "/x/my-law"}}]'
    problems = audit_mod.audit(_doc("microsoft.keyvault/vaults", "AZKVAuditLogs"), 50, "")
    assert any(p["check"] == "no diagnostic setting" for p in problems)


def test_a_category_being_off_is_not_reported_as_a_missing_setting(azure):
    """The false positive this script produced on its first real run, and the
    reason the vocabulary was split.

    The workspace had exactly one diagnostic setting reaching itself with the
    relevant category unticked. The scan called that "never configured" -- the
    same words it used for a resource with no settings at all -- so the checker
    read the obvious meaning and accused a correct answer.
    """
    azure["settings"] = '[{"properties": {"workspaceId": "/x/my-law"}}]'
    doc = _doc("microsoft.keyvault/vaults", "AZKVAuditLogs",
               dark_reason="category not enabled")
    assert audit_mod.audit(doc, 50, "") == []


def test_ships_elsewhere_is_checked_too(azure):
    """The mirror: a scan claiming the logs go somewhere else, when a setting
    does point here."""
    azure["settings"] = '[{"properties": {"workspaceId": "/x/my-law"}}]'
    doc = _doc("microsoft.keyvault/vaults", "AZKVAuditLogs",
               dark_reason="ships elsewhere")
    assert any(p["check"] == "ships elsewhere" for p in audit_mod.audit(doc, 50, ""))


def test_logging_must_reach_the_scanned_workspace(azure):
    """A setting shipping to a different workspace is not coverage here: no rule
    in the scanned workspace can read what it sends."""
    azure["settings"] = '[{"properties": {"workspaceId": "/x/some-other-workspace"}}]'
    doc = _doc("microsoft.keyvault/vaults", "AZKVAuditLogs",
               is_logging=True, dark_reason="configured")
    problems = audit_mod.audit(doc, 50, "")
    assert any(p["check"] == "logging reaches workspace" for p in problems)


def test_a_table_this_workspace_does_not_have_is_flagged(azure):
    problems = audit_mod.audit(
        _doc("microsoft.keyvault/vaults", "NoSuchTable"), 50, "")
    assert any(p["check"] == "table exists here" for p in problems)


# ── and stays quiet when they agree ──────────────────────────────────────────


def test_a_healthy_resource_produces_nothing(azure):
    assert audit_mod.audit(_doc("microsoft.keyvault/vaults", "AZKVAuditLogs"), 50, "") == []


def test_a_linux_vm_expecting_syslog_produces_nothing(azure):
    azure["os_type"] = "Linux"
    assert audit_mod.audit(
        _doc("microsoft.compute/virtualmachines", "Syslog"), 50, "") == []


def test_the_table_check_uses_the_workspace_not_the_hand_catalogue(azure):
    """The first draft checked against `TABLE_SCHEMAS` and flagged `Event` —
    a real table every Windows VM writes, simply missing from a catalogue we
    already know is incomplete. A checker whose false positives outnumber its
    findings gets muted, and then it is worth less than nothing."""
    azure["os_type"] = "Windows"
    doc = _doc("microsoft.compute/virtualmachines", "Event")
    assert "Event" in doc["provisioned_tables"]
    assert audit_mod.audit(doc, 50, "") == []


# ── a read that failed is not a disagreement ─────────────────────────────────


def test_an_unreadable_resource_says_so_rather_than_accusing(azure):
    """Same rule as everywhere else: "could not look" must never render as
    "looked and found a problem"."""
    azure["rc"] = 1
    problems = audit_mod.audit(_doc("microsoft.keyvault/vaults", "AZKVAuditLogs"), 50, "")
    assert all("could read" in p["check"] for p in problems)
    assert problems, "and it must not be silent about it either"
