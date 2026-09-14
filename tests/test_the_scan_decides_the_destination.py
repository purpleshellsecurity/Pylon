"""The scan reads which table a category lands in, and nothing consulted it.

`analyze` reads `logAnalyticsDestinationType` off every diagnostic setting,
works out which table each category fills, and writes that as `expected_tables`.
The table a detection is generated against came from a fixed overlay entry.

On a tenant in Dedicated mode the two agree. Measured on this lab: Key Vault's
setting says Dedicated, 90 rows are in AZKVAuditLogs and none are in
AzureDiagnostics, and the overlay's AZKVAuditLogs is right.

On a tenant left in the default the scan records AzureDiagnostics, the overlay
still says AZKVAuditLogs, and every Key Vault detection is generated against a
table holding nothing. The workspace gate grades them no-match, which reads as
"the attack did not happen here" rather than "you are querying the wrong table".
The tool collected the answer and never asked.
"""

import json

from pylon.deployed import destination_tables

_KV = "microsoft.keyvault/vaults"


def _scan(tmp_path, resource_type, tables, mode_basis="measured"):
    doc = {"resources": [{
        "resource_id": "/subscriptions/x/providers/vaults/one",
        "resource_type": resource_type, "assessment_status": "assessed",
        "surfaces": [{"expected_tables": tables, "mode_basis": mode_basis}],
        "expected_tables": tables}]}
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_no_scan_is_not_an_answer(tmp_path):
    """`None` means nobody looked. It must never read as "fills no tables"."""
    tables, why = destination_tables(_KV, tmp_path / "analysis.json")
    assert tables is None
    assert "no scan document" in why


def test_a_dedicated_tenant_reports_the_resource_specific_table(tmp_path):
    tables, why = destination_tables(_KV, _scan(tmp_path, _KV, ["AZKVAuditLogs"]))
    assert tables == frozenset({"AZKVAuditLogs"})
    assert "read from a diagnostic setting" in why


def test_a_default_tenant_reports_the_shared_table(tmp_path):
    """The case the overlay gets wrong. Same resource type, same category, and
    the rows are somewhere else entirely."""
    tables, _why = destination_tables(_KV, _scan(tmp_path, _KV, ["AzureDiagnostics"]))
    assert tables == frozenset({"AzureDiagnostics"})
    assert "AZKVAuditLogs" not in tables


def test_an_assumed_destination_says_so(tmp_path):
    """A resource with no diagnostic setting has no mode to read, so the table
    is the documented default rather than a measurement. The reason has to say
    which, or a reader acts on a guess in the same voice as a fact."""
    _tables, why = destination_tables(
        _KV, _scan(tmp_path, _KV, ["AZKVAuditLogs"], mode_basis="assumed"))
    assert "assumed" in why


def test_a_resource_the_scan_never_assessed_is_not_an_answer(tmp_path):
    """Looked and could not assess is still nobody looked, for this purpose."""
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps({"resources": [{
        "resource_type": _KV, "assessment_status": "not_assessed",
        "surfaces": [], "expected_tables": ["AZKVAuditLogs"]}]}), encoding="utf-8")
    tables, why = destination_tables(_KV, path)
    assert tables is None and "assessed no" in why


def test_the_run_warns_when_the_overlay_and_the_scan_disagree():
    """The whole point. A mismatch has to be said out loud BEFORE the money,
    because afterwards it is indistinguishable from a quiet tenant."""
    import inspect

    from pylon import cli

    source = inspect.getsource(cli)
    assert "destination_tables(" in source and "target.resource_type" in source, (
        "the run does not consult the destination the scan recorded")
    assert "scan saw nothing land there" in source, (
        "a mismatch that is not printed is a mismatch nobody acts on")
