"""`reads.defender_plans.ran` answered the wrong question.

It was set from `defender["ran"]` alone -- whether `az security pricing list`
answered. The assessment that turns those plans into rows lives inside
`if workspace_guid:`, and is stubbed out when the guid does not resolve.

So on a tenant whose inventory reads fine, whose subscription answers, and
whose workspace guid does not (a lapsed token, or no read permission on the
workspace), the scan reported:

    reads.defender_plans: {"ran": true, "detail": "not assessed. workspace
                           guid unresolved"}

An empty `defender_plans.json`, no Defender section in the report, and the
question absent from "what this scan could not answer" -- the run summary said
10 unanswered checks where it was 11. A reader of the sentence was fine and a
reader of the flag was misled, which is word for word what the note above
`diagnostic_settings` in the same constructor describes fixing for its own
field.
"""

import json

import pytest


@pytest.fixture
def scan(tmp_path, monkeypatch):
    """`inventory.run` with a subscription that answers, and a guid that does
    not resolve. `_stub_run` in test_deployed_tables.py returns no rows, so
    `sub_id` is None there and the Defender read never fires at all -- this
    needs the case where it fires and succeeds."""
    from pylon import inventory, scopes

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(inventory, "query_graph", lambda: [
        {"id": "/subscriptions/S/rg/r1", "type": "Microsoft.Storage/storageAccounts",
         "subscriptionId": "S", "location": "eastus", "tags": {}}])

    def _run(guid):
        monkeypatch.setattr(inventory, "resolve_workspace",
                            lambda v: ("t", "/subscriptions/S/ws", guid))
        monkeypatch.setattr(scopes, "defender_plans", lambda sub: {
            "ran": True, "on": ["VirtualMachines"], "off": ["StorageAccounts"],
            "plans": [{"name": "VirtualMachines", "pricingTier": "Standard"},
                      {"name": "StorageAccounts", "pricingTier": "Free"}],
            "detail": "1 of 2 plans on the Standard tier"})
        inventory.run("ws")
        return json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))

    return _run


def test_plans_read_but_never_assessed_is_not_a_read_that_ran(scan):
    written = scan(guid="")
    assert written["reads"]["defender_plans"]["ran"] is False, (
        "the control-plane call answered and nothing was assessed from it")


def test_the_unanswered_question_reaches_the_reader(scan, tmp_path):
    """The point of the flag. `coverage_of_reads` lists a read only when `ran`
    is false, so a true flag deletes the question from the report."""
    from pylon.report import coverage_of_reads

    written = scan(guid="")
    unanswered = [q for q, ok, _why in coverage_of_reads(written["reads"]) if not ok]
    assert any("Defender" in q for q in unanswered), unanswered


def test_the_sidecar_is_empty_when_the_read_did_not_run(scan, tmp_path):
    """The two have to agree: an empty sidecar and `ran=True` is the
    contradiction this whole check exists to stop."""
    scan(guid="")
    rows = json.loads((tmp_path / "defender_plans.json").read_text(encoding="utf-8"))
    assert rows == []
