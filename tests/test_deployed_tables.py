"""Naming a table this tenant actually has, and saying so when we can't.

A detection names one table. Get it wrong and the query is syntactically
perfect, passes every validator, ships, and returns nothing for ever -- which
looks exactly like a tenant where nothing happened. It is the quietest failure
this tool can produce.

The way to get it wrong is the legacy/resource-specific split: the same Key
Vault audit event lands in `AzureDiagnostics` or `AZKVAuditLogs` depending on one
field on one diagnostic setting, and the catalogue that routes a detection knows
only what Azure OFFERS, never what this tenant CHOSE.

The evidence was already being fetched and thrown away. `tables._plans` read the
control-plane table list on every scan, kept the billing tier, and discarded the
names -- so nothing knew which tables the workspace has.

The asymmetry is the design, and most of these tests are about the second line:

    the table exists      the tenant uses that mode. Proof.
    the table is absent   proves NOTHING. Legacy mode and "not deployed yet"
                          are identical from here.
    no list at all        nobody looked.

Absence must never pick the other table. Writing a detection ahead of deploying
the service is a normal thing to do and has to keep working -- it just must not
come out looking like a measurement.
"""

import json
import subprocess
from datetime import UTC

import pytest

from pylon import azcli, deployed, tables
from pylon.analysis_model import Analysis, Reads, ReadState
from pylon.models import Detection, ValidatedDetection

KV_DEDICATED = "AZKVAuditLogs"
LEGACY = "AzureDiagnostics"


def _doc(tmp_path, **kwargs):
    """A minimal scan document on disk."""
    body = {"generated_at": "2026-09-07T00:00:00Z", "reads": {}, **kwargs}
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


# ── reading the evidence ─────────────────────────────────────────────────────


def test_no_scan_document_is_unchecked_not_empty(tmp_path):
    """Absent evidence and "the workspace has no tables" are different answers,
    and only the second would justify falling back to legacy."""
    have, why = deployed.from_analysis(tmp_path / "nope.json")
    assert have is None
    assert "pylon analyze" in why, "say what would fix it"


def test_an_unreadable_document_is_unchecked(tmp_path):
    path = tmp_path / "analysis.json"
    path.write_text("{ not json", encoding="utf-8")
    have, why = deployed.from_analysis(path)
    assert have is None and "could not read" in why


def test_a_scan_whose_activity_read_failed_is_unchecked(tmp_path):
    """The scan ran, the table-activity query did not. `_legs_agree` guarantees
    the null section and the ran=False read agree, so the read's own detail is
    the honest reason to show."""
    path = _doc(tmp_path, tables=None,
                reads={"table_activity": {"ran": False,
                                          "detail": "AuthorizationFailed"}})
    have, why = deployed.from_analysis(path)
    assert have is None
    assert "AuthorizationFailed" in why


def test_a_scan_with_table_activity_supplies_it(tmp_path):
    path = _doc(tmp_path, tables=[{"table_name": KV_DEDICATED},
                                  {"table_name": "AzureActivity"}])
    have, why = deployed.from_analysis(path)
    assert have == frozenset({KV_DEDICATED, "AzureActivity"})
    assert "2 table(s)" in why and "holding data" in why


def test_a_provisioned_schema_is_not_evidence_of_use(tmp_path):
    """The correction, as a test.

    A real tenant returned 844 tables from the control-plane list and 34 holding
    data. `AKSAudit`, `AZMSRunTimeAuditLogs` and `CDBDataPlaneRequests` were all
    "present" in a tenant running no AKS, no Service Bus and no Cosmos DB --
    installing a Content Hub solution provisions its table SCHEMAS, so existence
    means a solution was installed, not that a row was ever written.

    Shipped as it was, this would have answered "confirmed present in the
    scanned workspace" for a table nothing has ever written to.
    """
    path = _doc(tmp_path,
                provisioned_tables=[KV_DEDICATED, "AKSAudit", "CDBDataPlaneRequests"],
                tables=[{"table_name": KV_DEDICATED}])
    have, _why = deployed.from_analysis(path)
    assert have == frozenset({KV_DEDICATED}), (
        "confirmation must come from data, not from a provisioned schema")
    assert deployed.basis("AKSAudit", have) == "catalogue"
    assert deployed.basis(KV_DEDICATED, have) == "deployed"


# ── what a table name is worth ───────────────────────────────────────────────


def test_a_table_the_workspace_has_is_confirmed():
    assert deployed.basis(KV_DEDICATED, frozenset({KV_DEDICATED})) == "deployed"


def test_a_table_the_workspace_lacks_is_an_assumption_not_a_verdict():
    """Not "wrong" -- the service may simply not be deployed yet. But it is not
    a measurement and must not render as one."""
    assert deployed.basis(KV_DEDICATED, frozenset({"AzureActivity"})) == "catalogue"


def test_no_evidence_is_unchecked_and_not_catalogue():
    """The distinction that matters: "we looked and it is not there" is a much
    stronger statement than "we never looked", and only the first is a reason to
    go checking a diagnostic setting."""
    assert deployed.basis(KV_DEDICATED, None) == "unchecked"


def test_the_default_basis_on_a_detection_is_unchecked():
    """The safe direction, same as `ReadState` defaulting to not-run: a caller
    that never supplied evidence claims nothing."""
    d = ValidatedDetection(
        detection=Detection(vector_name="v", mitre_technique="T1098",
                            kql="AzureActivity | take 1", tuning_guidance="-",
                            false_positive_notes="-"),
        log_table="AzureActivity", valid=True, errors=[], warnings=[], retried=False)
    assert d.table_basis == "unchecked"


# ── choosing between candidates ──────────────────────────────────────────────


def test_with_no_evidence_the_routing_choice_stands():
    """This does not get to overrule the catalogue on a guess."""
    assert deployed.prefer(KV_DEDICATED, [KV_DEDICATED, LEGACY], None) == KV_DEDICATED


def test_a_deployed_pick_is_left_alone():
    assert deployed.prefer(KV_DEDICATED, [KV_DEDICATED, LEGACY],
                           frozenset({KV_DEDICATED})) == KV_DEDICATED


def test_a_sibling_the_tenant_actually_has_wins():
    """The whole point. The catalogue routed to the resource-specific table; this
    workspace is in legacy mode and has AzureDiagnostics instead. Left alone, the
    detection could never fire."""
    assert deployed.prefer(KV_DEDICATED, [KV_DEDICATED, LEGACY],
                           frozenset({LEGACY})) == LEGACY


def test_when_nothing_on_the_list_is_deployed_the_pick_stands():
    """Writing ahead of deployment. Substituting a different unconfirmed table
    would be trading one guess for another; the honest move is to keep the
    routing choice and label it."""
    assert deployed.prefer(KV_DEDICATED, [KV_DEDICATED, LEGACY],
                           frozenset({"SigninLogs"})) == KV_DEDICATED


# ── what the human is told ───────────────────────────────────────────────────


def test_the_unconfirmed_note_names_the_consequence():
    """A marker is enough to notice. It is not enough to act on -- so the note
    says which other table to look in and what happens if it is wrong."""
    text = deployed.note(KV_DEDICATED, "catalogue")
    assert LEGACY in text
    assert "never fire" in text


def test_the_unchecked_note_says_what_would_fix_it():
    text = deployed.note(KV_DEDICATED, "unchecked", "no scan document")
    assert "pylon analyze" in text


def test_a_confirmed_table_is_not_hedged():
    """Annotating the expected case trains people to ignore annotations."""
    assert "NOT confirmed" not in deployed.note(KV_DEDICATED, "deployed")


# ── the control-plane read: existence and tier are different questions ───────


def _rest(monkeypatch, payload, returncode=0, stderr=""):
    monkeypatch.setattr(
        azcli, "run",
        lambda *a, **k: subprocess.CompletedProcess(
            ["az"], returncode, json.dumps(payload) if payload is not None else "", stderr))


def test_a_table_whose_plan_is_unreadable_still_exists(monkeypatch):
    """The bug this split exists to prevent. `_plans` kept only tables whose plan
    was a known tier, so "not in the dict" meant BOTH "no such table" and "the
    plan did not parse". Harmless when the only question is billing; as an
    existence check it would silently downgrade a confirmed table to an assumed
    one and send someone hunting a diagnostic setting that is fine."""
    _rest(monkeypatch, {"value": [
        {"name": KV_DEDICATED, "properties": {"plan": "Analytics"}},
        {"name": "WeirdTable", "properties": {"plan": "SomethingNew"}},
        {"name": "NoProps"},
    ]})
    names, plans, error = tables.deployed("/subscriptions/s/ws")
    assert error is None
    assert names == sorted([KV_DEDICATED, "WeirdTable", "NoProps"])
    assert plans == {KV_DEDICATED: "Analytics"}, "the tier map stays strict"


def test_a_failed_read_is_none_not_an_empty_workspace(monkeypatch):
    """`{}` was returned for both, so an ARM hiccup and a workspace with no
    tables were the same value."""
    _rest(monkeypatch, None, returncode=1, stderr="AuthorizationFailed")
    names, plans, error = tables.deployed("/subscriptions/s/ws")
    assert names is None
    assert plans == {}
    assert error and "AuthorizationFailed" in error


def test_a_workspace_with_no_tables_is_an_empty_list_not_none(monkeypatch):
    _rest(monkeypatch, {"value": []})
    names, _plans, error = tables.deployed("/subscriptions/s/ws")
    assert names == [] and error is None


def test_unparseable_output_is_a_failure(monkeypatch):
    monkeypatch.setattr(
        azcli, "run",
        lambda *a, **k: subprocess.CompletedProcess(["az"], 0, "not json", ""))
    names, _plans, error = tables.deployed("/subscriptions/s/ws")
    assert names is None and error and "parse" in error


# ── the document keeps the two halves honest ─────────────────────────────────


def test_the_document_cannot_claim_tables_it_did_not_read():
    from datetime import datetime
    with pytest.raises(ValueError, match="provisioned_tables"):
        Analysis(generated_at=datetime.now(UTC),
                 provisioned_tables=[KV_DEDICATED])


def test_the_document_cannot_drop_tables_it_did_read():
    from datetime import datetime
    with pytest.raises(ValueError, match="provisioned_tables"):
        Analysis(generated_at=datetime.now(UTC),
                 reads=Reads(provisioned_tables=ReadState(ran=True)))


def test_an_empty_list_is_a_read_that_found_nothing():
    from datetime import datetime
    a = Analysis(generated_at=datetime.now(UTC),
                 reads=Reads(provisioned_tables=ReadState(ran=True)),
                 provisioned_tables=[])
    assert a.provisioned_tables == []


# ── the crash this work uncovered ────────────────────────────────────────────


def test_an_inventory_that_raised_still_writes_an_honest_document(tmp_path, monkeypatch):
    """Pre-existing, and the worst possible place for it: `endpoint_os=census`
    and two summary prints read names bound only on the success branch, so a
    Resource Graph failure -- a lapsed `az login` -- died with UnboundLocalError
    instead of writing the document that says the read did not happen.

    The one path the whole model exists to describe was the one path that could
    not reach it.
    """
    from pylon import inventory

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(inventory, "query_graph",
                        lambda: (_ for _ in ()).throw(RuntimeError("no az")))
    monkeypatch.setattr(inventory, "resolve_workspace",
                        lambda v: ("t", "/subscriptions/x/ws", "guid"))

    assert inventory.run("ws") == 1
    written = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
    assert written["reads"]["inventory"]["ran"] is False
    assert written["resources"] is None
    assert written["provisioned_tables"] is None
    assert written["endpoint_os"] is None


# ── the guid fork, which is a second place to forget a name ──────────────────


def _stub_run(monkeypatch, tmp_path, guid):
    """`inventory.run` with the inventory read succeeding and the workspace guid
    resolving to `guid`. An empty guid is what `resolve_workspace` returns on any
    failed ARM read -- a lapsed token, or no read permission on the workspace."""
    from pylon import inventory

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(inventory, "query_graph", lambda: [])
    monkeypatch.setattr(inventory, "resolve_workspace",
                        lambda v: ("t", "/subscriptions/x/ws", guid))
    return inventory.run("ws")


def test_an_unresolved_workspace_guid_does_not_crash_the_scan(tmp_path, monkeypatch):
    """`deployed_names` was bound in one place -- inside `if workspace_guid:` --
    and read unconditionally forty lines below. The else branch hand-mirrors a
    dozen other names and missed that one, so a tenant whose inventory reads fine
    and whose workspace guid does not resolve died with UnboundLocalError.

    Exactly the bug the file already carries a scar comment about, twenty lines
    lower. It came back because the previous fix was "remember to guard" rather
    than a shape that cannot be forgotten.
    """
    assert _stub_run(monkeypatch, tmp_path, guid="") == 0
    written = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
    assert written["provisioned_tables"] is None
    assert written["reads"]["provisioned_tables"]["ran"] is False


def test_a_leg_that_did_not_run_leaves_its_section_null(tmp_path, monkeypatch):
    """`rules` and `coverage_gaps` were guarded on `resources is not None` alone,
    so a tenant where Resource Graph answers and the SecurityInsights read is
    denied built a document claiming rules it never read. `_legs_agree` refused
    it -- correctly -- and the scan died with a pydantic traceback instead of
    writing the document that says which leg failed.

    `tables` already guarded on its own leg. The difference was never deliberate.
    """
    _stub_run(monkeypatch, tmp_path, guid="")
    written = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
    assert written["reads"]["rules"]["ran"] is False
    assert written["rules"] is None, "a leg that did not run has no section"
    # The contrast that makes it meaningful: coverage DID run and found nothing.
    assert written["reads"]["resource_activity"]["ran"] is True
    assert written["coverage_gaps"] == []


def test_the_printed_summary_does_not_report_zero_for_an_unread_leg(
        tmp_path, monkeypatch, capsys):
    """The document said null and the screen said 0. "rules = 0" is the claim
    this whole project refuses, printed on the line the operator actually reads.
    """
    _stub_run(monkeypatch, tmp_path, guid="")
    out = capsys.readouterr().out
    rules = [ln for ln in out.splitlines() if ln.strip().startswith("analytics rules")]
    assert rules and "not measured" in rules[0], rules
    # Not a blanket "say not measured for everything" -- a leg that ran and
    # found nothing must still print 0.
    gaps = [ln for ln in out.splitlines() if ln.strip().startswith("ingestion gaps")]
    assert gaps and gaps[0].split()[-1] == "0", gaps
    # And the reason is on the screen, not only in the document.
    assert "NOT MEASURED" in out
