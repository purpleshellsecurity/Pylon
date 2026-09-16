"""The expiry check on `tablemap.TABLE_MAP`.

`TABLE_MAP` is hand-written from Microsoft's docs and there is no second source
for it, so it cannot be replaced by a lookup -- but it can be told when it has
gone stale. Azure adds a category, the map does not have it, `table_for` returns
`unmapped`, and a real loggable category becomes invisible to every coverage
verdict. Nothing errors. The scan just quietly stops asking.

The tests that matter here are the ones about NOT reporting. A drift report is
read by someone deciding whether to trust a coverage number, so a false "in
sync" and a false "drifted" are both expensive:

  * a type that could not be read must never render as a type that agrees
  * a category list az returned in a shape we cannot classify must produce no
    finding at all, rather than treating every metric category as a missing row

The response shape could not be pinned from Microsoft's published reference --
the CLI page documents no output and the REST schema pages 404 -- so both known
shapes are exercised here and an unknown third says so out loud.
"""

import re
import subprocess

import pytest

from pylon import azcli, tabledrift
from pylon.tablemap import TABLE_MAP

KV = "microsoft.keyvault/vaults"
KV_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v1"


def _az(monkeypatch, stdout="[]", returncode=0, stderr=""):
    """Stub the bounded runner, not `subprocess`. Patching past `azcli` would
    also patch past its timeout, which is the thing that keeps a slow tenant
    from hanging the scan."""
    monkeypatch.setattr(
        azcli, "run",
        lambda *a, **k: subprocess.CompletedProcess(["az"], returncode, stdout, stderr))


def _cat(name, kind="Logs", nested=False):
    """One category entry, in either of the two shapes az is known to emit."""
    return ({"name": name, "properties": {"categoryType": kind}} if nested
            else {"name": name, "categoryType": kind})


# ── a read that did not happen is not agreement ──────────────────────────────


def test_a_failed_read_reports_ran_false_and_claims_no_drift(monkeypatch):
    _az(monkeypatch, returncode=1, stderr="AuthorizationFailed")
    [finding] = tabledrift.survey({KV: [KV_ID]}, types=[KV])
    assert finding.ran is False
    assert finding.error and "AuthorizationFailed" in finding.error
    assert finding.unlisted == [] and finding.not_offered_here == []
    assert finding.drifted is False, "an unread type must not be reported as drift"


def test_a_hung_tenant_costs_one_type_not_the_run(monkeypatch):
    """`read_categories` goes through `azcli`, so a hang is a failed call with a
    reason rather than an exception that ends the survey at the first slow
    resource type."""
    monkeypatch.setattr(
        azcli.subprocess, "run",
        lambda *a, **k: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(cmd=["az"], timeout=60)))
    entries, error = tabledrift.read_categories(KV_ID)
    assert entries is None
    assert error and "did not finish" in error


def _verdict(text: str) -> dict[str, int]:
    """The verdict block as {label: count}.

    Parsed rather than string-matched: the counts sit in an aligned column now,
    so asserting on "0 drifted" was asserting on the padding.
    """
    return {m.group(2): int(m.group(1))
            for m in re.finditer(r"^\s+(\d+)\s\s(.+)$", text, re.M)}


def test_an_unreadable_type_never_renders_as_a_clean_one(monkeypatch):
    _az(monkeypatch, returncode=1, stderr="ResourceNotFound")
    text = tabledrift.render(tabledrift.survey({KV: [KV_ID]}, types=[KV]))
    assert "NOT CHECKED" in text
    assert _verdict(text) == {"match the map": 0, "drifted": 0,
                              "could not be checked": 1,
                              "not run in this tenant, so not checked": 0}


def test_no_matching_resource_is_not_a_clean_bill(monkeypatch):
    """An empty survey means nothing was compared. Rendering that as "0 drifted"
    would be a passing report produced by looking at nothing."""
    assert "NOT CHECKED" in tabledrift.render([])


# ── the shape we could not classify ──────────────────────────────────────────


def test_a_list_with_no_category_type_reports_shape_unknown(monkeypatch):
    """Defaulting to "it must be a log category" would flag every metric
    category as a missing row -- a first run that is all false positives."""
    _az(monkeypatch, stdout='[{"name": "AuditEvent"}, {"name": "Requests"}]')
    [finding] = tabledrift.survey({KV: [KV_ID]}, types=[KV])
    assert finding.ran is True and finding.shape_unknown is True
    assert finding.drifted is False


def test_shape_unknown_says_which_distinction_was_lost(monkeypatch):
    _az(monkeypatch, stdout='[{"name": "AuditEvent"}]')
    text = tabledrift.render(tabledrift.survey({KV: [KV_ID]}, types=[KV]))
    assert "categoryType" in text and "metrics" in text


@pytest.mark.parametrize("nested", [False, True])
def test_both_known_az_shapes_are_read(monkeypatch, nested):
    """az flattens ARM's `properties` bag on some commands and not others, and
    which one this is could not be established from the docs."""
    import json
    known = sorted(TABLE_MAP[KV])
    _az(monkeypatch, stdout=json.dumps([_cat(c, nested=nested) for c in known]))
    [finding] = tabledrift.survey({KV: [KV_ID]}, types=[KV])
    assert finding.ran and not finding.shape_unknown
    assert not finding.drifted, "the map's own categories must read as in sync"


def test_a_value_wrapped_payload_is_unwrapped(monkeypatch):
    _az(monkeypatch, stdout='{"value": [{"name": "AuditEvent", "categoryType": "Logs"}]}')
    entries, error = tabledrift.read_categories(KV_ID)
    assert error is None and entries and entries[0]["name"] == "AuditEvent"


def test_unparseable_output_is_an_error_not_an_empty_list(monkeypatch):
    """`[]` and "az printed something we cannot read" are different answers, and
    only the first one means the type offers no categories."""
    _az(monkeypatch, stdout="not json at all")
    entries, error = tabledrift.read_categories(KV_ID)
    assert entries is None and error and "parse" in error


# ── what counts as drift ─────────────────────────────────────────────────────


def test_metric_categories_are_not_reported_as_missing_rows():
    """TABLE_MAP makes no claim about metrics -- they do not land in a log
    table -- so a metric category is not a hole in it."""
    offered, unknown = tabledrift.log_categories(
        [_cat("AuditEvent"), _cat("Requests", kind="Metrics")])
    assert offered == {"AuditEvent"} and unknown is False


def test_a_category_azure_offers_that_the_map_lacks_is_the_blind_spot():
    unlisted, absent = tabledrift.compare(KV, set(TABLE_MAP[KV]) | {"NewAuditThing"})
    assert unlisted == ["NewAuditThing"]
    assert absent == []


def test_a_row_azure_no_longer_offers_is_reported_separately():
    """Dead weight, not a blind spot. Conflating them sends someone looking for
    a gap that closed."""
    keep = sorted(TABLE_MAP[KV])[:1]
    unlisted, absent = tabledrift.compare(KV, set(keep))
    assert unlisted == []
    assert absent == sorted(set(TABLE_MAP[KV]) - set(keep))


def test_the_report_says_why_an_unlisted_category_matters():
    finding = tabledrift.Drift(resource_type=KV, ran=True, unlisted=["NewThing"])
    text = tabledrift.render([finding])
    assert "DRIFT" in text and "NewThing" in text
    assert "invisible to every coverage verdict" in text


def test_an_unmapped_resource_type_reports_every_category_it_offers():
    """The four services the dataplane playbook covers that TABLE_MAP has no row
    for at all. `compare` must treat a missing type as an empty map rather than
    raising, so the first run names them."""
    unlisted, absent = tabledrift.compare(
        "microsoft.servicebus/namespaces", {"RuntimeAuditLogs", "OperationalLogs"})
    assert unlisted == ["OperationalLogs", "RuntimeAuditLogs"]
    assert absent == []


# ── which resources get probed ───────────────────────────────────────────────


def test_every_instance_of_a_type_is_probed():
    """This took ONE instance per type, on the premise that categories belong to
    the type. They do not. `microsoft.web/sites` covers Web Apps, Function Apps
    and Logic Apps, on Windows and Linux, each offering a different set -- and a
    tenant whose only site was a Linux Function App had seven real Windows
    categories reported as retired by Azure."""
    rows = [{"id": f"/x/{n}", "type": "Microsoft.KeyVault/vaults"} for n in range(3)]
    assert tabledrift.representatives(rows) == {KV: ["/x/0", "/x/1", "/x/2"]}


def test_the_probe_order_is_stable_between_runs():
    """Two reports that walked the resources differently cannot be diffed, and a
    drift job whose output churns for no reason is one nobody reads."""
    rows = [{"id": "/x/b", "type": KV}, {"id": "/x/a", "type": KV}]
    assert tabledrift.representatives(rows) == tabledrift.representatives(rows[::-1])
    assert tabledrift.representatives(rows)[KV] == ["/x/a", "/x/b"]


def test_a_mapped_type_with_no_instance_here_is_recorded_not_dropped(monkeypatch):
    """The honest limit of a tenant-grounded check: not running a Service Bus
    says nothing about whether Azure changed Service Bus. So it fails nothing
    and is not counted as checked.

    It is also not dropped. Four of the eleven map rows used to vanish here,
    and the verdict then read "7 match the map" as though it had checked all
    eleven."""
    _az(monkeypatch)
    out = tabledrift.survey({}, types=[KV])
    assert [f.resource_type for f in out] == [KV]
    assert out[0].no_instance is True
    assert out[0].drifted is False, "absence must not fail the run"
    verdict = _verdict(tabledrift.render(out))
    assert verdict["match the map"] == 0
    assert verdict["could not be checked"] == 0
    assert verdict["not run in this tenant, so not checked"] == 1


def test_rows_without_an_id_or_type_are_ignored():
    assert tabledrift.representatives(
        [{"id": "", "type": KV}, {"type": KV}, {"id": "/x/1"}]) == {}


# ── what leaves the machine ──────────────────────────────────────────────────


def test_the_serialised_finding_carries_no_resource_id():
    """This tool is meant to ship public, and a drift report is exactly the kind
    of low-stakes output nobody checks before pasting it into an issue. The
    probe's ARM path holds a subscription guid, a resource group and a resource
    name, and the finding does not need any of it -- categories belong to the
    TYPE."""
    finding = tabledrift.Drift(resource_type=KV, probe_id=KV_ID, ran=True)
    dumped = finding.public()
    assert "probe_id" not in dumped
    assert KV_ID not in str(dumped)
    assert dumped["resource_type"] == KV, "the subject of the finding survives"


def test_the_rendered_report_carries_no_resource_id():
    findings = [tabledrift.Drift(resource_type=KV, probe_id=KV_ID, ran=True,
                                 unlisted=["NewThing"]),
                tabledrift.Drift(resource_type=KV, probe_id=KV_ID, ran=False,
                                 error="AuthorizationFailed")]
    text = tabledrift.render(findings)
    assert KV_ID not in text and "/subscriptions/" not in text


# ── the exit codes the monthly job branches on ───────────────────────────────


def _run_cli(monkeypatch, rows, tmp_path, **stub):
    """`pylon tabledrift` end to end, with ARM stubbed at both reads."""
    import argparse

    from pylon import cli, inventory
    monkeypatch.setattr(inventory, "query_graph", lambda: rows)
    _az(monkeypatch, **stub)
    return cli._tabledrift(argparse.Namespace(json=None))


def test_a_map_that_holds_exits_zero(monkeypatch, tmp_path, capsys):
    import json
    _rows = [{"id": KV_ID, "type": KV}]
    code = _run_cli(monkeypatch, _rows, tmp_path,
                    stdout=json.dumps([_cat(c) for c in TABLE_MAP[KV]]))
    assert code == 0
    assert _verdict(capsys.readouterr().out)["drifted"] == 0


def test_drift_exits_one(monkeypatch, tmp_path, capsys):
    import json
    _rows = [{"id": KV_ID, "type": KV}]
    offered = [_cat(c) for c in TABLE_MAP[KV]] + [_cat("SomethingNew")]
    code = _run_cli(monkeypatch, _rows, tmp_path, stdout=json.dumps(offered))
    assert code == 1, "the monthly job fails the run on 1 and only on 1"
    assert "SomethingNew" in capsys.readouterr().out


def test_a_check_that_could_not_run_exits_two_not_one(monkeypatch, capsys):
    """The distinction the workflow branches on. A lapsed `az login` raising the
    same alarm as a real finding is how a monthly check gets muted, so
    "could not look" and "looked and found drift" must not share an exit code.
    """
    import argparse

    from pylon import cli, inventory

    def _dead():
        raise RuntimeError("could not run az")

    monkeypatch.setattr(inventory, "query_graph", _dead)
    assert cli._tabledrift(argparse.Namespace(json=None)) == 2
    assert "NOT CHECKED" in capsys.readouterr().err


def test_an_unreadable_type_alone_does_not_fail_the_run(monkeypatch, capsys):
    """Reported, not fatal. One resource type the runner cannot read is a note
    in the summary; it is not evidence that the map is wrong."""
    code = _run_cli(monkeypatch, [{"id": KV_ID, "type": KV}], None,
                    returncode=1, stderr="AuthorizationFailed")
    assert code == 0
    out = capsys.readouterr().out
    assert "NOT CHECKED" in out
    assert _verdict(out)["could not be checked"] == 1


def test_the_written_json_is_the_redacted_finding(monkeypatch, tmp_path):
    import argparse
    import json

    from pylon import cli, inventory
    monkeypatch.setattr(inventory, "query_graph", lambda: [{"id": KV_ID, "type": KV}])
    _az(monkeypatch, stdout=json.dumps([_cat(c) for c in TABLE_MAP[KV]]))
    out = tmp_path / "drift.json"
    cli._tabledrift(argparse.Namespace(json=str(out)))
    written = out.read_text(encoding="utf-8")
    assert "/subscriptions/" not in written, "the artifact is uploadable"
    assert KV in written


# ── the premise the first real tenant broke ──────────────────────────────────


def test_categories_are_unioned_across_instances(monkeypatch):
    """Two resources of one type can offer different sets. A Linux Function App
    and a Windows Web App are both `microsoft.web/sites`, and the Windows one
    offers `AppServiceHTTPLogs` while the Linux one does not."""
    import json
    seen = []

    def _by_resource(args, **kwargs):
        rid = args[args.index("--resource") + 1]
        seen.append(rid)
        offered = ["AuditEvent"] if rid.endswith("linux") else ["AuditEvent", "HTTPLogs"]
        return subprocess.CompletedProcess(
            ["az"], 0, json.dumps([_cat(c) for c in offered]), "")

    monkeypatch.setattr(azcli, "run", _by_resource)
    [finding] = tabledrift.survey({KV: ["/x/a-linux", "/x/b-windows"]}, types=[KV])
    assert len(seen) == 2, "every instance must be probed, not just the first"
    assert finding.instances == 2
    # HTTPLogs came from only one of them and must still count as offered.
    assert "HTTPLogs" in finding.unlisted


def test_a_category_no_instance_offers_is_not_a_finding(monkeypatch):
    """The correction. A real tenant's only site was a Linux Function App, so
    seven genuine Windows App Service categories came back absent and were
    reported as "not offered by Azure — renamed, retired, or misspelled".

    Azure had retired none of them. Even probing every instance, "nothing here
    offers it" is not "Azure removed it" -- you would have to own the variant
    that offers it to tell. So this is printed as context and fails nothing.
    """
    import json
    keep = sorted(TABLE_MAP[KV])[:1]
    _az(monkeypatch, stdout=json.dumps([_cat(c) for c in keep]))
    [finding] = tabledrift.survey({KV: [KV_ID]}, types=[KV])

    assert finding.not_offered_here, "the absence is still recorded"
    assert finding.unlisted == []
    assert finding.drifted is False, "absence must not fail the run"


def test_the_report_says_absence_proves_nothing(monkeypatch):
    finding = tabledrift.Drift(resource_type=KV, ran=True, instances=1,
                               not_offered_here=["AppServiceHTTPLogs"])
    text = tabledrift.render([finding])
    assert "context only" in text
    assert "neither is counted above" in text
    assert _verdict(text)["drifted"] == 0, "it must not be counted into the verdict"
    assert "AppServiceHTTPLogs" in text, "but it is still shown"


def test_a_blind_spot_still_fails_the_run(monkeypatch):
    """The direction that CAN be proven: Azure offering something the map has no
    row for is evidence of a gap, whichever instance offered it."""
    import json
    offered = sorted(TABLE_MAP[KV]) + ["SomethingNew"]
    _az(monkeypatch, stdout=json.dumps([_cat(c) for c in offered]))
    [finding] = tabledrift.survey({KV: [KV_ID]}, types=[KV])
    assert finding.unlisted == ["SomethingNew"]
    assert finding.drifted is True


def test_the_help_says_it_checks_pylon_not_the_tenant():
    """The one verb here that says nothing about the tenant. Its old help line,
    "check tablemap against the categories Azure offers", used an internal name
    and never said who it was for, so it read as a fifth thing to run in an
    engagement."""
    import re

    from pylon import cli
    # Whitespace normalised: argparse wraps the epilog to the terminal width,
    # so an assertion on an exact phrase breaks whenever an unrelated edit
    # moves the line break. This one failed because a verb was removed from the
    # sentence in front of it.
    top = re.sub(r"\s+", " ", cli.build_parser().format_help())
    assert "maintenance" in top
    assert "tablemap" not in top, "an internal name in user-facing help"
    assert "maintain Pylon itself" in top

    sub = [a for a in cli.build_parser()._subparsers._group_actions][0]
    detail = sub.choices["tabledrift"].format_help()
    assert "not an assessment of your tenant" in detail
    assert "never the table they land in" in detail, "the reason the map exists"


def test_storage_sub_services_are_actually_probed():
    """The bug this pair of fixes exists for.

    The map keys storage by sub-service, because that is where storage keeps
    its log categories. Resource Graph's `Resources` table returns TOP-LEVEL
    resources only, so it reports `.../storageaccounts` and never a
    sub-service. All four map rows matched nothing and were skipped as "no
    instance here" on every tenant that has ever run this -- storage being the
    commonest resource type there is, and five of the dark resources on the
    tenant that found it.
    """
    rows = [{"id": "/x/st1", "type": "microsoft.storage/storageaccounts"}]
    probes = tabledrift.representatives(rows)
    for service in ("blob", "file", "queue", "table"):
        key = f"microsoft.storage/storageaccounts/{service}services"
        assert key in TABLE_MAP, f"{key} is a map row"
        assert probes.get(key), f"{key} was never probed"
    assert probes["microsoft.storage/storageaccounts/blobservices"] == [
        "/x/st1/blobServices/default"]


def test_a_type_with_no_sub_services_is_probed_directly():
    rows = [{"id": "/x/kv1", "type": KV}]
    assert tabledrift.representatives(rows) == {KV: ["/x/kv1"]}


def test_the_expansion_comes_from_the_same_table_diagnostics_probes_with():
    """Two copies of "storage keeps its categories on child services" would
    drift apart, and the one that fell behind would go quiet rather than
    fail."""
    from pylon import diagnostics
    rows = [{"id": "/x/st1", "type": "microsoft.storage/storageaccounts"}]
    probed = set(tabledrift.representatives(rows))
    expected = {f"microsoft.storage/storageaccounts/{c.lower()}"
                for c in diagnostics.SUBSERVICES["microsoft.storage/storageaccounts"]}
    assert probed == expected
