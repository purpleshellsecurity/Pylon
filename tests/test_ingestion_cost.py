"""What a workspace is charged for, and at what rate.

Two separate questions, answered from two separate places, because getting
either from a price list would be guessing:

    IS it billed      the Usage meter's own IsBillable column. What a tenant
                      pays for depends on what it bought -- an E5 grant behind
                      a Defender XDR connection, a Defender for Servers data
                      allowance -- and no published rate card encodes that.

    at WHAT rate      the workspace sku. PerGB2018 is pay-as-you-go;
                      CapacityReservation is a daily commitment bought below
                      list. The rate itself is still not readable, which is
                      why it is overridable and why the report says "list".
"""

import json

import pytest

from pylon import tables, usage


class _Ran:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


# ── the meter ────────────────────────────────────────────────────────────────

def _probe(monkeypatch, usage_rows, plans=None):
    """Run `tables.probe` against a stubbed workspace with one table."""
    def _query(guid, kql):
        if kql.startswith("Usage"):
            return usage_rows, None
        return [{"T": "SecurityAlert", "rows": 5, "newest": "2026-09-01T00:00:00Z"}], None
    monkeypatch.setattr(tables, "_query", _query)
    monkeypatch.setattr(tables, "deployed",
                        lambda arm: (["SecurityAlert"], plans or {}, None))
    rows, _names, _read = tables.probe("guid", "/arm/id")
    return {r["table_name"]: r for r in rows}


def test_the_free_share_and_the_billed_share_are_summed_apart(monkeypatch):
    """A DataType can appear under both values in one window. Summing them into
    one number, or letting one row overwrite the other, loses exactly the
    distinction this read exists to make."""
    row = _probe(monkeypatch, [
        {"DataType": "SecurityAlert", "mb": 10.0, "IsBillable": "false"},
        {"DataType": "SecurityAlert", "mb": 5.0, "IsBillable": "true"},
    ])["SecurityAlert"]
    assert row["megabytes"] == 15.0
    assert row["billable_megabytes"] == 5.0
    assert row["billable"] is True


def test_a_wholly_free_table_is_priced_at_zero_not_left_unknown(monkeypatch):
    """`0.0` is a real answer -- Microsoft charges nothing for this source --
    and it is not the same claim as "the meter did not price it"."""
    row = _probe(monkeypatch, [
        {"DataType": "SecurityAlert", "mb": 15.7, "IsBillable": "false"},
    ])["SecurityAlert"]
    assert row["billable_megabytes"] == 0.0
    assert row["billable"] is False


def test_a_table_the_meter_never_mentions_is_unknown_not_free(monkeypatch):
    """An absent table has no volume figure at all. Reading that as free would
    put a table the meter never saw in the same bucket as SecurityAlert."""
    row = _probe(monkeypatch, [])["SecurityAlert"]
    assert row["megabytes"] is None
    assert row["billable_megabytes"] is None
    assert row["billable"] is None


@pytest.mark.parametrize("flag", [True, "True", "true"])
def test_the_billable_flag_is_read_in_both_shapes_it_arrives_in(monkeypatch, flag):
    """az renders the bool as a string and the SDK returns a real one. Reading
    one as the other prices every table in the workspace as free."""
    row = _probe(monkeypatch, [
        {"DataType": "SecurityAlert", "mb": 8.0, "IsBillable": flag},
    ])["SecurityAlert"]
    assert row["billable_megabytes"] == 8.0


def test_a_table_billed_for_kilobytes_still_reads_as_billed(monkeypatch):
    """Rounded to two places this is 0.0 MB. The boolean is what stops the
    report printing "free" over a table that is charged for."""
    row = _probe(monkeypatch, [
        {"DataType": "SecurityAlert", "mb": 0.001, "IsBillable": "true"},
    ])["SecurityAlert"]
    assert row["billable_megabytes"] == 0.0
    assert row["billable"] is True


def test_an_unreadable_meter_row_does_not_take_the_others_with_it(monkeypatch):
    row = _probe(monkeypatch, [
        {"DataType": "SecurityAlert", "mb": "not a number", "IsBillable": "true"},
    ])["SecurityAlert"]
    assert row["megabytes"] is None


# ── the plan ─────────────────────────────────────────────────────────────────

def test_a_pay_as_you_go_workspace_reports_its_sku(monkeypatch):
    monkeypatch.setattr(tables.azcli, "run", lambda *a, **k: _Ran(
        0, json.dumps({"properties": {"sku": {"name": "PerGB2018"},
                                      "retentionInDays": 30}})))
    plan, err = tables.plan("/arm/id")
    assert err is None
    assert plan == {"sku": "PerGB2018", "commitment_gb_per_day": None,
                    "retention_days": 30}


def test_a_commitment_tier_reports_the_level_it_committed_to(monkeypatch):
    """The level is the whole point: a 100 GB/day commitment is bought below
    list, so a report pricing that tenant at list overstates the bill."""
    monkeypatch.setattr(tables.azcli, "run", lambda *a, **k: _Ran(
        0, json.dumps({"properties": {
            "sku": {"name": "CapacityReservation",
                    "capacityReservationLevel": 100},
            "retentionInDays": 90}})))
    plan, _ = tables.plan("/arm/id")
    assert plan["sku"] == "CapacityReservation"
    assert plan["commitment_gb_per_day"] == 100


def test_a_plan_that_could_not_be_read_is_empty_not_guessed(monkeypatch):
    """Naming the wrong plan is worse than naming none: the reader cannot tell
    that the figure does not apply to them."""
    monkeypatch.setattr(tables.azcli, "run",
                        lambda *a, **k: _Ran(1, stderr="Forbidden"))
    plan, err = tables.plan("/arm/id")
    assert plan == {} and "Forbidden" in err


def test_an_unparseable_workspace_is_an_error_not_a_crash(monkeypatch):
    monkeypatch.setattr(tables.azcli, "run", lambda *a, **k: _Ran(0, "{not json"))
    plan, err = tables.plan("/arm/id")
    assert plan == {} and "could not parse" in err


# ── the rate ─────────────────────────────────────────────────────────────────

def test_the_default_rate_is_list_price(monkeypatch):
    monkeypatch.delenv("PYLON_PRICE_GB", raising=False)
    assert usage.ingest_price() == usage.INGEST_PRICE_GB


def test_the_rate_is_overridable_because_nobody_pays_list(monkeypatch):
    """A commitment tier, an enterprise agreement and a region all move it, and
    none of the three is readable from the workspace."""
    monkeypatch.setenv("PYLON_PRICE_GB", "2.75")
    assert usage.ingest_price() == 2.75
    assert usage.ingest_cost(1024) == 2.75


def test_an_unreadable_rate_falls_back_rather_than_raising(monkeypatch):
    monkeypatch.setenv("PYLON_PRICE_GB", "four dollars")
    assert usage.ingest_price() == usage.INGEST_PRICE_GB


def test_cost_is_computed_per_gigabyte_not_per_megabyte(monkeypatch):
    monkeypatch.setenv("PYLON_PRICE_GB", "4.00")
    assert usage.ingest_cost(512) == 2.0
