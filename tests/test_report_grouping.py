"""The census behind the "Diagnostic settings" table.

`report.py` had no tests at all. It renders HTML, which is awkward to assert
on, but the part that can be wrong in a way a reader would act on is the
counting -- and counting is testable. These hold the two distinctions the
section is built around: a resource with nothing to switch on is not a gap,
and a resource nobody could check is not a clean one.
"""

from pylon.report import group_by_type

RG = "/subscriptions/S/resourceGroups/RG/providers"


def row(name, rtype, status, assessment="assessed"):
    return {"resource_id": f"{RG}/{rtype}/{name}",
            "resource_type": rtype,
            "logging_status": status,
            "assessment_status": assessment}


def test_out_of_scope_rows_are_not_counted():
    """A resource with nothing to switch on must not swell the denominator.

    Counting it turns "1 of 1 not logging" into "1 of 2", which reads as
    half-done work on something that has no work to do.
    """
    rows = [row("a", "microsoft.storage/storageaccounts", "not-enabled"),
            row("b", "microsoft.storage/storageaccounts", None, "out_of_scope")]
    out = group_by_type(rows)
    assert out["microsoft.storage/storageaccounts"]["total"] == 1
    assert out["microsoft.storage/storageaccounts"]["off"] == 1


def test_not_assessed_is_counted_but_kept_separate():
    """"Could not check" is not "clean" and is not "off" either."""
    rows = [row("a", "microsoft.keyvault/vaults", "fully-enabled"),
            row("b", "microsoft.keyvault/vaults", None, "not_assessed")]
    out = group_by_type(rows)["microsoft.keyvault/vaults"]
    assert out["total"] == 2
    assert out["on"] == 1
    assert out["unknown"] == 1
    assert out["off"] == 0 and out["partial"] == 0


def test_partial_counts_as_a_gap_and_is_named():
    """Partly-enabled is a gap. It is what makes this section's number larger
    than the `dark_resources` figure in the Coverage block above it."""
    rows = [row("kv1", "microsoft.keyvault/vaults", "partial-enabled")]
    out = group_by_type(rows)["microsoft.keyvault/vaults"]
    assert out["partial"] == 1
    assert out["names"] == ["kv1"]


def test_only_gaps_are_named():
    """The names exist so a row is somewhere to start. A healthy resource is
    not somewhere to start, so listing it buries the ones that are."""
    rows = [row("good", "microsoft.web/sites", "fully-enabled"),
            row("bad", "microsoft.web/sites", "not-enabled"),
            row("dunno", "microsoft.web/sites", None, "not_assessed")]
    out = group_by_type(rows)["microsoft.web/sites"]
    assert out["names"] == ["bad"]


def test_types_are_kept_apart():
    rows = [row("a", "microsoft.storage/storageaccounts", "not-enabled"),
            row("b", "microsoft.keyvault/vaults", "fully-enabled")]
    out = group_by_type(rows)
    assert set(out) == {"microsoft.storage/storageaccounts",
                        "microsoft.keyvault/vaults"}
    assert out["microsoft.keyvault/vaults"]["off"] == 0


def test_a_type_with_nothing_loggable_disappears_entirely():
    """Not a zero row -- absent. A row of zeroes invites the reader to wonder
    what it is telling them, and the answer is nothing."""
    rows = [row("a", "microsoft.foo/bars", None, "out_of_scope")]
    assert group_by_type(rows) == {}


def test_no_rows_is_an_empty_census_not_a_crash():
    assert group_by_type([]) == {}
