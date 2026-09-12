"""The "Activity Log only" declarations.

These decide what the estate scan reports as NOT a gap, so a wrong one hides a
real blind spot — the worst failure this tool has. They were originally written
from memory with a `basis:` line that read as though it had been checked; one of
sixteen actually had been. `scripts/verify-no-detection-surface.py` is what made
the rest true (and caught microsoft.web/serverfarms, recorded as having no logs
when it has two).

These tests are the offline half: structure and honesty. The network half lives
in that script, because a unit test that reaches learn.microsoft.com would fail
on a plane.
"""

import pytest

from pylon.catalog.no_detection_surface import NONE, OPERATIONAL_ONLY, declared, lookup


def test_every_declaration_has_a_reason_the_loader_understands():
    for rt, d in declared().items():
        assert d.reason in (NONE, OPERATIONAL_ONLY), rt


def test_operational_only_must_name_what_it_sets_aside():
    """This reason is a JUDGEMENT — that these categories describe availability
    rather than identity — not a fact about Azure. Making it without listing the
    categories asks a reader to take the call on trust, and there would be no way
    to disagree with it."""
    for rt, d in declared().items():
        if d.reason == OPERATIONAL_ONLY:
            assert d.logs, f"{rt} sets aside nothing it will name"


def test_none_never_lists_logs():
    # "No resource logs exist" and "here are the logs" cannot both be true.
    for rt, d in declared().items():
        if d.reason == NONE:
            assert not d.logs, rt


def test_every_declaration_says_what_to_detect_on_instead():
    """A report that says only "nothing to enable here" leaves a reader with
    nothing to do. Every one of these resources IS detectable — through the
    Activity Log — so each declaration carries the operation."""
    for rt, d in declared().items():
        assert d.activity_operation, f"{rt} names no control-plane operation"


def test_every_named_operation_is_one_ARM_actually_has():
    """The operation is the actionable half of the finding: paste it into a
    query and it either matches rows or it does not. An invented one produces a
    detection that can never fire, which is worse than saying nothing.

    Checked against the vendored provider-operations catalog rather than by
    eye — the whole reason this file exists is that I wrote sixteen claims from
    memory and one was wrong."""
    from pylon.provider_operations import is_known

    for rt, d in declared().items():
        assert is_known(d.activity_operation), f"{rt}: {d.activity_operation} is not a real operation"


def test_the_operation_belongs_to_the_type_it_is_declared_on():
    # A real operation for the WRONG resource would pass is_known and still send
    # a reader to query something unrelated.
    for rt, d in declared().items():
        assert d.activity_operation.lower().startswith(rt.lower() + "/"), rt


def test_every_declaration_explains_itself():
    for rt, d in declared().items():
        assert len(d.basis) > 40, f"{rt} has no real basis"


def test_no_label_claims_the_resource_is_undetectable():
    """The correction that prompted all of this. Both states mean "no
    resource-specific surface to switch on" — never "you cannot detect this".
    A public IP being stood up is a real finding via AzureActivity."""
    for d in declared().values():
        assert "Activity Log only" in d.label()
        assert "no telemetry exists" not in d.label().lower()


def test_lookup_is_case_insensitive():
    # Resource Graph returns lowercase; the catalog is authored mixed-case.
    assert lookup("Microsoft.Compute/disks") is not None
    assert lookup("microsoft.compute/disks") is not None


def test_an_undeclared_type_returns_nothing_rather_than_a_guess():
    # Silence has to stay "not in the catalog", not become a claim nobody made.
    assert lookup("microsoft.madeup/things") is None
    assert lookup("") is None


@pytest.mark.parametrize("resource_type,reason", [
    # The two verified against the docs by hand, kept as the worked examples.
    ("microsoft.network/publicipaddresses", OPERATIONAL_ONLY),  # 3 DDoS categories
    ("microsoft.web/serverfarms", OPERATIONAL_ONLY),            # console + platform logs
    ("microsoft.compute/disks", NONE),                          # page 404s
])
def test_the_worked_examples_keep_their_classification(resource_type, reason):
    assert lookup(resource_type).reason == reason


def test_public_ip_sets_aside_the_ddos_categories():
    logs = lookup("microsoft.network/publicipaddresses").logs
    assert set(logs) == {
        "DDoSProtectionNotifications", "DDoSMitigationFlowLogs", "DDoSMitigationReports"
    }


def test_serverfarms_records_that_it_was_corrected():
    # It was wrong, the verifier caught it, and the entry says so — the file is
    # the record of what has actually been checked.
    d = lookup("microsoft.web/serverfarms")
    assert set(d.logs) == {"AppServiceConsoleLogs", "AppServicePlatformLogs"}
    assert "First recorded as having no resource logs" in d.basis
    # ...and that correction stays in the FILE, not in the report. The summary is
    # what a reader of a coverage report sees, and it is a reason, not a history.
    assert "First recorded" not in d.short


# --- report length vs file length ---------------------------------------------
#
# `basis` is for a reader of THIS FILE and may argue with itself. It was being
# rendered verbatim into the coverage report, where one entry opened by
# narrating a mistake its author had made. `summary` is what a report shows.


def test_no_declaration_puts_a_paragraph_on_a_report_line():
    for rt, d in declared().items():
        assert len(d.short) <= 160, f"{rt}: {len(d.short)} chars on one line"


def test_the_short_form_never_narrates_the_authoring():
    # A coverage report wants the reason, not the reasoning.
    for rt, d in declared().items():
        low = d.short.lower()
        for tell in (" i ", "i first", "this file", "borderline case", "cannot be claimed"):
            assert tell not in f" {low} ", f"{rt} narrates itself in the report line"


def test_a_declaration_with_no_summary_falls_back_to_its_basis():
    # Most entries are already one clause; only the long ones need a summary.
    for rt, d in declared().items():
        assert d.short, rt
        if not d.summary:
            assert d.short == d.basis, rt
