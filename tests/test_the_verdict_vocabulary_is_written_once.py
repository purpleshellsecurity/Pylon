"""Every verdict has exactly one definition, and everything else reads it.

Two findings in the fourth round of clean-room testing were the same mistake
wearing different clothes: something defined in one place, and a copy of it
typed out by hand somewhere else. When the original changed, the copy did not.

    the tally     `verification` produces eight verdicts. The terminal summary
                  listed six as string literals. A run of two detections where
                  one summarised printed a tally of ONE -- that detection was in
                  the table above, absent from the count, absent from the
                  callouts (defects only), absent from the "not a pass" warning
                  (special-cased to no-ground-truth), and did not move the exit
                  code. A CI caller was told everything passed about a detection
                  whose correctness was never established.

    the measurer  `design verify` repeated `verification.measure` line for line.
                  `measure`'s own docstring says it "lives here rather than in
                  the CLI because generation needs it too" -- it was extracted
                  so there would be one, and the original was never deleted. The
                  copy then missed the one change that mattered.

The first is testable and this file tests it. The second is not, really: no
assertion distinguishes a legitimate second implementation from a forgotten
one, so it is guarded by having one call site and a comment saying why.
"""

import inspect
import re

import pytest

from pylon import cli, verification


def test_every_verdict_the_function_can_return_is_in_the_list():
    """Read out of the source rather than by calling it, because reaching every
    branch needs a workspace and the point is that the list cannot drift."""
    src = inspect.getsource(verification.verdict)
    returned = set(re.findall(r'return\s+"([a-z-]+)"', src))
    missing = returned - set(verification.VERDICTS)
    assert missing == set(), f"{verdict_msg(missing)}"


def verdict_msg(missing: set) -> str:
    return (f"`verdict()` can return {sorted(missing)} and VERDICTS does not "
            "list them. Anything iterating the vocabulary will skip them "
            "silently, which is how a detection vanished from a tally.")


def test_the_list_names_nothing_the_function_cannot_return():
    """The other direction. A verdict that stopped being produced should leave
    the list, or the list becomes a record of what used to be true."""
    src = inspect.getsource(verification.verdict)
    returned = set(re.findall(r'return\s+"([a-z-]+)"', src))
    stale = set(verification.VERDICTS) - returned
    assert stale == set(), f"listed and never returned: {sorted(stale)}"


def test_every_verdict_is_a_defect_or_unproven_or_a_match():
    """Three buckets and no fourth. A verdict in none of them is one nothing
    downstream knows how to treat."""
    accounted = set(verification.DEFECTS) | set(verification.UNPROVEN) | {
        "exact", "under"}
    assert set(verification.VERDICTS) <= accounted


def test_the_tally_iterates_the_vocabulary_rather_than_a_literal_list():
    """The fix. Six of eight were typed out here, so two could never print."""
    src = inspect.getsource(cli._show_verification)
    assert "verification.VERDICTS" in src, (
        "the tally lists verdicts by hand again; a ninth will be dropped "
        "silently the day it is added")


@pytest.mark.parametrize("call", verification.VERDICTS)
def test_the_tally_can_print_every_verdict(call, capsys):
    """Directly: one result per verdict, and each must appear in the output."""
    from pylon.models import DetectionVerification

    cli._show_verification([DetectionVerification(
        vector_name="v", operation="op", expected=1, observed=1,
        verdict=call, detail="d")])
    assert call in capsys.readouterr().out


def test_verify_measures_through_the_shared_implementation():
    """It repeated `measure` line for line, and the copy went stale in the one
    way that mattered: `narrowed` was never passed, so `no-match` was
    unreachable from the command whose whole purpose is measuring."""
    src = inspect.getsource(cli._design_verify)
    assert "verification.measure(" in src
    assert "verification.verdict(" not in src, (
        "verify computes a verdict itself again; that is the duplicate that "
        "drifted last time")


def test_a_narrowed_query_can_reach_no_match_from_verify():
    """The symptom, not the structure. A detection asking for a shape inside
    the operation must be able to come back `no-match` rather than `dead`."""
    narrowed = ('AzureActivity\n| where TimeGenerated > ago(1h)\n'
                '| where OperationNameValue =~ "X"\n'
                '| where tostring(props.logs) == "[]"')
    graded = verification.measure(narrowed, "AzureActivity", "X", "30d",
                                  lambda kql: 0 if "where" in kql else 110)
    assert graded.verdict in ("no-match", "no-ground-truth")


def test_the_same_query_without_narrowing_is_still_dead():
    plain = ('AzureActivity\n| where TimeGenerated > ago(1h)\n'
             '| where OperationNameValue =~ "X"')
    counts = iter([110, 0])
    graded = verification.measure(plain, "AzureActivity", "X", "30d",
                                  lambda _kql: next(counts))
    assert graded.verdict == "dead"
