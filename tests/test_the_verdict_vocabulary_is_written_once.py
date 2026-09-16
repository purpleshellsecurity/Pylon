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
    # Answers by CONTENT rather than by call order. `measure` used to make
    # exactly two calls and a two-element iterator encoded that; it now also
    # peels the filters when a query matched nothing, so a fixed-length
    # iterator made this test assert the call count rather than the verdict.
    def count(kql: str) -> int:
        return 110 if "| count" not in kql and kql.count("where") <= 1 else 0

    graded = verification.measure(plain, "AzureActivity", "X", "30d", count)
    assert graded.verdict == "dead"


def test_the_peel_does_not_count_the_count():
    """`count` is "run this and tell me how many rows", and every caller
    appends its own `| count`. The peel appended a second one, so each line
    counted the one-row output of the first and the whole table came back 1s --
    valid KQL, a clean run, and no information."""
    seen: list[str] = []

    def count(kql: str) -> int:
        seen.append(kql)
        return 0

    verification.peel(
        'AzureActivity\n| where TimeGenerated > ago(1h)\n'
        '| where OperationNameValue =~ "X"\n| where ResourceGroup has "prod"',
        count)
    assert seen, "the peel ran nothing"
    assert not any("| count" in q for q in seen), seen


def test_the_peel_names_the_filter_that_reached_zero():
    rows = [("T (no filters)", 900), ("where a", 32), ("where b", 28),
            ("where c", 0)]
    assert verification.killed_by(rows) == "where c"


def test_a_query_that_never_reaches_zero_names_nothing():
    """Guards the off-by-one shape: a peel whose first line is already zero has
    no filter to blame, and neither does one that keeps rows throughout."""
    assert verification.killed_by([("T", 0), ("where a", 0)]) == ""
    assert verification.killed_by([("T", 9), ("where a", 4)]) == ""


def test_a_joined_query_is_not_peeled():
    """The prefix of a join is not the join. Removing a filter on one leg
    changes what the other leg joins to, so the counts would describe a query
    nobody wrote."""
    joined = ('AzureActivity | where TimeGenerated > ago(1h)\n'
              '| where OperationNameValue =~ "X"\n'
              '| join kind=inner (AzureActivity | where Caller != "") on CorrelationId')
    assert verification.peel(joined, lambda _k: 0) == []


def test_the_baseline_carries_the_same_time_bound_as_every_row_below_it():
    """Round nine printed a ladder in which a filter INCREASED the row count:

        114  StorageBlobLogs (no filters)
        580  where TimeGenerated > ago(30d)

    The baseline was the only row with no time predicate, so it was counted over
    a different window and was never the denominator the rest were measured
    against. A time filter says which window is being measured; it is not one of
    the conditions under test.
    """
    from pylon import verification

    seen = []
    verification.peel(
        'StorageBlobLogs\n'
        '| where TimeGenerated > ago(30d)\n'
        '| where OperationName == "GetBlob"\n'
        '| where AuthenticationType == "OAuth"\n'
        '| where toint(StatusCode) < 300',
        lambda q: (seen.append(q), 1)[1])

    assert seen, "the peel ran nothing"
    assert all("TimeGenerated" in q for q in seen), (
        "every row of the ladder must be counted over the same window; "
        f"these were not: {[q for q in seen if 'TimeGenerated' not in q]}")


def test_the_time_filter_is_not_offered_as_a_step_that_killed_the_query():
    """It is the window, so it cannot be the filter under test -- and listing it
    as a step is what let it appear to add rows."""
    from pylon import verification

    rows = verification.peel(
        'StorageBlobLogs\n'
        '| where TimeGenerated > ago(30d)\n'
        '| where OperationName == "GetBlob"\n'
        '| where AuthenticationType == "OAuth"',
        lambda _q: 1)
    steps = [label for label, _n in rows[1:]]
    assert not any("TimeGenerated" in s for s in steps), steps
    assert rows[0][0].endswith("(time filter only)"), rows[0][0]
