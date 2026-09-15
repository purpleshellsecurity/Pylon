"""Four things a clean-room test of the release found, in its first hour.

Someone cloned the public repo, installed it fresh and ran the documented flow
against a real tenant. Everything below is what that produced. Three of the four
were introduced the day before by work meant to make the tool more honest.
"""


import pytest

from pylon import report_design
from pylon.catalog.table_techniques import second_opinion
from pylon.scoring import normalize_technique_id, technique_weight


# ── 1. the tool contradicted itself about ATT&CK ─────────────────────────────
# Generation was taught to relabel a revoked technique id onto its replacement.
# The vendored catalogues still spoke the old one -- `table-techniques.yaml`
# carries T1562.008 twelve times and T1685.002 not once. So a run relabelled a
# technique, flagged its own relabel as disagreeing with the catalogue, and
# reported 0 of 101 techniques covered because the two sides could not match.

@pytest.mark.parametrize("revoked,current", [
    ("T1562", "T1685"),
    ("T1562.007", "T1686.001"),
    ("T1562.008", "T1685.002"),
])
def test_a_revoked_id_normalises_onto_its_replacement(revoked, current):
    assert normalize_technique_id(revoked) == current


def test_the_embellished_form_still_normalises():
    """The original job of this function: a model returns the id wrapped in
    prose."""
    assert normalize_technique_id(
        "T1003.001 - OS Credential Dumping: LSASS Memory (Enterprise)") == "T1003.001"


def test_a_current_id_is_left_alone():
    assert normalize_technique_id("T1098.003") == "T1098.003"


def test_the_catalogue_no_longer_disagrees_with_a_relabel():
    """The exact line the clean-room run saw on the page: "Pylon maps
    Microsoft.Insights/DiagnosticSettings/Delete to T1562.008. This run chose
    T1685.002." Both are the same technique."""
    assert second_opinion("AzureActivity",
                          "Microsoft.Insights/DiagnosticSettings/Delete",
                          "T1685.002") == ()


def test_a_real_disagreement_is_still_reported():
    """The check has to keep working. Silencing it would be a worse fix than
    the bug."""
    assert second_opinion("AzureActivity",
                          "Microsoft.Insights/DiagnosticSettings/Delete",
                          "T1078.004") != ()


def test_a_weight_written_for_the_revoked_spelling_is_still_found():
    """Weights are keyed by the current id and looked up through the
    normaliser, so neither spelling can miss."""
    assert technique_weight("T1562.008") == technique_weight("T1685.002") == 10


# ── 2. the page called an under-match a pass ─────────────────────────────────

def _page(tmp_path, verdict, detail):
    report = {
        "service": "x", "platform": "resource", "generation_yield": 1,
        "critical_gaps": [],
        "analysis": {"service": "x", "platform": "resource",
                     "executive_summary": "s", "attack_vectors": [
                         {"name": "v", "priority": "high",
                          "mitre_technique": "T1685.002", "operation": "op",
                          "log_table": "AzureActivity", "alert_condition": "c",
                          "rationale": "r r."}]},
        "detections": [{
            "detection": {"vector_name": "v", "mitre_technique": "T1685.002",
                          "kql": "AzureActivity | take 1", "tuning_guidance": "-",
                          "false_positive_notes": "-"},
            "log_table": "AzureActivity", "valid": True, "errors": [],
            "warnings": [], "retried": False, "operation": "op",
            "table_basis": "deployed",
            "verification": {"vector_name": "v", "operation": "op",
                             "expected": 110, "observed": 22, "verdict": verdict,
                             "detail": detail, "widened": True}}]}
    report_design.write(report, tmp_path)
    return (tmp_path / "detections.html").read_text(encoding="utf-8")


def test_an_under_match_is_not_described_as_matching_real_events(tmp_path):
    """"2 detections matched real events" sat above two detections at x0.25 and
    x0.10 of expected. Technically true, read as a pass."""
    page = _page(tmp_path, "under", "22 rows for 110 events (x0.20)")
    assert "matched real events" not in page
    assert "matched fewer rows than its operation produced" in page


def test_an_exact_match_says_so_plainly(tmp_path):
    page = _page(tmp_path, "exact", "110 rows for 110 events")
    assert "matched every event of its operation" in page


def test_the_verdict_chip_says_it_is_a_measurement(tmp_path):
    """A reviewer looking directly at this page for a verdict reported there
    was none. The plain-English wording alone did not read as one."""
    page = _page(tmp_path, "under", "22 rows for 110 events (x0.20)")
    assert "measured:" in page


# ── 3. a paid run wrote nothing ──────────────────────────────────────────────

def test_detections_never_discards_a_run_for_want_of_a_flag():
    """`--out` was optional here and required on `design plan`, and the "next"
    line plan printed omitted it -- so following the tool's own suggestion
    charged for detections and wrote nothing but a log."""
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_detections)
    assert "if args.out:" not in src, "output is still gated behind the flag"
    assert "args.out or args.source" in src


def test_the_next_hint_names_an_output_directory():
    import inspect

    from pylon import cli

    for fn in (cli._design_plan, cli._design_list):
        src = inspect.getsource(fn)
        for line in src.splitlines():
            if "next   pylon design detections" in line:
                # the hint is built across two lines; the --out is on the second
                assert "--out" in src, f"{fn.__name__} suggests a run with no --out"


# ── 4. record built a fixture the detection could not fire on ────────────────

def test_rows_are_spread_across_the_outcome_column():
    """It took three Start rows and two Failure rows for a query filtering
    `ActivityStatusValue =~ "Success"`, so the detection could not fire on a
    single true positive -- and `grade` blamed a threshold. There were eleven
    matching Success rows in the same window."""
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_record)
    assert "partition by" in src, "a bare `take N` returns whatever comes first"
    assert "ActivityStatusValue" in src


def test_the_outcome_column_is_named_per_table_not_guessed():
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_record)
    for table, column in (("AzureActivity", "ActivityStatusValue"),
                          ("AuditLogs", "Result"),
                          ("AZKVAuditLogs", "ResultType")):
        assert table in src and column in src


# ── 5 and 6. two cosmetic ones that still misled a reader ────────────────────

def _listed(capsys) -> list[str]:
    """The rows `design list` prints, from THIS source.

    Shelling out to `pylon` was the first version, and it read whichever build
    happened to be on PATH -- which during this work was a different checkout
    entirely. A test that depends on PATH is testing the machine.
    """
    import argparse

    from pylon import cli

    cli._design_list(argparse.Namespace(target=[], source=None))
    return [line for line in capsys.readouterr().out.splitlines() if line.strip()]


def test_the_whole_directory_target_heads_its_own_block(capsys):
    """`Entra` is the whole directory and the eleven `Entra Something` rows are
    slices of it. Sorted plainly it lands LAST, where it reads as a stray line
    with nothing beside it -- a clean-room reader called it a formatting
    artifact and then could not reconcile 24 visible rows against the 25 that
    `design coverage` counts."""
    rows = _listed(capsys)
    entra = [i for i, line in enumerate(rows) if line.startswith("Entra")]
    assert rows[entra[0]] == "Entra", f"first Entra row is {rows[entra[0]]!r}"
    assert len(rows) == 25


def test_every_listed_line_is_still_a_bare_value(capsys):
    """What makes it pipeable. A tables column and a footer were removed once
    for answering a question nobody asks at a menu; the fix for the ordering
    must not put either back."""
    for line in _listed(capsys):
        assert line == line.strip(), f"indented: {line!r}"
        assert "  " not in line, f"looks like a column: {line!r}"


def test_grade_drops_the_prefix_every_fixture_shares():
    """Fixture names all begin with the target they came from, so truncating
    from the left made two rows read identically -- you could not tell which
    one had failed."""
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_grade)
    assert "commonprefix" in src
    assert "labels[name]" in src, "the table still prints the untrimmed name"


# ── 7. the rationale under "why this technique" was about another service ────
# A technique id is NOT unique within a table. `T1685.002` on AzureActivity
# carries three separate claims -- diagnostic settings, Key Vault, SQL auditing
# -- so a lookup keyed by technique alone keeps whichever came last. Twelve ids
# on that table collide the same way.
#
# Curated prose under a specific heading gives a reader no reason to doubt it,
# which makes a confidently wrong section worse than a missing one.

from pylon.catalog.table_techniques import basis_for, candidates


def test_each_operation_gets_its_own_argument():
    write = basis_for("AzureActivity",
                      "Microsoft.Insights/DiagnosticSettings/Write", "T1685.002")
    vault = basis_for("AzureActivity",
                      "Microsoft.KeyVault/vaults/providers/Microsoft.Insights"
                      "/diagnosticSettings/write", "T1685.002")
    sql = basis_for("AzureActivity",
                    "Microsoft.Sql/servers/auditingSettings/write", "T1685.002")
    assert write != vault != sql
    assert "cloud logging" in write
    assert "vault" in vault.lower()
    assert "SQL auditing" in sql


def test_a_diagnostic_settings_detection_is_not_given_the_sql_argument():
    """The exact text a reader saw under "why this technique" on a query that
    touches no SQL operation and does not read SQLSecurityAuditEvents."""
    write = basis_for("AzureActivity",
                      "Microsoft.Insights/DiagnosticSettings/Write", "T1685.002")
    assert "SQLSecurityAuditEvents" not in write
    assert "Ledger" not in write


def test_the_revoked_spelling_finds_the_same_argument():
    """The lookup normalises both sides, so a catalogue written in the old
    spelling and a run relabelled onto the new one still meet."""
    assert basis_for("AzureActivity",
                     "Microsoft.Insights/DiagnosticSettings/Write",
                     "T1562.008") == basis_for(
        "AzureActivity", "Microsoft.Insights/DiagnosticSettings/Write",
        "T1685.002")


def test_an_operation_with_no_claim_returns_nothing_rather_than_someone_elses():
    assert basis_for("AzureActivity", "Microsoft.Nonsense/things/write",
                     "T1685.002") == ""


def test_the_collision_this_guards_against_is_real():
    """If the catalogue ever stops colliding, this whole mechanism is dead
    weight and the test should say so rather than passing quietly."""
    import collections

    seen = collections.Counter(c.technique for c in candidates("AzureActivity")
                               if c.basis)
    assert [t for t, n in seen.items() if n > 1], (
        "no technique id collides any more; basis_for may be unnecessary")


# ── 8. two hints and a missing cost line ─────────────────────────────────────

def test_the_engine_hint_matches_the_machine_it_prints_on():
    """The README carried the Apple silicon invocation and this message did
    not, so the one place a reader sees it at the moment they need it handed
    them the command that exits 133 under Rosetta."""
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_grade)
    assert "platform.machine()" in src
    assert "--platform linux/amd64" in src


def test_a_plan_reports_what_it_cost():
    """It is a paid call and printed no cost at all, while `detections` printed
    one -- so the cheap half of the flow was the half that looked free."""
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._print_report)
    head = src[:src.index("COST")]
    assert "estimated_cost_usd" in head, "the plan branch returns before any cost"


# ── 9. "dead" asserted a fault the evidence did not establish ────────────────
# A detection for "a diagnostic settings write that disables ALL categories"
# matched none of 110 DiagnosticSettings/Write events -- because none of those
# 110 disabled all categories. The lab had never performed that action.
#
# The tool converted "the attack did not happen here" into a judgement about the
# query: verdict `dead`, `valid: false`, printed BAD, counted as a generation
# failure, and told in its own .kql header that "the fault is in what it
# MATCHES". None of that was established. The operation count is the wrong
# denominator for a behaviour-scoped query -- a limit this codebase had already
# named for `under` and then built a gate on top of anyway.

from pylon.verification import DEFECTS, UNPROVEN, narrows, verdict

OPERATION_ONLY = ('AzureActivity\n| where TimeGenerated > ago(1h)\n'
                  '| where OperationNameValue =~ "X"\n'
                  '| where ActivityStatusValue =~ "Success"')
NARROWED = OPERATION_ONLY + '\n| where tostring(props.logs) == "[]"'


def test_a_query_filtering_only_the_operation_does_not_narrow():
    """The frame every detection shares: operation, time, outcome."""
    assert narrows(OPERATION_ONLY) is False


def test_a_query_asking_for_more_than_the_operation_narrows():
    assert narrows(NARROWED) is True


def test_a_let_bound_constant_counts_as_narrowing():
    """`let OwnerRoleGuid = "..."` narrows without a where-clause doing it."""
    assert narrows('let OwnerRoleGuid = "8e3af657";\n'
                   'AzureActivity | where OperationNameValue =~ "X"') is True


def test_a_comment_is_not_a_filter():
    assert narrows(OPERATION_ONLY + '\n// | where props.logs == "[]"') is False


def test_matching_none_while_filtering_only_the_operation_is_still_dead():
    """The case this can be sure about: the events are right there and the
    query matched none of them."""
    call, detail = verdict(110, 0, narrowed=False)
    assert call == "dead"
    assert "nothing beyond the operation itself" in detail


def test_matching_none_while_narrowing_is_not_called_a_defect():
    call, detail = verdict(110, 0, narrowed=True)
    assert call == "no-match"
    assert call not in DEFECTS, "a behaviour that did not happen is not a fault"
    assert call in UNPROVEN


def test_the_no_match_wording_offers_both_readings():
    """Saying either one alone would be a claim the evidence does not carry."""
    _call, detail = verdict(110, 0, narrowed=True)
    assert "did not happen here" in detail
    assert "filter that is wrong" in detail
    assert "cannot tell them apart" in detail


# ── 10. a verdict was computed, written to disk, and not carried forward ─────

def test_a_fixture_carries_what_a_live_run_already_measured():
    """`grade` met a detection an earlier stage had measured as matching
    nothing and offered a benign explanation for it -- the same shape as the
    fixture bug fixed a round earlier, one stage later."""
    from pylon.record import fixture

    fx = fixture("n", "AzureActivity", "q", "op", [{"A": "1"}], [{"A": "2"}],
                 measured={"verdict": "dead", "detail": "matched none"})
    assert fx["measured"]["verdict"] == "dead"


def test_an_unmeasured_fixture_says_none_rather_than_clean():
    from pylon.record import fixture

    fx = fixture("n", "AzureActivity", "q", "op", [{"A": "1"}], [])
    assert fx["measured"] is None


def test_grade_says_when_it_is_reproducing_a_known_result():
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_grade)
    assert "reproducing a known result" in src


# ── 11. the yield read 100% on a run where half the detections failed ────────

def test_the_yield_is_not_a_percentage_of_vectors():
    """It is computed over distinct, weight-scored TECHNIQUE ids. Two vectors
    sharing a technique with one valid detection scores 100, and two vectors on
    different techniques with one valid scores 67 rather than 50."""
    from pylon.scoring import score_program

    same = score_program(threats_in_scope=["T1685.002", "T1685.002"],
                         threats_covered=["T1685.002"]).generation_yield
    diff = score_program(threats_in_scope=["T1685.002", "T1490"],
                         threats_covered=["T1685.002"]).generation_yield
    assert same == 100 and diff not in (50, same)


def test_the_printed_line_counts_rather_than_scores():
    """It printed "100% of the 2 enumerated vectors produced a valid detection"
    four lines under the word BAD."""
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._print_report)
    assert "produced a valid detection" in src
    assert "{result.generation_yield:.0f}% of the" not in src


def test_the_weighted_number_is_kept_and_labelled():
    """Missing a weight-10 technique is not the same as missing a weight-3, so
    the score is worth having -- wearing its own name."""
    import inspect

    from pylon import cli

    assert "by technique weight" in inspect.getsource(cli._print_report)


# ── 12. the .kql kept a verdict the page had already corrected ───────────────
# `design verify` rewrites report.json and the page. It did not rewrite the
# .kql files, which carry a `// MEASURED:` header written at generation. So on a
# directory whose verdict changed from `dead` to `no-match`, the page said the
# query could not be judged and the file someone pastes into Sentinel still said
# "the fault is in what it MATCHES" -- precisely the claim that release removed,
# surviving in the one artifact that leaves the tool.

def test_verify_rewrites_the_file_that_leaves_the_tool():
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_verify)
    assert "_kql_header" in src, (
        "verify updates the page and the report and leaves the .kql behind, so "
        "the artifact a responder actually uses keeps a superseded verdict")


# ── 13. a fixture whose halves belonged to different events ──────────────────
# `partition by <outcome> (take K)` samples each outcome INDEPENDENTLY, so the
# Start rows and Success rows came from different operations. A detection that
# joins Start to Success on CorrelationId -- how every ARM detection reads the
# role or the request body, because only Start carries it -- could never produce
# a row. Measured: the Start row satisfied the predicate, the Success row
# existed, and the two CorrelationId sets did not intersect at all.

def test_a_joining_detection_records_whole_events():
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_record)
    assert "Halves" in src and "dcount" in src, (
        "tp rows are still sampled per outcome, so a join-based detection gets "
        "a Start and a Success from different operations")
    assert '"join" in d.detection.kql.lower()' in src, (
        "correlation should be asked for only when the query actually joins")


def test_it_falls_back_rather_than_recording_nothing():
    """No correlated pair in the window is not a reason to write an empty
    fixture: unrelated rows still grade a detection that does not correlate."""
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_record)
    assert "Fall through to the stratified" in src


# ── 14. a deleted file shipped anyway ────────────────────────────────────────

def test_the_release_script_warns_that_rsync_does_not_delete():
    """A test deliberately deleted from this repo survived in the public one,
    because `rsync` copies and does not delete. It then failed on a clean
    clone, so the first thing a new user did -- the README's pytest step --
    was watch the suite go red."""
    import pathlib

    script = (pathlib.Path(__file__).resolve().parents[1]
              / "scripts" / "make-release.sh")
    if not script.is_file():
        import pytest
        pytest.skip("make-release.sh is not shipped in a release tree")
    text = script.read_text(encoding="utf-8")
    assert "--delete" in text
    assert "rsync copies, it does not delete" in text


def test_the_release_ships_the_licence():
    """The release is built from an EXPLICIT file list, and LICENSE was not on
    it -- the list predates the file.

    So the one thing that stops anyone legally using Pylon was fixed in this
    repo and dropped on the way out, and nothing failed: `pyproject.toml`
    declares `license-files = ["LICENSE"]`, a glob matching nothing is not an
    error, so the wheel built clean and simply carried no licence.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    script = root / "scripts" / "make-release.sh"
    if not script.is_file():
        import pytest
        pytest.skip("make-release.sh is not shipped in a release tree")

    archived = script.read_text(encoding="utf-8")
    line = archived[archived.index("git archive HEAD"):]
    line = line[:line.index("| tar")]
    for required in ("LICENSE", "SECURITY.md", "CHANGELOG.md"):
        assert required in line, (
            f"make-release.sh does not archive {required}, so the public repo "
            f"ships without it")

    licence = root / "LICENSE"
    assert licence.is_file(), "there is no LICENSE to ship"
    body = licence.read_text(encoding="utf-8")
    assert len(body) > 500, "LICENSE looks like a placeholder"
    assert "Purple Shell Security" in body, "the copyright line is unfilled"


# ── 15. the header carried a verdict a later measurement had replaced ────────
# `_kql_header` builds from two sources: MEASURED from `verification`, which
# `verify` updates, and DID NOT VALIDATE from `errors`, which it never touched.
# A detection re-measured from `dead` to `no-match` therefore carried both "we
# cannot tell whether the attack simply did not happen or the filter is wrong"
# and, four lines below, "the fault is in what it MATCHES" -- the exact claim
# three rounds of work removed, preserved in the one artifact that leaves the
# tool.

def _det(errors, verdict):
    from pylon.models import Detection, DetectionVerification, ValidatedDetection

    return ValidatedDetection(
        detection=Detection(vector_name="v", mitre_technique="T1",
                            kql="T | take 1", tuning_guidance="-",
                            false_positive_notes="-"),
        log_table="AzureActivity", valid=False, errors=errors, warnings=[],
        retried=False,
        verification=DetectionVerification(
            vector_name="v", operation="X", expected=110, observed=0,
            verdict=verdict, detail="110 events, none matching"))


WORKSPACE_ERROR = ("against real events in the workspace this is dead: 110 real "
                   "events and the detection matched none ... the fault is in "
                   "what it MATCHES")


def test_a_superseded_workspace_verdict_is_dropped_from_the_header():
    from pylon.cli import _kql_header

    header = _kql_header(_det([WORKSPACE_ERROR], "no-match"))
    assert "no-match" in header
    assert "MATCHES" not in header, (
        "the header asserts a fault beneath a verdict saying it cannot tell")


def test_a_static_rejection_survives_a_later_measurement():
    """Only the workspace error is superseded, and only by a workspace verdict.
    A column that does not exist is about the query TEXT, which no measurement
    can overturn."""
    from pylon.cli import _kql_header

    header = _kql_header(_det(['AzureActivity: "Foo" is not a column'], "no-match"))
    assert "Foo" in header and "no-match" in header


def test_an_unmeasured_detection_keeps_its_error():
    from pylon.models import Detection, ValidatedDetection

    d = ValidatedDetection(
        detection=Detection(vector_name="v", mitre_technique="T1",
                            kql="T | take 1", tuning_guidance="-",
                            false_positive_notes="-"),
        log_table="AzureActivity", valid=False, errors=[WORKSPACE_ERROR],
        warnings=[], retried=False)
    from pylon.cli import _kql_header

    assert "MATCHES" in _kql_header(d), (
        "with no later verdict there is nothing to supersede it")


# ── 16. record captured the detection's OUTPUT, not the rows it read ─────────
# Selecting true positives by operation, then outcome spread, then correlation
# was three guesses across three rounds, none of which asked whether the query
# matches the row. Running the query answers it -- but keeping its OUTPUT is a
# different thing, and that shipped first: a detection ending `project
# TimeGenerated, Scope, Action` handed back its own columns, so the fixture held
# `Scope` and none of the `Authorization` or `Properties` the query reads, and
# graded silent against rows it had itself selected.

def test_record_asks_which_rows_matched_then_fetches_those_rows():
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_record)
    assert "project EventDataId" in src, (
        "record keeps the query's output; a projecting detection then gets a "
        "fixture without the columns it reads")
    assert "where EventDataId in " in src


def test_record_only_asks_for_a_key_the_query_surfaces():
    """Asking regardless made the workspace refuse the query once per
    detection -- "Failed to resolve scalar expression named 'EventDataId'" --
    printed as a raw warning before falling through silently. Measured: 11 of
    106 generated detections project it, so nine in ten runs showed a user a
    scary error and then quietly used the old heuristics."""
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_record)
    assert "_surfaces(d.detection.kql" in src


def test_a_sampled_fixture_says_it_is_one():
    """A weaker fixture must not look like the strong kind. A sample proves a
    detection stays quiet on rows it should not match; it anchors nothing about
    what it DOES match, because nothing knows which rows those are."""
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_record)
    assert "sample only" in src and "anchored" in src


def test_only_the_final_projection_decides_what_a_query_surfaces():
    """`| project TimeGenerated, Caller` ends the row at two columns however
    many the table has, so asking for a third is a query that cannot run."""
    from pylon.cli import _surfaces

    assert _surfaces("T | project EventDataId, Caller", "EventDataId")
    assert not _surfaces(
        "T | summarize take_any(*) by EventDataId\n| project Caller",
        "EventDataId")
    assert _surfaces("T | where EventDataId != ''", "EventDataId"), (
        "with no projection the whole row survives")


def test_duplicate_rows_are_collapsed():
    """AzureActivity is commonly ingested twice, so a capture returns each event
    twice and a fixture advertised as 8 rows holds 4. Every detection dedupes on
    EventDataId anyway."""
    from pylon.cli import _distinct

    rows = [{"EventDataId": "a", "n": 1}, {"EventDataId": "a", "n": 1},
            {"EventDataId": "b", "n": 2}]
    assert len(_distinct(rows)) == 2


def test_rows_without_a_key_are_kept_rather_than_collapsed():
    """Two distinct rows that both lack an id are two rows, not one."""
    from pylon.cli import _distinct

    assert len(_distinct([{"n": 1}, {"n": 2}])) == 2


# ── 17. a dedupe on the join key was read as a grouping ─────────────────────
# `_DEDUPE` matched `summarize take_any(*) by EventDataId` alone, so the same
# idiom on CorrelationId -- the join key this codebase's own prompt rules tell
# the model to dedupe on -- was read as an aggregation. A detection using it
# short-circuited to `aggregates` and could never be reported `dead` or
# `no-match`, however many real events it failed to match. One did: 0 groups
# from 110 events, counted toward "3 of 5 produced a valid detection".

@pytest.mark.parametrize("key", ["EventDataId", "CorrelationId", "_ItemId"])
def test_a_dedupe_on_any_single_key_is_a_dedupe(key):
    from pylon.verification import aggregates

    assert not aggregates(f"T | summarize take_any(*) by {key} | project X")


def test_two_keys_is_a_grouping():
    """The output row no longer corresponds to one input row."""
    from pylon.verification import aggregates

    assert aggregates("T | summarize take_any(*) by A, B")


def test_a_real_aggregation_is_still_one():
    from pylon.verification import aggregates

    assert aggregates("T | summarize n = count() by Caller")


def test_zero_groups_names_both_readings_without_picking_one():
    """The old wording said "It needs a case that exceeds its threshold" on
    queries with no threshold -- no count(), no dcount, no comparison. Zero
    groups is genuinely ambiguous and saying so beats asserting either."""
    from pylon.verification import verdict

    call, detail = verdict(110, 0, groups=True)
    assert call == "aggregates", "a threshold rule quiet on benign data is correct"
    assert "threshold nobody crossed" in detail and "matches nothing" in detail


# ── 18. grade keyed its known-result check on the word, not the measurement ──

def test_a_live_run_that_measured_zero_counts_as_known():
    """An `aggregates` verdict with zero groups is a live run that matched
    nothing, and it slipped past a check testing the verdict LABEL into the
    generic "a fixture this size may not hold" branch -- the benign
    misexplanation three earlier rounds were about."""
    import inspect

    from pylon import cli

    src = inspect.getsource(cli._design_grade)
    assert "observed == 0" in src
