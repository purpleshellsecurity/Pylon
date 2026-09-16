"""What the object knows has to reach the page someone opens.

Every check in this codebase was honest in its own data and invisible at the
surface a human reads. `validate_kql` says "Microsoft's column list could not be
fetched, so this was NOT checked -- verify before deploying"; the page said
"Every query passed the validator". `design verify` measures that a detection
matched nothing real; the page never mentioned it, and was never rewritten
afterwards, so running the one command built to catch a dead detection left the
full-marks page exactly as it was.

Both were the same failure: the renderer is handed the whole report -- warnings,
offline verdict and verification all sit in its own argument -- and read none of
it.
"""



from pylon import report_design
from pylon.cli import _kql_header
from pylon.models import (Detection, DetectionVerification, ValidatedDetection)


def _detection(**over) -> dict:
    d = {
        "detection": {"vector_name": "Owner role granted", "mitre_technique": "T1098.003",
                      "kql": "AzureActivity | take 1", "tuning_guidance": "-",
                      "false_positive_notes": "-"},
        "log_table": "AzureActivity", "valid": True, "errors": [], "warnings": [],
        "retried": False, "operation": "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
        "table_basis": "deployed",
    }
    d.update(over)
    return d


def _page(tmp_path, *detections) -> str:
    report = {
        "service": "Microsoft.Authorization/roleAssignments", "platform": "resource",
        "generation_yield": len(detections), "critical_gaps": [],
        "analysis": {"service": "x", "platform": "resource", "executive_summary": "s",
                     "attack_vectors": [
                         {"name": "Owner role granted", "priority": "critical",
                          "mitre_technique": "T1098.003",
                          "operation": "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
                          "log_table": "AzureActivity", "alert_condition": "c",
                          "rationale": "r r."}]},
        "detections": list(detections),
    }
    report_design.write(report, tmp_path)
    return (tmp_path / "detections.html").read_text(encoding="utf-8")


def _graded(verdict: str, detail: str) -> dict:
    return {"vector_name": "Owner role granted", "operation": "X", "expected": 144,
            "observed": 0, "verdict": verdict, "detail": detail, "widened": True}


# ── the verdict reaches the page ─────────────────────────────────────────────

def test_a_dead_detection_does_not_look_like_a_working_one(tmp_path):
    """The whole reason `design verify` exists. A query that parses, deploys and
    never fires rendered identically to one that matches real events."""
    page = _page(tmp_path, _detection(
        verification=_graded("dead", "144 real events and the detection matched none")))
    assert "matched nothing real" in page
    assert "144 real events" in page


def test_no_ground_truth_is_neither_a_pass_nor_a_fault(tmp_path):
    """The workspace could not settle the question. Rendering it as either
    answer is the mistake this codebase is arranged to prevent."""
    page = _page(tmp_path, _detection(
        verification=_graded("no-ground-truth", "no events of this operation in the window")))
    assert "no events to test against" in page
    assert "which is not a pass" in page


def test_a_detection_that_matched_real_events_says_so(tmp_path):
    page = _page(tmp_path, _detection(
        verification=_graded("exact", "2 rows for 2 events")))
    assert "matches real events" in page


# ── warnings reach the page ──────────────────────────────────────────────────

WARNING = ('AzureActivity: "Foo" is not a column the prompt teaches. '
           "Microsoft's column list could not be fetched, so this was NOT "
           "checked against it -- verify the name before deploying.")


def test_a_validator_warning_is_rendered(tmp_path):
    page = _page(tmp_path, _detection(warnings=[WARNING]))
    assert "could not be fetched" in page


def test_a_warned_run_does_not_claim_every_query_passed(tmp_path):
    """The exact sentence that was wrong: valid=True with a warning saying the
    column list was never checked, under a line reading 'Every query passed'."""
    page = _page(tmp_path, _detection(warnings=[WARNING]))
    assert "Every query passed the validator" not in page
    assert "carries a validator warning" in page


def test_a_clean_run_still_says_so_and_points_at_verify(tmp_path):
    page = _page(tmp_path, _detection())
    assert "Every query passed the validator" in page
    assert "design verify" in page, (
        "a page claiming the validator passed must say what it does not cover")


def test_the_engine_refusing_a_query_is_on_the_page(tmp_path):
    page = _page(tmp_path, _detection(
        offline_check={"ran": True, "ok": False, "error": "bad request"}))
    assert "KQL engine refused" in page


def test_the_headline_counts_detections_not_valid_ones(tmp_path):
    """`valid` answers "is it well formed" and was the headline number, read as
    "it works"."""
    page = _page(tmp_path, _detection(verification=_graded("dead", "matched none")))
    assert "1 detection over" in page


# ── the .kql file, which is what gets pasted into Sentinel ───────────────────

def _vd(**over) -> ValidatedDetection:
    base = dict(
        detection=Detection(vector_name="v", mitre_technique="T1",
                            kql="AzureActivity | take 1", tuning_guidance="-",
                            false_positive_notes="-"),
        log_table="AzureActivity", valid=True, errors=[], warnings=[], retried=False)
    base.update(over)
    return ValidatedDetection(**base)


def test_the_header_the_engine_comment_promised_now_exists():
    """`engine.py` said warnings "surface in the .kql header". They did not --
    the writer was one line and the files began with the table name. A comment
    asserting a surface that does not exist is how a gap stays open."""
    header = _kql_header(_vd(warnings=[WARNING]))
    assert header.startswith("// ")
    # Wrapped at 96 columns, so the sentence spans lines. Read it the way a
    # person does rather than the way a string does.
    flat = " ".join(line.lstrip("/ ") for line in header.splitlines())
    assert "could not be fetched" in flat


def test_a_measured_verdict_is_in_the_header():
    header = _kql_header(_vd(verification=DetectionVerification(
        vector_name="v", operation="X", expected=144, observed=0,
        verdict="dead", detail="144 real events and the detection matched none")))
    assert "MEASURED: dead" in header


def test_a_clean_detection_gets_no_header():
    """A comment block on every file would be noise, and noise is what stops
    the one that matters being read."""
    assert _kql_header(_vd()) == ""


def test_the_header_is_valid_kql_comments():
    """It is prepended to a query someone pastes into Sentinel. A line that is
    not a comment breaks the query it was meant to warn about."""
    header = _kql_header(_vd(warnings=[WARNING, "another " * 40]))
    for line in header.splitlines():
        assert line.startswith("//"), line
