"""What the scan could NOT read.

This codebase records a `ran` flag and a reason per leg; nothing rendered the
second half where a reader would see it, so a scan missing seven of its ten
reads produced a document that looked complete.

The section that fixes that only appears when something went unanswered. On a
clean scan it was ten rows all saying "Answered", restating a workspace name
and window the page header already carries — noise in a document whose whole
job is to be worth reading.
"""

from pylon import report
from pylon.report import coverage_of_reads


def test_an_unanswered_question_is_named_with_its_reason():
    rows = coverage_of_reads({"table_activity": {
        "ran": False, "detail": "log-analytics extension not installed"}})
    question, answered, why = next(r for r in rows
                                   if r[0] == "Which tables hold data")
    assert answered is False
    assert why == "log-analytics extension not installed"


def test_unanswered_questions_come_first():
    """They change how everything above them should be read, so they are not
    at the bottom of a list sorted by name."""
    rows = coverage_of_reads({"inventory": {"ran": True},
                              "table_activity": {"ran": False, "detail": "x"}})
    assert rows[0][1] is False


def test_a_leg_absent_from_the_document_counts_as_unanswered():
    """A missing key is not an answered question. Treating absence as success
    is the failure this whole section exists to surface."""
    rows = coverage_of_reads({})
    assert all(answered is False for _, answered, _ in rows)


def test_an_answered_question_carries_no_reason():
    rows = coverage_of_reads({"inventory": {"ran": True, "detail": ""}})
    question, answered, why = next(r for r in rows
                                   if r[0] == "Which resources exist")
    assert answered is True and why == ""


def test_every_question_is_phrased_for_a_reader():
    """`table_activity` and `rule_audit` are this codebase's field names. A
    client reads questions, not schema."""
    for question, _, _ in coverage_of_reads({}):
        assert "_" not in question
        assert question[0].isupper()


def test_the_section_is_absent_when_every_read_answered():
    """Ten rows of "Answered" say nothing a report without the section does
    not already imply."""
    from pylon import report
    doc = _document()
    html = report.build(doc, None, None, None, None)
    assert "could not answer" not in html


def test_the_section_appears_when_a_read_failed(document=None):
    """The case it exists for: a section above is incomplete rather than
    empty, and nothing else on the page says so."""
    from pylon import report
    doc = _document()
    doc["reads"]["table_activity"] = {
        "ran": False, "detail": "log-analytics extension not installed"}
    html = report.build(doc, None, None, None, None)
    assert "1 question this scan could not answer" in html
    assert "log-analytics extension not installed" in html


def _document():
    SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
    kind = "microsoft.storage/storageaccounts"
    rows = [{"resource_id": f"{SUB}/providers/{kind}/s{i}",
             "resource_type": kind, "scope": "resource",
             "logging_status": "not-enabled", "assessment_status": "assessed",
             "surfaces": [], "expected_tables": [], "unmapped_categories": [],
             "basis": "", "privileged_role_assignments": [],
             "exposure": "unknown", "exposure_source": "unrated"}
            for i in range(2)]
    return {
        "generated_at": "2026-09-08T00:00:00Z", "scope": SUB, "window_days": 30,
        "workspace": "example-workspace",
        # Derived from READ_LABEL, not retyped. This was a hand-written list
        # of ten names, so adding an eleventh read made the fixture report it
        # as unanswered and both tests below failed for a reason that had
        # nothing to do with what they check.
        "reads": {k: {"ran": True, "detail": "done"} for k in report.READ_LABEL},
        "summary": {"resources": 2, "resource_types": 1, "dark_resources": 2,
                    "loggable_resources": 2, "rules_total": 0,
                    "tables_checked": 1},
        "resources": rows, "rules": [], "coverage_gaps": [], "tables": [],
    }
