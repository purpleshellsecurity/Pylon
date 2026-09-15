"""A vector that was never built must not render as a detection with no query.

A plan enumerates a service's whole operation vocabulary and `--pick` builds a
handful. Round nine built 5 of 25, and the page showed 25 cards. The only
difference between a built one and a proposal was that the built one happened to
carry a code block -- the query block was omitted for the rest, with no label --
so the report read as twenty detections whose KQL had gone missing, and the
header said "detections 5" above them.
"""
from pylon.report_design import _one

# `bases` is CALLED -- `bases(operation, technique)` -- despite the `dict`
# annotation on the signature. Passing {} raises TypeError, not an assertion.
def _bases(_op="", _tech=""):
    return "why this technique"

VECTOR = {"name": "Container ACL changed", "operation": "SetContainerACL",
          "log_table": "StorageBlobLogs", "priority": "high",
          "rationale": "Changes who can read blobs.",
          "alert_condition": "Successful ACL change",
          "mitre_technique": "T1098"}

BUILT = {"valid": True, "table_basis": "deployed",
         "detection": {"kql": "StorageBlobLogs | where OperationName == 'SetContainerACL'",
                       "mitre_technique": "T1098"},
         "verification": {"verdict": "match", "detail": ""}}


def test_a_planned_vector_is_labelled_planned():
    html = _one(VECTOR, None, {}, _bases)
    assert "not built in this run" in html, html
    assert "planned" in html.lower(), html


def test_a_planned_vector_explains_the_missing_query_and_how_to_build_it():
    html = _one(VECTOR, None, {}, _bases)
    assert "planned but not" in html, html
    assert "--pick" in html, "the reader is not told how to build it"


def test_a_planned_vector_does_not_claim_no_scan_was_run():
    """`table_basis` belongs to a built detection. Defaulting an unbuilt vector
    to "unchecked" made it report "No scan was run." on a run where one had
    been, and had answered for the built detections on the same page."""
    html = _one(VECTOR, None, {}, _bases)
    assert "No scan was run." not in html, html
    assert "Not built in this run" in html, html


def test_a_built_detection_is_not_labelled_planned():
    html = _one(VECTOR, BUILT, {}, _bases)
    assert "not built in this run" not in html, html
    assert "SetContainerACL" in html
    assert "Had data in the scan window." in html, html


def test_built_but_queryless_is_distinct_from_never_built():
    """Two different failures. Collapsing them is the bug."""
    empty = {"valid": False, "table_basis": "deployed",
             "detection": {"kql": "", "mitre_technique": "T1098"}}
    html = _one(VECTOR, empty, {}, _bases)
    assert "built but produced no query" in html, html
    assert "planned" not in html.lower(), html
