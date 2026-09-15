"""The report joins a detection to its vector by NAME, and the model renames.

Told that its allowlist clause was dead, the model narrowed "Diagnostic sink
redirected to non-approved destination" to "...redirected cross-subscription".
That is the right answer to the feedback and it broke the join: the lookup
missed, and the page rendered a card with the rationale and the alert condition
and NO QUERY and NO VERDICT, for three of five detections at once. report.json
held every query and every verdict the whole time.

This is the shape that keeps recurring here -- a value computed correctly in one
place and lost at the far end -- and it is the second time name matching has
been the cause. So there are two defences and a test for each. The engine stamps
the key it owns, and the page renders a detection it was given even when no
vector claims it.
"""

import re

from pylon import report_design


def _report(vector_name: str, detection_name: str) -> dict:
    return {
        "platform": "azure",
        "service": "AzureActivity",
        "analysis": {"attack_vectors": [{
            "name": vector_name, "priority": "high",
            "mitre_technique": "T1685.002", "log_table": "AzureActivity",
            "operation": "Microsoft.Insights/DiagnosticSettings/Write",
            "alert_condition": "c", "rationale": "r r.",
        }]},
        "detections": [{
            "valid": True, "log_table": "AzureActivity", "table_basis": "unchecked",
            "operation": "Microsoft.Insights/DiagnosticSettings/Write",
            "verification": {"verdict": "under", "detail": "15 rows for 60 events"},
            "detection": {
                "vector_name": detection_name,
                "mitre_technique": "T1685.002",
                "kql": "AzureActivity\n| where TimeGenerated > ago(1h)\n| take 1",
                "tuning_guidance": "t", "false_positive_notes": "f",
            },
        }],
    }


def _queries(html: str) -> list[str]:
    return re.findall(r'<pre class="kql">(.*?)</pre>', html, re.S)


def test_the_query_renders_when_the_names_agree():
    html = report_design.build(_report("Sink redirected", "Sink redirected"))
    assert len(_queries(html)) == 1
    assert "measured" in html


def test_the_query_still_renders_when_the_model_renamed_the_vector():
    """The regression. Before the orphan pass this produced zero queries."""
    html = report_design.build(
        _report("Sink redirected to non-approved destination",
                "Sink redirected cross-subscription"))
    queries = _queries(html)
    assert len(queries) == 1, "the page dropped a query it was handed"
    assert "take 1" in queries[0]


def test_the_verdict_survives_the_rename_too():
    """A card with no verdict reads as a detection nobody measured, which is a
    different and much worse claim than the one the run actually made."""
    html = report_design.build(
        _report("Original name", "Renamed by the model"))
    assert "15 rows for 60 events" in html


def test_a_vector_that_produced_no_detection_is_still_shown():
    """The orphan pass must not swallow the opposite case: a vector that was
    planned and never built still gets a card, without a query."""
    report = _report("Planned", "Planned")
    report["detections"] = []
    html = report_design.build(report)
    assert "Planned" in html
    assert _queries(html) == []


def test_the_engine_stamps_the_key_rather_than_trusting_the_answer():
    """First line of defence. The engine holds the vector it asked for, so the
    join key must come from there and not from the model's reply."""
    import inspect

    from pylon import engine

    source = inspect.getsource(engine)
    assert "detection.vector_name = vector.name" in source, (
        "the engine no longer stamps the vector name, so the report's join key "
        "is whatever the model decided to call it")
