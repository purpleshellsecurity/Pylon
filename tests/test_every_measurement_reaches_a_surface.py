"""Populate everything, render it, and check what arrived where.

Counting references is not a trace. A field referenced by the eval harness and
by nothing a user opens is still a measurement nobody receives -- `retried` is
read exactly once, in `eval_metrics`, so a detection that needed a correction
pass says so to no reader. That passes a reference check and fails the thing
the reference check was for.

So this builds a detection with EVERY field populated with a distinctive value,
renders the surfaces a human actually opens, and asserts each value arrived at
the surface it belongs to -- or is registered, with a reason, as not belonging
on any.

The surfaces, and what each is for:

    detections.html   the page a reader keeps open
    the .kql file     what gets pasted into Sentinel
    report.json       the artifact every later command reads

Three rounds of clean-room testing found warnings, the verify verdict and the
engine refusal each computed correctly and rendered nowhere. This is the test
that fails on that, rather than on a name appearing somewhere in the package.
"""

import json

import pytest

from pylon import report_design
from pylon.cli import _kql_header
from pylon.models import (Detection, DetectionVerification, OfflineCheck,
                          ValidatedDetection)

# A distinctive string per field, so "did it arrive" is a substring search that
# cannot pass by coincidence.
MARK = {
    "kql": "MARKQUERY",
    "tuning_guidance": "MARKTUNING",
    "false_positive_notes": "MARKFALSEPOS",
    "warnings": "MARKWARNING",
    "errors": "MARKERROR",
    "operation": "MARKOPERATION",
    "rationale": "MARKRATIONALE",
    "prerequisite": "MARKPREREQ",
    "verification_detail": "MARKVERDICTDETAIL",
    "offline_error": "MARKENGINEERROR",
}

# Fields that belong on NO surface, each with the reason. A field here is one
# whose value a reader is not meant to see; the entry is what stops that being
# an accident. Anything not listed must reach at least one surface.
_NOT_FOR_A_READER: dict[str, str] = {
    "live_check": "F3, populated only under --verify-live, which no verb passes",
    "tune": "populated only under --tune, which no verb passes",
    "prove": "populated only by the emulation path, which was cut",
    "retrohunt": "what a detection WOULD have alerted on; read by `library` "
                 "when assembling a saved list, not shown per detection",
    "requires": "attack-path preconditions, consumed by the graph builder",
    "enables": "attack-path effects, consumed by the graph builder",
    "operation_check": "its warnings are merged into `warnings` at generation "
                       "and render from there",
    "log_table": "shown once in the page header rather than per detection",
    "table_basis": "rendered as a sentence ('Had data in the scan window'), "
                   "not as its literal value",
    "priority": "rendered as the card's eyebrow",
    "valid": "rendered as a chip, not as the word True or False",
    "retried": "TODO: a detection that needed a correction pass says so to no "
               "reader. Registered rather than silently passing, because that "
               "is the exact shape this file exists to catch",
    "detection": "the container; its own fields are checked individually",
}


def _detection() -> ValidatedDetection:
    return ValidatedDetection(
        detection=Detection(
            vector_name="MARKVECTOR", mitre_technique="T1685.002",
            kql=f"AzureActivity | where X == '{MARK['kql']}'",
            tuning_guidance=MARK["tuning_guidance"],
            false_positive_notes=MARK["false_positive_notes"]),
        log_table="AzureActivity", valid=False,
        errors=[MARK["errors"]], warnings=[MARK["warnings"]], retried=True,
        offline_check=OfflineCheck(ran=True, ok=False, error=MARK["offline_error"]),
        table_basis="deployed", prerequisite=MARK["prerequisite"],
        operation=MARK["operation"], rationale=MARK["rationale"], priority="high",
        verification=DetectionVerification(
            vector_name="MARKVECTOR", operation=MARK["operation"],
            expected=110, observed=0, verdict="dead",
            detail=MARK["verification_detail"], widened=True))


def _page(tmp_path) -> str:
    d = _detection()
    report = {
        "service": "x", "platform": "resource", "generation_yield": 0,
        "critical_gaps": [],
        "analysis": {"service": "x", "platform": "resource",
                     "executive_summary": "s", "attack_vectors": [
                         {"name": "MARKVECTOR", "priority": "high",
                          "mitre_technique": "T1685.002",
                          "operation": MARK["operation"],
                          "log_table": "AzureActivity",
                          "alert_condition": "c",
                          "rationale": MARK["rationale"]}]},
        "detections": [json.loads(d.model_dump_json())]}
    report_design.write(report, tmp_path)
    return (tmp_path / "detections.html").read_text(encoding="utf-8")


# ── the page ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("field", [
    "kql", "tuning_guidance", "false_positive_notes", "warnings",
    "operation", "rationale", "verification_detail",
])
def test_the_page_carries_it(tmp_path, field):
    """Each of these was, at some point in three rounds, computed and rendered
    nowhere."""
    assert MARK[field] in _page(tmp_path), (
        f"{field} is populated on the detection and does not reach the page a "
        "reader opens")


def test_an_engine_refusal_reaches_the_page(tmp_path):
    """Not the raw text -- the engine reports no reason worth quoting -- but the
    fact that it refused."""
    assert "KQL engine refused" in _page(tmp_path)


def test_a_verdict_reaches_the_page_as_a_verdict(tmp_path):
    page = _page(tmp_path)
    assert "measured:" in page and "matched nothing real" in page


# ── the .kql file, which is what gets pasted into Sentinel ───────────────────

@pytest.mark.parametrize("field", ["warnings", "errors", "verification_detail"])
def test_the_kql_header_carries_it(field):
    header = _kql_header(_detection())
    flat = " ".join(line.lstrip("/ ") for line in header.splitlines())
    assert MARK[field] in flat, (
        f"{field} does not reach the file someone pastes into Sentinel")


# ── report.json, which every later command reads ─────────────────────────────

@pytest.mark.parametrize("field", list(MARK))
def test_the_artifact_carries_everything(field):
    """The artifact is the one surface that should lose nothing, because
    `verify`, `record` and `coverage` all read it rather than the page."""
    assert MARK[field] in _detection().model_dump_json()


# ── the registry ─────────────────────────────────────────────────────────────

def test_every_field_reaches_a_surface_or_says_why_not(tmp_path):
    """The check that makes the rest of this file a trace rather than a
    sample. A new field either shows up somewhere a reader looks, or the person
    adding it writes down why it does not."""
    page, header = _page(tmp_path), _kql_header(_detection())
    artifact = _detection().model_dump_json()
    unreachable = []
    for name in ValidatedDetection.model_fields:
        if name in _NOT_FOR_A_READER:
            continue
        # A nested object carries its marker on an inner field. Named here
        # rather than flattened, so adding a nested type forces the author to
        # say which of its fields a reader is meant to see.
        mark = MARK.get({"offline_check": "offline_error",
                         "verification": "verification_detail"}.get(name, name))
        if mark is None:
            unreachable.append(f"{name} (no marker in this test)")
        elif not any(mark in surface for surface in (page, header, artifact)):
            unreachable.append(f"{name} (populated, reaches no surface)")
    assert unreachable == [], (
        f"{unreachable}. Wire it to a surface, or add it to _NOT_FOR_A_READER "
        "with the reason. A measurement a reader never receives is the shape "
        "of every finding three rounds of clean-room testing produced.")


def test_the_registry_gives_a_reason_for_each_exemption():
    for field, reason in _NOT_FOR_A_READER.items():
        assert len(reason) > 25, f"{field} is exempt with no real reason"


def test_the_registry_names_only_real_fields():
    unknown = [f for f in _NOT_FOR_A_READER
               if f not in ValidatedDetection.model_fields]
    assert unknown == [], f"exempt and not a field any more: {unknown}"
