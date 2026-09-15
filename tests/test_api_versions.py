"""The pinned API versions, and the gate that a stale one was routing around.

An api-version is part of the contract. A version four years old can be missing
an enum value the code branches on, and the failure is silent: the field parses,
the value is unrecognised, and a default takes over.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from pylon import apiversions, rulehealth


def test_no_call_site_hardcodes_a_version():
    """The point of the module. A pin that lives at a call site is a pin nobody
    re-checks, because re-checking means grepping eleven files."""
    offenders = []
    for path in pathlib.Path("src/pylon").rglob("*.py"):
        if path.name in ("apiversions.py", "__init__.py"):
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"api-version=\d{4}-\d{2}-\d{2}", line):
                offenders.append(f"{path}:{n}")
    assert not offenders, offenders


@pytest.mark.parametrize("name", ["LOG_ANALYTICS", "SENTINEL", "AUTHORIZATION"])
def test_these_are_stable_versions(name):
    assert not getattr(apiversions, name).endswith("-preview")


def test_the_diagnostic_settings_pin_is_preview_and_says_why():
    """Microsoft has never shipped a stable diagnostic settings API. Checked
    2026-09-09: the reference lists 2021-05-01-preview as the only version.
    Left preview deliberately, and the module records that so the next audit
    does not hunt for a stable version that does not exist."""
    assert apiversions.MONITOR_DIAGNOSTIC_SETTINGS.endswith("-preview")
    doc = pathlib.Path("src/pylon/apiversions.py").read_text(encoding="utf-8")
    # Comment markers and wrapping removed, so the assertion is about the
    # sentence being there rather than where it happens to break.
    flat = " ".join(doc.replace("#", " ").split())
    assert "never shipped a stable diagnostic settings API" in flat


def test_the_entra_pin_is_stable_and_was_actually_checked():
    """Old and correct. The aadiam provider offers exactly two versions,
    2017-04-01 and 2017-04-01-preview, and the stable one is what every
    Microsoft sample uses. Age is not staleness."""
    assert apiversions.AADIAM == "2017-04-01"
    assert not apiversions.AADIAM.endswith("-preview")
    doc = pathlib.Path("src/pylon/apiversions.py").read_text(encoding="utf-8")
    assert "NOT yet re-checked" not in doc, "every pin now carries its evidence"


def test_no_entra_category_is_matched_against_a_hardcoded_list():
    """The aadiam reference documents two log categories and its own sample
    enables seven. A tool that checked the returned categories against that
    enum would silently drop every category added since 2017, which is the
    same failure as the Auxiliary table plan."""
    src = pathlib.Path("src/pylon/scopes.py").read_text(encoding="utf-8")
    body = "\n".join(ln for ln in src.splitlines()
                     if not ln.lstrip().startswith("#"))
    for category in ("SignInLogs", "NonInteractiveUserSignInLogs", "RiskyUsers"):
        assert category not in body, category


def test_log_analytics_is_new_enough_to_know_about_auxiliary():
    """The bug this file exists for. On 2022-10-01 the table plan enum holds
    Basic and Analytics only; Auxiliary came later. Reading `plan` on the old
    version meant an Auxiliary table reported a plan the code did not
    recognise."""
    assert apiversions.LOG_ANALYTICS >= "2025-02-01"


# ── the gate itself ──────────────────────────────────────────────────────────

def _rule(tables):
    return {"name": "r", "_query": "AnyTable | count",
            "tables_referenced": tables, "_kind": "Scheduled"}


def _no_query_should_run(*_a, **_k):
    raise AssertionError("a query ran against a table that may be billable")


def test_a_billable_table_is_never_queried(monkeypatch):
    monkeypatch.setattr(rulehealth, "_run", _no_query_should_run)
    out = rulehealth._one(_rule(["Cheap", "Verbose"]), "guid",
                          {"Cheap": "Analytics", "Verbose": "Auxiliary"})
    assert out["rule_health_status"] == "not-assessed"
    assert "Verbose" in out["health_detail"]


def test_an_unknown_plan_is_refused_like_a_billable_one(monkeypatch):
    """The hole. The caller used to coerce an unreadable plan to "Analytics",
    so the gate read FREE exactly when the control plane would not say. An
    unmeasured cost is not a licence to spend."""
    monkeypatch.setattr(rulehealth, "_run", _no_query_should_run)
    out = rulehealth._one(_rule(["Mystery"]), "guid", {"Mystery": None})
    assert out["rule_health_status"] == "not-assessed"
    assert "could not be read" in out["health_detail"]


def test_a_table_absent_from_the_map_is_still_queried(monkeypatch):
    """Not the same case. A table absent from the tier map holds no data at
    all, so querying it scans nothing and costs nothing -- and that empty
    result is the never-fires signal."""
    monkeypatch.setattr(rulehealth, "_run", lambda *a, **k: (0, None, 0))
    out = rulehealth._one(_rule(["Empty"]), "guid", {"Other": "Analytics"})
    assert out["rule_health_status"] == "never-fires"


def test_analytics_is_queried(monkeypatch):
    monkeypatch.setattr(rulehealth, "_run", lambda *a, **k: (7, None, 0))
    out = rulehealth._one(_rule(["Cheap"]), "guid", {"Cheap": "Analytics"})
    assert out["rule_health_status"] == "fires"
