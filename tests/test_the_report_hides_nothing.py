"""The report does not truncate, so nothing in it may claim it did.

Lists here were once capped -- eight resource names, six categories -- with a
"+N more" tail. The caps went, on the grounds that a reader has to go and tick
every one of them in the portal and the ones hidden are the ones they would
miss. Two halves of that removal were left behind:

  * the Entra / Activity Log scope row joined EVERY unticked category and then
    appended "+4 more" anyway -- the document claiming to hide four names it
    had just printed;
  * `headline` carried a comment describing a cap that no longer existed.

The second is prose and this file cannot see it. The first is arithmetic, and
this file holds it.
"""

import re

from pylon.report import build

CATEGORIES = [f"Category{i:02d}" for i in range(10)]


def _document(enabled, available):
    tenant = {
        "resource_id": "/tenants/t1/providers/microsoft.aadiam/tenant",
        "resource_type": "microsoft.aadiam/tenant",
        "scope": "tenant",
        "logging_status": "partial-enabled",
        "assessment_status": "assessed",
        "surfaces": [], "expected_tables": [], "unmapped_categories": [],
        "basis": "synthetic", "privileged_role_assignments": [],
        "exposure": "unknown", "exposure_source": "unrated",
    }
    analysis = {
        "generated_at": "2026-09-08T00:00:00Z", "window_days": 30,
        "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
        "workspace": "example-workspace",
        "summary": {"resources": 1, "resource_types": 1, "dark_resources": 0,
                    "loggable_resources": 1, "rules_total": 0,
                    "tables_checked": 0},
        "reads": {}, "resources": [tenant], "rules": [],
        "coverage_gaps": [], "tables": [],
    }
    verdicts = [{"resource_id": analysis["resources"][0]["resource_id"],
                 "enabled": enabled, "available": available, "groups": []}]
    return build(analysis, None, None, verdicts, None)


def test_every_unticked_category_is_named():
    html = _document(CATEGORIES[:2], CATEGORIES)
    for name in CATEGORIES[2:]:
        assert name in html, f"{name} is not enabled and the report never names it"


def test_the_report_does_not_claim_to_have_hidden_anything():
    """`+4 more` under a list that is already complete."""
    html = _document(CATEGORIES[:2], CATEGORIES)
    phantom = re.findall(r"\+\s*\d+\s+more", html)
    assert phantom == [], f"the report says it truncated a list it printed in full: {phantom}"


def test_a_short_list_still_renders():
    html = _document(["AuditLogs"], ["AuditLogs", "SignInLogs"])
    assert "SignInLogs" in html
    assert "Not enabled" in html


# ── a slice that says nothing about having sliced ────────────────────────────

def test_the_rule_name_is_not_cut():
    """`name[:52]` in the rules table.

    The name is the identifier a reader takes to the portal, and two rules
    sharing a long prefix -- which Sentinel's own templates do -- became the
    same 52 characters in the only column that tells them apart. The dead-rule
    group two sections below already printed both in full.
    """
    long = "Suspicious number of resource creation or deployment activities"
    assert len(long) > 52
    html = build(
        {"generated_at": "2026-09-08T00:00:00Z", "window_days": 30,
         "scope": "/subscriptions/0", "workspace": "w", "summary": {},
         "reads": {}, "resources": [], "rules": [], "coverage_gaps": [],
         "tables": []},
        None, None, None,
        [{"name": long, "rule_health_status": "fires",
          "tables_referenced": ["AzureActivity"], "_template": True}],
    )
    assert long in html, "the rules table cut the name a reader has to match"


def test_a_clipped_reason_says_it_was_clipped():
    from pylon.report import clip

    assert clip("short", 99) == "short"
    assert clip("x" * 200, 10) == "x" * 10 + "…"
    assert not clip("x" * 200, 10).endswith("xx… ")


def test_no_bare_slice_survives_in_a_text_cell():
    """The pattern, not the four instances. A timestamp slice is deliberate
    formatting; a slice of a name, a reason or a detail is text going missing.
    """
    import pathlib
    import re

    src = (pathlib.Path(__file__).resolve().parents[1]
           / "src" / "pylon" / "report.py").read_text(encoding="utf-8")
    bad = re.findall(r"""\w*(?:name|why|detail|description|reason)\w*"?\]?\[:\d+\]""",
                     src, re.IGNORECASE)
    assert bad == [], f"text cut with no ellipsis and nothing saying so: {bad}"
