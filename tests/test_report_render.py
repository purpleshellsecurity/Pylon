"""Render the whole report from a synthetic document.

`build()` is a 600-line f-string. Nothing in the suite called it, so a stray
key or a broken format spec would have shipped and only shown up as a
traceback on somebody's first scan. This renders it end to end and asserts on
the section a reader acts on.

The document is synthetic on purpose: made-up subscription, made-up resource
names. A fixture cut from a real scan would put a tenant's inventory in a
public repo, which is the thing `scripts/make-release.sh` exists to prevent.
"""

import re

import pytest

from pylon import report

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
RG = f"{SUB}/resourceGroups/example-rg/providers"


def _res(name, rtype, status, assessment="assessed"):
    return {"resource_id": f"{RG}/{rtype}/{name}", "resource_type": rtype,
            "scope": "resource", "logging_status": status,
            "assessment_status": assessment, "surfaces": [],
            "expected_tables": [], "unmapped_categories": [],
            "basis": "synthetic", "privileged_role_assignments": [],
            "exposure": "unknown", "exposure_source": "unrated"}


@pytest.fixture
def document():
    resources = (
        [_res(f"examplestg{i}", "microsoft.storage/storageaccounts", "not-enabled")
         for i in range(10)]
        + [_res("example-kv-1", "microsoft.keyvault/vaults", "fully-enabled"),
           _res("example-kv-2", "microsoft.keyvault/vaults", "partial-enabled"),
           _res("example-vm-1", "microsoft.compute/virtualmachines", None,
                "not_assessed"),
           _res("example-web-1", "microsoft.web/sites", "fully-enabled"),
           _res("example-web-2", "microsoft.web/sites", None, "not_assessed"),
           _res("example-nsg-1", "microsoft.network/networksecuritygroups",
                "fully-enabled"),
           _res("example-nothing", "microsoft.foo/bars", None, "out_of_scope")])
    return {
        "generated_at": "2026-09-08T00:00:00Z", "scope": SUB, "window_days": 30,
        "workspace": "example-workspace",
        "reads": {"inventory": {"ran": True, "detail": ""},
                  "rules": {"ran": True, "detail": ""},
                  "table_activity": {"ran": True, "detail": ""},
                  "role_assignments": {"ran": True, "detail": ""}},
        "summary": {"resources": 17, "resource_types": 6, "dark_resources": 10,
                    "loggable_resources": 14, "rules_total": 2,
                    "tables_checked": 3},
        "resources": resources, "rules": [], "coverage_gaps": [],
        "tables": [{"table_name": "AzureActivity", "table_tier": "Analytics",
                    "last_ingest": "2026-09-08T00:00:00Z", "megabytes": 1.0}],
    }


@pytest.fixture
def section(document):
    """Just the Not-logging section, as rendered."""
    html = report.build(document, None, None, None, None)
    # "Step 1 · Sources", renamed from "Diagnostic settings". The section now
    # answers one question with two mechanisms: a resource logs through a
    # diagnostic setting, and Microsoft 365 / AWS / Defender have none, so the
    # connector is the source. Both fill tables, so both are judged here.
    found = re.search(r'<div class="eyebrow">Step 1 . Sources</div>.*?</section>',
                      html, re.S)
    assert found, "the Sources section did not render"
    return found.group(0)


def test_it_renders_at_all(document):
    """The whole report, start to finish, without raising.

    Both reports emit a fragment -- a title, a stylesheet and sections, with no
    doctype or <html> wrapper. That is `reportkit.HEAD` as written and browsers
    render it; this asserts what it actually produces rather than what an
    HTML document usually looks like.
    """
    html = report.build(document, None, None, None, None)
    assert html.startswith("<title>")
    # Every section that should be there, is. The failure this guards against
    # is a section quietly rendering empty because a key moved.
    #
    # The eyebrows are the STEP names now. "Diagnostic settings" and "Data
    # sources" both answered step 1 and sat at opposite ends of the page;
    # "Ingestion gaps" and "Connector health" both answered step 2 and were
    # five sections apart. Each pair merged.
    for eyebrow in ("Step 1 · Sources", "Step 2 · Data arriving"):
        assert f'<div class="eyebrow">{eyebrow}</div>' in html, eyebrow
    # What those two sections absorbed, still rendering inside them.
    assert "What each scope emits about itself" in html
    # "Coverage" is gone on purpose. It said "N of M loggable resources are
    # dark" directly above "Not logging", which said the same thing with a
    # different denominator — two headings about one subject, close enough
    # together that the report needed a note explaining why they disagreed.
    # The bar moved into Diagnostic settings; the second heading did not survive.
    assert '<div class="eyebrow">Coverage</div>' not in html


def test_a_type_where_nothing_is_logging_says_so(section):
    assert "0 of 10 configured" in section
    assert "microsoft.storage/storageaccounts" in section


def test_a_partly_covered_type_names_only_the_gap(section):
    """Ten healthy resources listed beside one broken one buries the one that
    needs work, so only resources with a gap are named."""
    assert "1 of 2 not configured" in section
    assert "example-kv-2" in section
    assert "example-kv-1" not in section


def test_an_unassessed_resource_is_never_shown_as_healthy(section):
    """The bug the first render caught. A VM nobody could check came out as
    "all logging", because zero gaps out of one resource is zero gaps."""
    row = re.search(r"microsoft\.compute/virtualmachines.*?</tr>", section, re.S)
    assert row, "the VM row did not render"
    assert "not assessed" in row.group(0)
    assert "all" not in row.group(0)


def test_unassessed_resources_stay_out_of_the_denominator(section):
    """One Web App is logging and one could not be checked. "all 2 configured"
    would be a claim about a resource nobody looked at."""
    row = re.search(r"microsoft\.web/sites.*?</tr>", section, re.S)
    assert "all 1 configured" in row.group(0)
    assert "+1 not assessed" in row.group(0)


def test_a_type_with_nothing_to_switch_on_is_absent(section):
    """Not a row of zeroes -- gone. It is not a gap and it is not work."""
    assert "microsoft.foo/bars" not in section


def test_every_resource_is_named_however_many_there_are(section):
    """The list used to stop at eight and say "+2 more". A reader cannot act on
    a resource the report will not name, and this document exists to be acted
    on."""
    assert "more</span>" not in section
    assert "examplestg9" in section


def test_the_heading_counts_what_the_table_adds_up_to(section):
    """It sits inches under "N of M loggable resources are dark", which counts
    something narrower. A heading that borrowed that number would make the
    table below it look like it could not add."""
    # The count is wrapped in the verdict colour, so the sentence carries a
    # tag between its two halves. Both halves, and the pair of numbers, are
    # what this test is about.
    assert '<span class="t-none">11 of 14 resources</span>' in section
    assert "diagnostic setting missing or incomplete" in section
    # The type count left the heading: the table underneath is a list of types,
    # so the heading was counting rows the reader can already see.
    assert "across" not in section.split("</h2>")[0]


def test_a_never_measured_figure_is_a_dash_not_the_word_None(document):
    """`None` means the leg did not run. Dropped into an f-string it renders as
    the word "None", sitting in the same slot as a count -- a real report
    announced "None tables with data", which reads as zero. Wrong in the one
    direction this document is not allowed to be wrong in."""
    document["summary"]["tables_checked"] = None
    html = report.build(document, None, None, None, None)
    assert ">None<" not in html
    assert "table activity NOT MEASURED" in html


def test_where_to_start_says_what_it_ranks_by(document):
    """The heading implied a judgement the tool did not make. Ranking by rules
    blocked means a gap nobody wrote a rule against scores zero — so the order
    rewards what the tenant already thought to detect, and a reader has to know
    that to know what is missing from the list."""
    html = report.build(document, None, None, None, None)
    if "Where to start" in html:
        assert "Ordered by how many analytics rules each gap blocks" in html
