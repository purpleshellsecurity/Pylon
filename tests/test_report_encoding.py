"""The report must survive being written on a machine whose default is cp1252.

`open(path, "w")` uses the platform's preferred encoding. On Linux and macOS
that is UTF-8, so every test passed; on Windows it is cp1252, and the first
non-ASCII character in the document killed the run after twelve legs of work
had completed and been written to analysis.json.

The character that did it was an arrow in "Enable AuditEvent → AZKVAuditLogs",
added while making the summary readable. Em dashes had always been written as
`&mdash;` entities, which are ASCII, so nothing had ever exercised this.

These tests do not run on Windows. They encode the document to cp1252 by hand,
which is the same question asked somewhere it can be answered.
"""

import re

import pytest

from pylon import report

RG = "/subscriptions/S/resourceGroups/RG/providers"
STORAGE = "microsoft.storage/storageaccounts"


def res(name, kind, status, assessment="assessed"):
    return {"resource_id": f"{RG}/{kind}/{name}", "resource_type": kind,
            "scope": "resource", "logging_status": status,
            "assessment_status": assessment, "surfaces": [],
            "expected_tables": [], "unmapped_categories": [],
            "basis": "synthetic", "privileged_role_assignments": [],
            "exposure": "unknown", "exposure_source": "unrated"}


@pytest.fixture
def document():
    rows = [res(f"s{i}", STORAGE, "not-enabled") for i in range(3)]
    return {
        "generated_at": "2026-09-08T00:00:00Z", "scope": "/subscriptions/S",
        "window_days": 30, "workspace": "example-workspace",
        "reads": {"inventory": {"ran": True, "detail": ""},
                  "rules": {"ran": True, "detail": ""},
                  "table_activity": {"ran": True, "detail": ""}},
        "summary": {"resources": 3, "resource_types": 1, "dark_resources": 3,
                    "loggable_resources": 3, "rules_total": 0,
                    "tables_checked": 1},
        "resources": rows, "rules": [], "tables": [],
        "coverage_gaps": [
            {"resource_id": rows[0]["resource_id"],
             "expected_table": "StorageBlobLogs",
             "dark_reason": "no diagnostic setting",
             "categories_to_enable": ["StorageRead"], "is_logging": False}],
    }


def test_the_document_is_encodable_as_utf8(document):
    """The encoding it is actually written in."""
    report.build(document, None, None, None, None).encode("utf-8")


def test_the_document_declares_its_encoding(document):
    """A UTF-8 file a browser is left to guess about renders as mojibake. The
    declaration has to be near the top: browsers scan the first 1024 bytes."""
    html = report.build(document, None, None, None, None)
    assert '<meta charset="utf-8">' in html[:1024]


def test_the_document_contains_characters_cp1252_cannot_hold(document):
    """The guard on this whole file. If the report ever became pure ASCII the
    test below would pass for the wrong reason and stop protecting anything."""
    html = report.build(document, None, None, None, None)
    with pytest.raises(UnicodeEncodeError):
        html.encode("cp1252")


def test_writing_it_the_way_main_does_survives_a_cp1252_default(document, tmp_path):
    """The failure, reproduced. `open(path, "w")` on Windows picks cp1252, and
    the run died AFTER twelve legs had completed — the measurements were all
    made and then thrown away at the last step."""
    html = report.build(document, None, None, None, None)
    out = tmp_path / "report.html"
    with open(out, "w", encoding="utf-8") as handle:
        handle.write(html)
    assert out.read_text(encoding="utf-8") == html


def test_main_names_an_encoding_rather_than_taking_the_platform_default():
    """Read from the source, because the point is that no test on Linux can
    tell the difference at runtime — the default there is already UTF-8."""
    import inspect
    source = inspect.getsource(report.main)
    for opened in re.findall(r'open\([^)]*\)', source):
        assert "encoding=" in opened, opened
