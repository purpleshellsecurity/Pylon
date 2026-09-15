"""The first number on the screen counted rows that are not resources.

`inventory.run` prints a MEASURED block, and the comment above it states the
rule the whole block follows:

    Every number still comes from the DOCUMENT, not the loose lists. The lists
    say 0 for a leg that never ran, and "analytics rules 0" on an operator's
    screen is the exact claim this project refuses.

The `resources` line broke it. It took `len(resources)`, and that list is every
VERDICT row -- the scope rows ride in it: tenant, subscription, Sentinel
monitoring, one per XDR family. A tenant with three storage accounts was told
it had seven resources.

`summarise.build` filters on `scope == "resource"` and `report.py` does the
same, so the document and the HTML both said three the whole time. Only the
screen was wrong, and it is the half nobody diffs.
"""

import json

import pytest


@pytest.fixture
def scan(tmp_path, monkeypatch, capsys):
    from pylon import inventory, scopes

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(inventory, "resolve_workspace",
                        lambda v: ("t", "/subscriptions/S/ws", ""))
    monkeypatch.setattr(scopes, "defender_plans",
                        lambda sub: {"ran": False, "detail": "no read"})

    def _run(n):
        monkeypatch.setattr(inventory, "query_graph", lambda: [
            {"id": f"/subscriptions/S/rg/r{i}",
             "type": "Microsoft.Storage/storageAccounts",
             "subscriptionId": "S", "location": "eastus", "tags": {}}
            for i in range(n)])
        inventory.run("ws")
        out = capsys.readouterr().out
        doc = json.loads((tmp_path / "analysis.json").read_text(encoding="utf-8"))
        return out, doc

    return _run


def _screen_count(out: str) -> str:
    line = next(ln for ln in out.splitlines() if ln.strip().startswith("resources"))
    return line.split()[-1]


def test_the_screen_counts_resources_not_verdict_rows(scan):
    out, doc = scan(3)
    resource_rows = [r for r in doc["resources"] if r["scope"] == "resource"]
    assert len(resource_rows) == 3
    assert len(doc["resources"]) > 3, "the scope rows must be in the document"
    assert _screen_count(out) == "3", (
        f"the screen counted every verdict row, including the "
        f"{len(doc['resources']) - 3} scope rows")


def test_the_screen_matches_the_summary_the_report_renders(scan):
    out, doc = scan(3)
    assert _screen_count(out) == str(doc["summary"]["resources"])


def test_an_inventory_that_did_not_run_still_says_not_measured(tmp_path, monkeypatch, capsys):
    """The other direction. A zero here would be a claim about the tenant."""
    from pylon import inventory

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(inventory, "query_graph",
                        lambda: (_ for _ in ()).throw(RuntimeError("no az")))
    monkeypatch.setattr(inventory, "resolve_workspace",
                        lambda v: ("t", "/subscriptions/S/ws", "g"))
    inventory.run("ws")
    line = next(ln for ln in capsys.readouterr().out.splitlines()
                if ln.strip().startswith("resources"))
    assert "not measured" in line, line
