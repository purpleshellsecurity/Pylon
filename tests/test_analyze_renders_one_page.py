"""`pylon analyze` writes one page containing every section, and
`--render-only` redraws it without scanning."""

import argparse
import json
import os

import pytest


@pytest.fixture
def scan(tmp_path, monkeypatch):
    from pylon import contenthub, inventory, scopes

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scopes, "defender_plans",
                        lambda sub: {"ran": False, "detail": "no read"})
    monkeypatch.setattr(inventory, "query_graph", lambda: [
        {"id": f"/subscriptions/S/rg/stg{i}",
         "type": "Microsoft.Storage/storageAccounts",
         "subscriptionId": "S", "location": "eastus", "tags": {}}
        for i in range(3)])
    monkeypatch.setattr(contenthub, "build", lambda *a, **k: (
        [{"display_name": "Azure Key Vault", "solution_id": "kv",
          "installed": True, "alignment": "fed", "basis": "b",
          "analytics_rules": 4, "rules_enabled": 1,
          "action": "enable", "action_detail": "none switched on"}],
        {"ran": True, "detail": "1 solution installed"}))

    def _run(workspace_id="/subscriptions/S/rg/providers/ws", render_only=False):
        from pylon import cli
        monkeypatch.setattr(inventory, "resolve_workspace",
                            lambda v: (workspace_id, "my-ws", "guid-1234"))
        return cli._analyze(argparse.Namespace(workspace="ws",
                                               render_only=render_only))

    return _run


def test_one_command_writes_one_page(scan, tmp_path):
    assert scan() == 0
    assert (tmp_path / "telemetry_health_report.html").exists()
    assert not (tmp_path / "content_hub_recommendations.html").exists(), (
        "the second page is back")


def test_content_hub_is_a_section_of_that_page(scan, tmp_path):
    scan()
    html = (tmp_path / "telemetry_health_report.html").read_text(encoding="utf-8")
    assert "Step 6 · Content Hub" in html
    assert "Azure Key Vault" in html


def test_the_page_runs_in_chain_order(scan, tmp_path):
    """Step-numbered sections appear in ascending order."""
    import re

    scan()
    html = (tmp_path / "telemetry_health_report.html").read_text(encoding="utf-8")
    steps = [int(m) for m in re.findall(r'eyebrow">Step (\d)', html)]
    assert steps == sorted(steps), f"sections are out of order: {steps}"


def test_render_only_redraws_without_scanning(scan, tmp_path, monkeypatch):
    from pylon import inventory

    scan()
    (tmp_path / "telemetry_health_report.html").unlink()

    def _must_not_scan(_w):
        raise AssertionError("--render-only scanned the tenant")

    monkeypatch.setattr(inventory, "run", _must_not_scan)
    assert scan(render_only=True) == 0
    assert (tmp_path / "telemetry_health_report.html").exists()


def test_analyze_with_neither_flag_refuses_rather_than_scanning_nothing():
    """Bare `pylon analyze` refuses rather than scanning against None."""
    from pylon import cli
    assert cli._analyze(argparse.Namespace(workspace=None,
                                           render_only=False)) == 2


def test_the_recommend_verb_is_gone():
    from pylon import cli
    sub = [x for x in cli.build_parser()._actions
           if isinstance(x, argparse._SubParsersAction)][0]
    assert "recommend" not in sub.choices
    assert not hasattr(cli, "_recommend")


def test_rendering_makes_no_azure_call():
    """The renderer makes no Azure call."""
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1] / "src" / "pylon"
           / "report.py").read_text(encoding="utf-8")
    for probe in ("azcli", "management.azure.com", "subprocess"):
        assert probe not in src, f"the renderer reaches Azure via {probe}"


# ── the stale sidecar ────────────────────────────────────────────────────────

def test_a_scan_that_makes_no_recommendations_clears_the_old_ones(scan, tmp_path):
    """A scan that produces no recommendations removes the previous scan's
    file."""
    assert scan() == 0
    assert (tmp_path / "recommendations.json").exists()
    assert scan(workspace_id="") == 0
    assert not (tmp_path / "recommendations.json").exists()
    assert (tmp_path / "telemetry_health_report.html").exists()


def test_a_sidecar_that_cannot_be_removed_is_not_fatal(scan, tmp_path, monkeypatch):
    """A stale file that cannot be removed does not fail the scan."""
    scan()
    monkeypatch.setattr(os, "remove", lambda p: (_ for _ in ()).throw(OSError("locked")))
    assert scan(workspace_id="") == 0


def test_a_mismatched_sidecar_drops_the_section_rather_than_the_page(scan, tmp_path):
    """Recommendations from a different scan drop the Content Hub section,
    not the page."""
    from pylon import report

    scan()
    rec = json.loads((tmp_path / "recommendations.json").read_text(encoding="utf-8"))
    rec["analysis_generated_at"] = "1999-01-01T00:00:00Z"
    (tmp_path / "recommendations.json").write_text(json.dumps(rec), encoding="utf-8")
    assert report.main() == 0
    html = (tmp_path / "telemetry_health_report.html").read_text(encoding="utf-8")
    assert "Step 6 · Content Hub" not in html
    assert "Step 1 · Sources" in html
