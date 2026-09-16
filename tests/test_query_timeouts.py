"""A slow tenant must cost one leg, not the scan.

The 2026-09-07 nightly ran `pylon analyze` for 37m58s and was killed by the job
timeout. Eight of the nine legs that read the workspace called `subprocess.run`
with no `timeout=`, so any one of them could block for as long as Azure took.

Two things are asserted here, and the second is the one that matters:

  1. The call is bounded.
  2. A bounded call reports DID NOT RUN, never FOUND NOTHING.

A timeout rendered as an empty result is worse than the hang it replaced -- it
turns "the scan could not look" into "your tenant has no rules firing", which is
an accusation the run did not earn. Every leg's own `returncode != 0` branch
already says the true thing; these tests are what proves a timeout lands there.
"""

import subprocess

import pytest

from pylon import (azcli, coverage, crosscheck, diagnostics, endpoints,
                   products, rulehealth, scopes, sentinelhealth, tables)


@pytest.fixture
def hangs(monkeypatch):
    """`az` that never returns. Raises what a real timeout raises, without
    waiting: `subprocess.run` raises TimeoutExpired once its own clock runs out,
    so a test that actually slept would only be measuring `sleep`."""
    def _timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["az"], timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr(azcli.subprocess, "run", _timeout)
    return _timeout


# ── the runner itself ────────────────────────────────────────────────────────


def test_a_hang_becomes_a_failed_call_not_an_exception(hangs):
    """Callers branch on `returncode != 0`. A raised TimeoutExpired would fly
    past all of them and kill the scan at the first slow query."""
    p = azcli.run(["account", "show"], timeout=1)
    assert p.returncode == azcli.TIMED_OUT
    assert p.returncode != 0
    assert "did not finish" in p.stderr
    assert p.stdout == "", "empty stdout must never accompany a zero return"


def test_a_missing_az_is_reported_rather_than_raised(monkeypatch):
    monkeypatch.setattr(azcli.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("az")))
    p = azcli.run(["account", "show"], timeout=1)
    assert p.returncode == azcli.COULD_NOT_RUN
    assert "could not run az" in p.stderr


def test_every_call_carries_a_bound(monkeypatch):
    """The defect was an absent `timeout=`, so the test is that one is always
    passed -- not that some constant has a particular value."""
    seen = []

    def _capture(cmd, **kwargs):
        seen.append(kwargs.get("timeout"))
        return subprocess.CompletedProcess(cmd, 0, "[]", "")

    monkeypatch.setattr(azcli.subprocess, "run", _capture)
    azcli.run(["account", "show"], timeout=azcli.CONTROL_TIMEOUT)
    azcli.query("guid", "AzureActivity | count")
    assert seen == [azcli.CONTROL_TIMEOUT, azcli.QUERY_TIMEOUT]
    assert all(t and t > 0 for t in seen)


# ── each leg, on a tenant that will not answer ───────────────────────────────


def test_table_activity_says_it_could_not_read(hangs):
    rows, err = tables._query("guid", "union withsource=T * | count")
    assert rows == [] and err, "an unread workspace must carry a reason"
    assert "did not finish" in err


def test_the_connector_differential_says_it_could_not_read(hangs):
    counts, err = crosscheck.live_tables("guid")
    assert counts == {} and err
    assert "did not finish" in err


def test_the_endpoint_census_says_it_could_not_read(hangs):
    rows, err = endpoints._query("guid", "DeviceInfo | take 1")
    assert rows == [] and err
    assert "did not finish" in err


def test_sentinel_health_says_it_could_not_read(hangs):
    rows, err = sentinelhealth._query("guid", "SentinelHealth | take 1")
    assert rows == [] and err
    assert "did not finish" in err


def test_product_coverage_reports_ran_false(hangs):
    """`products.probe` owns its own ReadState, so it can be checked end to end:
    a timeout must leave `ran=False`, not an empty coverage map with ran=True."""
    cover, read = products.probe("guid")
    assert read["ran"] is False
    assert cover == {}


def test_rule_health_reports_a_count_it_did_not_take(hangs):
    """`None` is the count, and it is not zero. Zero would read as "this rule
    matched nothing", which is the never-fires verdict."""
    count, err, code = rulehealth._run("guid", "AzureActivity | take 1")
    assert count is None, "a query that did not run has no row count"
    assert err and code == azcli.TIMED_OUT


def test_the_generic_control_plane_readers_report_the_failure(hangs):
    for module in (scopes, diagnostics):
        rc, out, err = module._az("rest", "--method", "get", "--url", "https://x")
        assert rc != 0, f"{module.__name__} reported success on a hung call"
        assert err


def test_coverage_returns_no_freshness_for_a_query_that_did_not_run(hangs):
    """Known wart, asserted so it is not mistaken for a fix: `_last_seen`
    returns None for BOTH a failed query and a genuinely idle resource, so this
    leg cannot tell them apart. Bounding it stops the hang; separating those two
    answers is a change to its interface and is not made here."""
    assert coverage._last_seen("guid", "AzureActivity", "/r/1") is None


def test_no_call_to_az_escapes_the_bounded_runner():
    """The guard this change should have carried from the start.

    The first pass fixed the nine legs the review named and stopped there,
    because the review said "eight of nine" and that was taken for the whole
    surface. Eleven more `subprocess.run` calls were still unbounded, including
    `query_graph` -- the first read the scan makes -- and both calls in
    `validate`, a verb shipped the same week.

    A count is not a boundary. This walks the AST instead: any `subprocess.run`
    in the package must pass a timeout, and only `azcli` may name `az`.
    """
    import ast
    import pathlib

    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "pylon"
    unbounded, direct = [], []
    for path in sorted(src.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run"
                    and getattr(node.func.value, "id", "") == "subprocess"
                    and "timeout" not in {k.arg for k in node.keywords}):
                unbounded.append(f"{path.name}:{node.lineno}")
            # `az` as the first element of a command list, outside azcli.
            if (isinstance(node, ast.List) and node.elts
                    and isinstance(node.elts[0], ast.Constant)
                    and node.elts[0].value == "az" and path.name != "azcli.py"):
                direct.append(f"{path.name}:{node.lineno}")

    assert not unbounded, (
        "subprocess.run without a timeout — a slow tenant hangs the scan: "
        + ", ".join(unbounded))
    assert not direct, (
        "az invoked outside azcli, so it carries no bound: " + ", ".join(direct))
