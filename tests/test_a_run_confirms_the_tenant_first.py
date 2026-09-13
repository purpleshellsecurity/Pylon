"""A detection run confirms the tenant before it spends anything.

`design detections` used to warn that no scan had been run and then build
anyway. Every detection it produced carried "No scan was run" where its table
basis belongs, which is the tool paying for work it has already said it cannot
check. Worse, a detection over a table holding no rows cannot be graded at all,
so the run ends with a page full of unproven verdicts and no way to tell an
attack that did not happen from a table nobody enabled.

So the order is: confirm the tenant, then build. `--unconfirmed-tables` is the
way to say "this service is not deployed yet and I want the query anyway",
which is a real thing to want and has to be asked for.

`design plan` is deliberately NOT gated. Phase 1 builds nothing and costs one
call; refusing to show someone the offer because their tenant is unscanned
would be gating the cheap half on the expensive half.
"""

import argparse

import pytest

from pylon import cli

_TABLES = ["AzureActivity"]


def test_no_scan_at_all_refuses_and_says_which_command_fixes_it():
    why = cli._unconfirmed(None, _TABLES)
    assert why, "a run with no scan must not proceed"
    assert "pylon analyze" in why, "the refusal must name the command that fixes it"
    assert "--unconfirmed-tables" in why, "and the way to proceed anyway"


def test_a_scan_that_found_no_rows_in_the_table_refuses_and_names_it():
    """The expensive case. The scan ran, so the tool KNOWS the table is empty,
    and building over it produces detections nothing can grade."""
    why = cli._unconfirmed(frozenset({"AuditLogs"}), ["AZKVAuditLogs"])
    assert why
    assert "AZKVAuditLogs" in why, "name the table, do not make the reader guess"


def test_a_confirmed_table_proceeds():
    assert cli._unconfirmed(frozenset({"AzureActivity"}), _TABLES) == ""


def test_one_confirmed_table_is_enough_for_a_two_plane_target():
    """Key Vault reads AzureActivity and AZKVAuditLogs. Control-plane data with
    no data-plane logging is a normal tenant, and the control-plane half of that
    run is gradable. Refusing it would refuse the half that works."""
    assert cli._unconfirmed(frozenset({"AzureActivity"}),
                            ["AzureActivity", "AZKVAuditLogs"]) == ""


def _ran(monkeypatch, **kw) -> int:
    """`design detections` as far as the gate, with the scan stubbed."""
    from pylon import deployed
    monkeypatch.setattr(deployed, "from_analysis",
                        lambda *a, **k: (kw.pop("have", None), "stubbed"))
    args = argparse.Namespace(
        target=["Microsoft.Insights/diagnosticSettings"], source="", out=None,
        max_cost=1.0, max_tokens=0, workspace="", verify_window="",
        **{"pick": "all", "unconfirmed_tables": False, **kw})
    return cli._design_detections(args)


def test_the_gate_is_reached_from_the_command_not_just_the_helper(monkeypatch):
    """The helper being right is worth nothing if nothing calls it. This is the
    check that failed us before -- a value computed correctly in one place and
    never carried to the next."""
    assert _ran(monkeypatch) == 2


def test_the_flag_lets_a_run_proceed_unconfirmed(monkeypatch, capsys):
    """It goes on to fail at the model call, which the suite blocks. That is a
    different refusal and it proves the gate is not what stopped it."""
    _ran(monkeypatch, unconfirmed_tables=True)
    assert "refusing to build" not in capsys.readouterr().err


def test_plan_only_is_not_gated(monkeypatch, capsys):
    """`pick="none"` is how `design plan` routes through this function. Phase 1
    builds nothing, so gating it would gate the cheap half on the expensive."""
    _ran(monkeypatch, pick="none")
    assert "refusing to build" not in capsys.readouterr().err
