"""A gate that does not run must not look like a gate that passed.

The offline KQL engine is the only real PARSER in this tool. The static checks
are regexes -- they catch a banned column and a dead literal, and they cannot
tell you a query is well formed. When no endpoint was configured the engine gate
was simply absent from the run log, so a run showed

    gate static: pass
    gate contract: pass
    gate workspace: pass

and nothing to suggest the parser had been skipped. Without a workspace either,
nothing in the run parses KQL at all, and a detection that cannot run ships
looking exactly like one that can. That happened: a generated detection with a
backslash-escaped quote inside a verbatim string reached the report, and the
only reason anyone found out was that the live query failed.

Two things here. The gate records the skip, and the run says once, up front and
before any money is spent, that syntax will not be checked.
"""

import inspect

from pylon import engine

_SOURCE = inspect.getsource(engine)


def test_the_engine_gate_records_a_verdict_even_when_it_does_not_run():
    assert 'skipped=True' in _SOURCE, (
        "the engine gate is absent from the log when no endpoint is configured, "
        "so a reader cannot tell it was skipped from it having passed")
    assert '_gate("engine", vector, kql, True, ran=False' in _SOURCE


def test_skipped_is_rendered_as_its_own_word():
    """`passed` and `skipped` are different answers and were printed the same."""
    assert '"skipped" if detail.get("skipped")' in _SOURCE


def test_the_run_says_up_front_when_nothing_will_parse_the_kql():
    """The gate lines are per detection and after the fact. This is the one that
    reaches someone before they have paid for a run they cannot trust."""
    assert "if not offline_on and not workspace_guid:" in _SOURCE
    assert "syntax will NOT be checked this run" in _SOURCE


def test_the_warning_is_not_raised_when_a_workspace_can_catch_it():
    """A live query fails on an unparseable detection, so a workspace run is not
    blind even without the engine. Warning there would train people to ignore
    it."""
    guard = _SOURCE[_SOURCE.index("if not offline_on and not workspace_guid:"):]
    assert "workspace_guid" in guard.splitlines()[0], (
        "the warning must be conditional on there being no workspace either")
