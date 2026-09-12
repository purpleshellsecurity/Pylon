"""The first-run failure that stopped a real machine.

`az graph query` lives in the `resource-graph` extension. az installs a missing
extension on demand and ASKS first — and under `capture_output=True` there is
no terminal to answer with, so the ask never returns. On a fresh Windows 11
install the first scan sat there until the 60-second bound killed it and
reported "the call did not finish", which is true and no help at all.

Two changes came out of that, and these hold both: the prompt is turned off so
az fails fast instead of hanging, and the failure it then gives is translated
into the one command that fixes it.
"""

import os

from pylon import azcli


def test_dynamic_install_is_off_in_the_environment_az_runs_in():
    """Left on, a missing extension is a hang rather than an error."""
    assert azcli.environment()["AZURE_EXTENSION_USE_DYNAMIC_INSTALL"] == "no"


def test_the_caller_environment_is_carried_through():
    """az needs PATH, HOME and the caller's proxy settings. Replacing the
    environment rather than extending it would break every call."""
    assert azcli.environment()["PATH"] == os.environ["PATH"]


def test_this_process_is_not_modified():
    """A copy, not a mutation. Setting it globally would change behaviour for
    anything else in the process that shells out."""
    azcli.environment()
    assert "AZURE_EXTENSION_USE_DYNAMIC_INSTALL" not in os.environ


def test_az_saying_graph_is_unknown_names_resource_graph():
    assert azcli.missing_extension(
        "'graph' is misspelled or not recognized by the system.") == "resource-graph"
    assert azcli.missing_extension(
        "ERROR: az graph: 'query' is not in the 'az graph' command group."
    ) == "resource-graph"


def test_az_saying_log_analytics_query_is_unknown_names_that_extension():
    """The second one, and the one that produced a report reading "None tables
    with data". `az monitor log-analytics query` is Extension, not Core."""
    assert azcli.missing_extension(
        "ERROR: 'query' is misspelled or not recognized by the system. "
        "az monitor log-analytics query") == "log-analytics"


def test_an_unrelated_failure_is_not_answered_with_extension_advice():
    """The check must be narrow. Telling someone to install an extension when
    their token expired sends them somewhere useless."""
    assert azcli.missing_extension("AADSTS700082: The refresh token has expired") is None
    assert azcli.missing_extension("the call did not finish within 60s") is None


def test_a_failure_merely_containing_the_word_extension_is_not_enough():
    """"extension" appears in plenty of unrelated Azure errors. Both halves
    have to be present: something unknown, and the command that needs it."""
    assert azcli.missing_extension(
        "The resource extension 'foo' could not be provisioned") is None


def test_the_hint_names_the_extension_and_what_it_is_for():
    """A reader who sees this has already been told "not recognized" by az,
    which sent them looking for a typo."""
    hint = azcli.install_hint("log-analytics")
    assert "az extension add --name log-analytics" in hint
    assert "table-activity" in hint
