"""A Linux VM writes Syslog and never Event.

`PSEUDO_CATEGORY_TABLES` mapped `AgentCollection` to `Event` for every virtual
machine, with a comment above it admitting the real answer is "whatever the data
collection rule's streams are configured to fill" -- and then hardcoding one
table anyway.

Found by comparing what the scan concluded against what Azure returned for a
single VM. Pylon's parse was right (no diagnostic settings, so "never
configured") and its expectation was wrong: the resource was an Ubuntu VM
and the coverage gap named `Event`. Microsoft's own table reference:

    Event    "Events from Windows Event Log on Windows computers"
    Syslog   "Syslog events on Linux computers"

So the finding told someone to enable collection into a table their machine can
never write to. Not a crash, not a wrong count -- advice that cannot be
followed, which is the kind of wrong that survives review.

Two sources of truth, in order. The collection rule's streams are what the agent
actually routes; the operating system is what the machine WOULD fill when no
rule exists. Neither is a guess, and an unknown OS with no streams returns
nothing rather than inventing a table.
"""

import pytest

from pylon import diagnostics
from pylon.tablemap import AGENT_STREAM_TABLES, agent_table

# ── the streams a rule routes are the authoritative answer ───────────────────


@pytest.mark.parametrize("stream,table", sorted(AGENT_STREAM_TABLES.items()))
def test_each_stream_maps_to_its_documented_table(stream, table):
    """Verified against Microsoft's own wording: Windows event data "can only be
    sent to a Log Analytics workspace where it's stored in the Event table"."""
    assert agent_table([stream], None) == [table]


def test_streams_beat_the_operating_system():
    """A rule collecting SecurityEvent on a machine is what that machine sends,
    whatever its OS default would have been."""
    assert agent_table(["Microsoft-SecurityEvent"], "Linux") == ["SecurityEvent"]


def test_every_configured_stream_is_reported():
    assert agent_table(["Microsoft-Syslog", "Microsoft-Perf"], "Linux") == [
        "Perf", "Syslog"]


def test_a_stream_nobody_mapped_falls_back_rather_than_vanishing():
    """An unrecognised stream must not silently produce an empty answer when the
    OS can still say what the machine would fill."""
    assert agent_table(["Microsoft-SomethingNew"], "Linux") == ["Syslog"]


# ── with no rule, the OS decides ─────────────────────────────────────────────


def test_a_linux_vm_with_no_rule_expects_syslog():
    """The case that was wrong. `Event` is Windows-only, so naming it for an
    Ubuntu machine is a gap nobody can close."""
    assert agent_table(None, "Linux") == ["Syslog"]
    assert agent_table([], "linux") == ["Syslog"], "case must not matter"


def test_a_windows_vm_with_no_rule_expects_event():
    assert agent_table(None, "Windows") == ["Event"]


def test_an_unknown_os_names_no_table_at_all():
    """"We do not know which table" and "Event" are different answers, and only
    one of them is true. The same rule the rest of this codebase follows."""
    assert agent_table(None, None) == []
    assert agent_table(None, "") == []


# ── and it reaches the surface the scan builds ───────────────────────────────


@pytest.mark.parametrize("os_type,expected", [
    ("Linux", ["Syslog"]), ("Windows", ["Event"]), (None, []),
])
def test_the_agent_surface_carries_the_right_table(os_type, expected):
    surface = diagnostics._agent_surface("/vm/x", {}, os_type)
    assert surface["agent_tables"] == expected


def test_an_unreadable_rule_still_names_the_os_table():
    """The read failed; the machine's operating system did not become unknown."""
    surface = diagnostics._agent_surface(
        "/vm/x", {"/vm/x": {"readable": False, "rules": []}}, "Linux")
    assert surface["readable"] is False
    assert surface["agent_tables"] == ["Syslog"]


def test_only_rules_reaching_the_target_workspace_count():
    """A rule shipping Syslog somewhere else is not coverage here, so its
    streams must not be read as tables this workspace will receive."""
    dcr = {"/vm/x": {"readable": True, "rules": [
        {"id": "r1", "name": "r1", "streams": ["Microsoft-SecurityEvent"],
         "to_target": False, "destinations": ["other-workspace"]}]}}
    surface = diagnostics._agent_surface("/vm/x", dcr, "Linux")
    assert surface["agent_tables"] == ["Syslog"], (
        "a rule pointing elsewhere must fall back to the OS, not claim its streams")
