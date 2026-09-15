"""Every trigger script must resolve against the installed modules.

A trigger script runs against a live tenant and changes it. A cmdlet or a
parameter that does not exist therefore fails halfway through, after the first
half already happened -- which is how a previous generated script left work to
undo by hand.

`parse_check` answers this without a tenant and without executing anything:
tier 3 resolves each command against the modules the script's own `#Requires`
lines name, and each named parameter against that command's real parameters.
It caught `New-MgDirectoryRoleMemberDirectoryObjectByRef` (does not exist; the
create verb is `New-MgDirectoryRoleMemberByRef`) while these were being written.

Skipped, never failed, when pwsh or the modules are absent -- "not installed"
must not be reported as "does not exist".
"""

from pathlib import Path

import pytest

from pylon.validation.script_check import parse_check

TRIGGERS = sorted((Path(__file__).parent.parent / "scripts" / "triggers").glob("*.ps1"))


def test_there_are_trigger_scripts_to_check():
    assert TRIGGERS, "scripts/triggers/*.ps1 is empty"


@pytest.mark.parametrize("script", TRIGGERS, ids=lambda p: p.stem)
def test_every_cmdlet_and_parameter_exists(script):
    result = parse_check(script.read_text(encoding="utf-8"), "powershell")
    if not result.ran:
        pytest.skip("pwsh or the required modules are not installed")
    assert result.errors == [], "\n".join(result.errors)


@pytest.mark.parametrize("script", TRIGGERS, ids=lambda p: p.stem)
def test_nothing_fires_without_an_explicit_execute_switch(script):
    """A trigger mutates a real tenant, so running it by accident must do
    nothing. The dry-run guard is the only thing standing between a stray
    invocation and a directory change."""
    text = script.read_text(encoding="utf-8")
    assert "[switch]$Execute" in text, "no -Execute switch"
    assert "if (-not $Execute)" in text, "no dry-run guard"
