"""A Graph scope that does not exist fails the script at its first line.

Measured against a live tenant. A generated script demanded
`ServicePrincipal.ReadWrite.All`; Entra answered AADSTS70011, "the scope ... does
not exist", and nothing ran. Two more across the runs are REAL but
application-only, which is invalid in `Connect-MgGraph -Scopes` and fails
identically for a different reason.

Tiers 1-4 all pass these: the cmdlets are real, the parameters are real, the
parameter set resolves. `Find-MgGraphPermission` is the authoritative local
answer and needs no auth, no tenant and no network — the exact counterpart to the
`Get-Command -Module` inventory already used to ground cmdlet names.

There is an irony worth keeping: grounding the CMDLETS probably encouraged this.
`Add-MgServicePrincipalPassword` exists, so `ServicePrincipal.ReadWrite.All`
feels right — and Graph's permission names do not follow its cmdlet nouns.
"""

import pytest

from pylon.validation.script_check import graph_permission_surface, graph_scope_errors

_HAVE_LIST = bool(graph_permission_surface()[0])
_needs_graph = pytest.mark.skipif(
    not _HAVE_LIST, reason="Microsoft.Graph.Authentication not installed"
)


@_needs_graph
def test_a_nonexistent_scope_is_rejected():
    errs = graph_scope_errors("Connect-MgGraph -Scopes 'ServicePrincipal.ReadWrite.All'")
    assert errs and "no such Graph permission" in errs[0]


@_needs_graph
def test_the_declaration_form_is_checked_too():
    """The one that actually bit. The failing script never passed the bad scope to
    Connect-MgGraph — it declared `$requiredScopes = @(...)` and compared it to the
    granted set, while its only Connect-MgGraph line was inside a help string."""
    errs = graph_scope_errors(
        "$requiredScopes = @('Application.ReadWrite.All','ServicePrincipal.ReadWrite.All')"
    )
    assert errs and "no such Graph permission" in errs[0]


@_needs_graph
def test_an_application_only_permission_is_named_as_such():
    """Real, and still wrong here. Telling someone it does not exist would send
    them looking for a typo in a name that is spelled correctly."""
    errs = graph_scope_errors("$requiredScopes = @('Device.ReadWrite.All')")
    assert errs and "APPLICATION permission" in errs[0]


@_needs_graph
@pytest.mark.parametrize(
    "script",
    [
        "Connect-MgGraph -Scopes 'Application.ReadWrite.All','Directory.ReadWrite.All'",
        "$requiredScopes = @('Application.ReadWrite.All')",
    ],
)
def test_valid_scopes_pass(script):
    assert graph_scope_errors(script) == []


@_needs_graph
@pytest.mark.parametrize(
    "script",
    [
        # These scripts PRINT the connect command in their own help text. Matching
        # it captured whole paragraphs as scope names: 38 of 116 scripts "failed".
        'Write-Host "Run: Connect-MgGraph -Scopes \'ServicePrincipal.ReadWrite.All\'"',
        "Connect-MgGraph -Scopes $scopeList",
        "$scopeMsg = 'Reconnect with the required scope please'",
    ],
)
def test_things_that_are_not_scope_declarations_are_ignored(script):
    assert graph_scope_errors(script) == []


@_needs_graph
def test_an_unreadable_permission_list_judges_nothing(monkeypatch):
    """No module, no pwsh, no verdict. Judging a scope against a list that could
    not be read is the same error as treating an empty table-plan map as 'nothing
    is billable'."""
    from pylon.validation import script_check

    monkeypatch.setattr(
        script_check, "graph_permission_surface", lambda: (frozenset(), frozenset())
    )
    assert script_check.graph_scope_errors(
        "Connect-MgGraph -Scopes 'ServicePrincipal.ReadWrite.All'"
    ) == []


def test_the_vendored_reference_is_the_authority_not_the_module():
    """The whole reason this file exists. `Find-MgGraphPermission` answers from the
    INSTALLED module, which knew 344 permissions against the reference's 786 — so a
    checker built on it rejects 460 REAL permissions as nonexistent. A gate that
    fails valid input is worse than the bug it catches, because people learn to
    ignore it."""
    from pylon.validation.script_check import _vendored_permissions

    delegated, application = _vendored_permissions()
    assert len(delegated) > 500, "the vendored reference did not load"
    assert "Application.ReadWrite.All" in delegated
    assert "Device.ReadWrite.All" in application
    assert "Device.ReadWrite.All" not in delegated, "application-only must not be delegated"
    assert "ServicePrincipal.ReadWrite.All" not in delegated | application


def test_a_permission_the_installed_module_does_not_know_still_passes():
    """The measured false positive. `Acronym.Read.All` is current and real; the
    module on the machine this was written for had never heard of it."""
    assert graph_scope_errors("Connect-MgGraph -Scopes 'Acronym.Read.All'") == []


def test_the_vendored_catalog_carries_descriptions():
    """The descriptions are what would have PREVENTED the original bug:
    Application.ReadWrite.All says in so many words that it covers service
    principals, so there was never a need to invent ServicePrincipal.ReadWrite.All.

    Asserted through `graph_permissions`, not by opening a file. This read a
    second, staler harvest of the same vocabulary until that copy was deleted —
    reaching past the module is how a test keeps a duplicate alive.
    """
    from pylon import graph_permissions

    assert graph_permissions._data()["meta"]["source"]
    desc = graph_permissions.describe("Application.ReadWrite.All")
    assert "service principal" in desc.lower()


def test_the_vendored_catalog_is_dated():
    """An undated vendored file cannot be judged stale, and staleness is the whole
    question for a permission reference: a scope Microsoft shipped last month
    reads as fabricated until the harvest catches up.

    The deleted copy carried `captured_at`. The surviving `.gz` carries no date at
    all, so `scripts/refresh-entra-graph-catalogs.py` must stamp one.
    """
    from pylon import graph_permissions

    meta = graph_permissions._data()["meta"]
    assert meta.get("harvested"), "the Graph permission harvest must record its date"
