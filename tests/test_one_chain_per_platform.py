"""Three platforms, three prompt chains, and nothing behind a door with no handle.

The tool used to route prompts down six chains. Four of them served tables no
target can select any more: `signin` (the four Entra sign-in tables),
`graph_activity` (the two Graph API access tables), `defender-endpoint` (the
Device* tables), and the combined "bundle" mode, where one `--service` name stood
for a SET of tables and the model tagged each attack vector with one of them.

None of that was reachable, and unreachable is not harmless. The Entra bundle
still told the model to route vectors to MicrosoftGraphActivityLogs, which the
engine then clamped back to AuditLogs — a vector spent on a table the run could
not produce, in a prompt nobody could see the effect of, because no test could
reach the path either.

These tests fail if a chain outlives its tables again.
"""

import pathlib

import pytest

from pylon import prompts
from pylon.prompts.shared import CONTAINMENT_CMD, LOG_SOURCE, QUERY_RULES

_ASSETS = pathlib.Path(prompts.__file__).parent / "assets"
_LIVE = {"arm", "dataplane", "entra"}
# `azure-diagnostics` is a builder, not a chain: it has no asset directory and is
# reached by table name rather than by platform.
_RULES_ONLY = {"azure-diagnostics"}

# From the catalogue, not from `PLATFORMS[*].services`. Those tuples were emptied
# for `arm` and `dataplane` when the catalogue took over deciding what a run can
# be aimed at, and this list silently became one row -- so both parametrized
# checks below stopped covering anything and stayed green saying so.
from conftest import live_targets, prompt_for  # noqa: E402

_TARGETS = live_targets()
_IDS = [key for key, _t, _tbl in _TARGETS]


def test_there_are_targets_to_check():
    """A parametrize over a shrinking list is green all the way to empty."""
    assert len(_TARGETS) >= 10, f"only {len(_TARGETS)} targets reached"


def test_the_chains_on_disk_are_the_chains_in_use():
    on_disk = {d.name for d in _ASSETS.iterdir() if d.is_dir()} - {"tables"}
    assert on_disk == _LIVE, (
        f"asset directories {sorted(on_disk)} but live chains {sorted(_LIVE)}. "
        "An asset nothing loads is a prompt nobody reviews."
    )


@pytest.mark.parametrize("mapping,name", [
    (LOG_SOURCE, "LOG_SOURCE"),
    (QUERY_RULES, "QUERY_RULES"),
    (CONTAINMENT_CMD, "CONTAINMENT_CMD"),
])
def test_no_shared_fragment_is_keyed_to_a_dead_chain(mapping, name):
    extra = set(mapping) - _LIVE - _RULES_ONLY
    assert not extra, f"{name} still carries {sorted(extra)}"


def test_the_kql_rules_carry_no_chain_a_run_cannot_reach():
    """`_KQL_RULES` was the one rules map this file did not check, and it held
    four chains -- acr, aks, backup, firewall -- 2,739 characters of KQL guidance
    for tables withdrawn with the platforms that used them. `_chain_for` returns
    the platform id, so nothing could ever index them."""
    assert set(prompts._KQL_RULES) == _LIVE, sorted(prompts._KQL_RULES)


def test_the_table_rules_map_is_exactly_the_tables_on_offer():
    """The same drift one level down. Eighteen of its twenty-five rows named a
    table no target can select, so `table_rules` carried routing for the AKS,
    firewall, container-registry and backup tables long after the last thing
    that could ask for them was gone."""
    from pylon.services import all_tables

    # AzureDiagnostics is the one legitimate exception and it is not drift.
    # `all_tables()` is "every table a REGISTERED TARGET can query", and the
    # shared table is not reached that way -- it is reached through the dynamic
    # resource route, which resolves a resource type to its surfaces at run time
    # and lands on AzureDiagnostics whenever the service has no dedicated table
    # or is left on the default destination mode. SQL and Automation both get
    # there and neither is in `targets()`.
    on_offer = all_tables() | {"AzureDiagnostics"}
    assert set(prompts._TABLE_RULES_KEY) == on_offer, (
        f"map has {sorted(set(prompts._TABLE_RULES_KEY) ^ on_offer)} that the "
        f"catalogue and the map disagree about"
    )


@pytest.mark.parametrize("key,target,table", _TARGETS, ids=_IDS)
def test_every_target_lands_on_a_live_chain(key, target, table):
    platform = "arm" if target.resource_type else "entra"
    assert prompts._chain_for(platform, table) in _LIVE


@pytest.mark.parametrize("key,target,table", _TARGETS, ids=_IDS)
def test_no_prompt_names_a_table_no_target_can_select(key, target, table):
    """The check that would have caught it: read the built prompt, not the code.

    Every one of these names reached a live prompt at some point — the data-plane
    context described eight services when five were on offer, and the Entra
    routing block offered three tables when one was.
    """
    withdrawn = (
        "SigninLogs", "AADNonInteractiveUserSignInLogs",
        "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs",
        "MicrosoftGraphActivityLogs", "AADGraphActivityLogs",
        "SQLSecurityAuditEvents", "CDBDataPlaneRequests", "AZMSRunTimeAuditLogs",
        # FunctionAppLogs and AppServiceAuditLogs were withdrawn for having no
        # grounding and are back: both now have a measured contract and values
        # counted from real rows, which is what the withdrawal was about.
        "AKSAudit", "AKSAuditAdmin",
        "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceLogonEvents",
    )
    for phase in ("threat", "detection", "playbook"):
        # Down the branch `engine._build_prompt` takes for this target: resource
        # mode for a resource type, platform/service for Entra. Building every
        # target through `build_system_prompt` would test a path the tool no
        # longer uses for thirteen of them.
        text = prompt_for(target, phase, "a vector" if phase == "playbook" else None)
        named = [w for w in withdrawn if w in text]
        assert not named, f"{key} {phase} prompt names {named}"
