"""The vendored Azure provider-operations reference (control-plane)."""

import pytest

from pylon import provider_operations as po


@pytest.fixture(autouse=True)
def _no_stub_survives_its_test():
    """The loaders are lru_cached, so a test that monkeypatches `_data` and warms
    the cache leaves its STUB behind for everything after it. monkeypatch undoes
    the attribute and cannot undo the cache.

    That is what happened: four tests below stub a two-operation catalog, and the
    real-catalog tests that ran after them saw those two operations and returned
    empty sets. The failure reads as a broken filter, and the filter was fine.

    Autouse rather than per-test, so the next person adding a stub cannot
    reintroduce it by forgetting.
    """
    def clear():
        # Teardown runs while a monkeypatched `_data` is still in place, and a
        # plain lambda has no cache_clear. Guarded rather than ordered, because
        # relying on fixture teardown order is how this comes back.
        for name in ("_data", "_ops_ci", "_covered_providers"):
            fn = getattr(po, name, None)
            if hasattr(fn, "cache_clear"):
                fn.cache_clear()

    clear()
    yield
    clear()


def test_catalog_loads_full_surface():
    data = po._data()
    # Sourced from ~150 providers / ~18k operations; use floors so a docs
    # refresh that adds operations never breaks the test.
    assert data["meta"]["providers"] >= 150
    assert data["meta"]["operations"] >= 18000
    assert len(data["operations"]) == data["meta"]["operations"]


def test_describe_known_operation():
    desc = po.describe("Microsoft.Authorization/roleAssignments/write")
    assert "role assignment" in desc.lower()


def test_lookup_is_case_insensitive():
    # AzureActivity logs OperationNameValue in upper case.
    upper = "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
    assert po.is_known(upper)
    assert po.describe(upper) == po.describe("Microsoft.Authorization/roleAssignments/write")


def test_unknown_operation():
    assert not po.is_known("Microsoft.Fake/widgets/frobnicate")
    assert po.describe("Microsoft.Fake/widgets/frobnicate") == ""
    assert po.reference("Microsoft.Fake/widgets/frobnicate") == {}
    assert po.reverse("Microsoft.Fake/widgets/frobnicate") is None


def test_reverse_is_the_real_inverse_sibling():
    # write -> delete, and the delete sibling genuinely exists in the catalog.
    rev = po.reverse("Microsoft.Authorization/roleAssignments/write")
    assert rev is not None
    assert rev[0] == "Microsoft.Authorization/roleAssignments/delete"
    assert "delete" in rev[1].lower()


def test_reverse_none_when_no_sibling():
    # A read has no inverse verb, so no reverse is proposed.
    assert po.reverse("Microsoft.Authorization/roleAssignments/read") is None


def test_reference_block_shape():
    ref = po.reference("Microsoft.AAD/domainServices/write")
    assert ref["operation"] == "Microsoft.AAD/domainServices/write"
    assert ref["description"]
    assert ref["service"] == "Microsoft Entra Domain Services"
    assert ref["reverse"]["operation"] == "Microsoft.AAD/domainServices/delete"


def test_service_for_provider():
    assert po.service_for("Microsoft.Storage/storageAccounts/listkeys/action") == po.service_for(
        "microsoft.storage/foo/read"
    )


class TestTheCatalogHasTwoShapesAndBothStayReadable:
    """The harvester used to write `operation -> description`, a bare string.
    Harvested from the ARM API it writes a dict carrying isDataAction,
    displayName and resourceType too.

    Both shapes have to load, because the shipped file is the old one until
    someone with an Azure login re-harvests, and a reader that only understands
    the new shape would break every install in between.
    """

    def test_a_string_entry_still_answers_describe(self, monkeypatch):
        monkeypatch.setattr(po, "_data", lambda: {
            "operations": {"Microsoft.Test/things/read": "Reads a thing."},
            "providers": {"Microsoft.Test": "Test"},
        })
        po._ops_ci.cache_clear()
        assert po.describe("Microsoft.Test/things/read") == "Reads a thing."
        assert po.is_known("Microsoft.Test/things/read")

    def test_a_string_entry_says_it_does_not_know_the_new_fields(self, monkeypatch):
        """None is not False. `isDataAction` decides which log a detection
        queries, so "the catalog predates this field" and "Azure says control
        plane" must never render the same."""
        monkeypatch.setattr(po, "_data", lambda: {
            "operations": {"Microsoft.Test/things/read": "Reads a thing."},
            "providers": {"Microsoft.Test": "Test"},
        })
        po._ops_ci.cache_clear()
        assert po.is_data_action("Microsoft.Test/things/read") is None
        assert po.resource_type("Microsoft.Test/things/read") == ""

    def test_a_dict_entry_carries_the_new_fields(self, monkeypatch):
        monkeypatch.setattr(po, "_data", lambda: {
            "operations": {"Microsoft.Test/things/getThing/action": {
                "description": "Gets a thing.", "displayName": "Get Thing",
                "isDataAction": True, "resourceType": "things"}},
            "providers": {"Microsoft.Test": "Test"},
        })
        po._ops_ci.cache_clear()
        assert po.describe("Microsoft.Test/things/getThing/action") == "Gets a thing."
        assert po.is_data_action("Microsoft.Test/things/getThing/action") is True
        assert po.resource_type("Microsoft.Test/things/getThing/action") == "things"

    def test_an_unknown_operation_is_unknown_in_both_directions(self, monkeypatch):
        monkeypatch.setattr(po, "_data", lambda: {
            "operations": {}, "providers": {}})
        po._ops_ci.cache_clear()
        assert po.is_data_action("Microsoft.Test/nope") is None
        assert po.resource_type("Microsoft.Test/nope") == ""


class TestScopingByResourceTypeRatherThanProvider:
    """A design target names a RESOURCE TYPE and the catalog is keyed by
    operation, so "Network Security Group" was being read as all of
    Microsoft.Network: 750 control-plane writes across 249 resource types, of
    which NSGs are six. Load balancers, DNS zones and VPN gateways under the name
    "Network Security Group".

    Matching on Azure's own resourceType field is what makes the target mean what
    it says. Across the ten ARM targets it takes 2,024 operations down to 618.
    """

    def test_a_target_gets_its_own_resource_type_and_not_its_provider(self):
        nsg = po.control_plane_operations("Microsoft.Network/networkSecurityGroups")
        assert nsg, "no NSG operations found"
        assert len(nsg) < 30, f"still provider-scoped: {len(nsg)}"
        assert any("networkSecurityGroups/delete" in o for o in nsg)
        assert not any("loadBalancers" in o or "dnsZones" in o for o in nsg)

    def test_sub_types_come_with_the_parent(self):
        """A security rule change IS a change to the NSG. Nobody thinks of them
        as separate surfaces, so asking for the parent returns both."""
        nsg = po.control_plane_operations("Microsoft.Network/networkSecurityGroups")
        assert any("securityRules" in o for o in nsg)

    def test_reads_and_data_actions_are_excluded(self):
        """AzureActivity records neither. A data action lands in the resource's
        own audit log, and this catalog's note says reads are not recorded here
        at all."""
        kv = po.control_plane_operations("Microsoft.KeyVault/vaults")
        assert not any(o.rsplit("/", 1)[-1].lower() == "read" for o in kv)
        assert not any(po.is_data_action(o) for o in kv)

    def test_a_small_answer_is_a_real_answer(self):
        """Role assignment is two operations, write and delete. That is the
        entire ARM privilege-escalation surface, and a result this small reads as
        a bug when it is the point of scoping properly."""
        roles = po.control_plane_operations("Microsoft.Authorization/roleAssignments")
        assert len(roles) == 2, sorted(roles)
        assert {o.rsplit("/", 1)[-1].lower() for o in roles} == {"write", "delete"}

    def test_an_unseen_resource_type_is_empty_not_wrong(self):
        assert po.control_plane_operations("Microsoft.Nope/things") == set()
