"""A role GUID that contradicts the name of the variable holding it.

A detection names a role and writes its id as a string literal:

    let UaaRoleId = "f1a07417-d97a-45cb-824c-7a7467783830";

That is Managed Identity Operator. User Access Administrator is
18d7d88d-d35e-4fb5-a5c3-7773c20a72d9. The query parses, passes every other
check here, runs clean against a live workspace, and matches nothing forever.

A string literal is the one thing nothing else could check. Columns are checked
against real schemas, cmdlets against installed modules; a GUID carries no type
a schema can contradict. Two ARM detections shipped with one, and the second was
worse than the first -- `uaa_guid` holding the Owner GUID, on a detection that
verified as healthy because Owner removals do happen in that tenant.
"""

import pytest

from pylon import roles
from pylon.validation.validate_kql import _role_guid_mismatches as issues

UAA = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
MIO = "f1a07417-d97a-45cb-824c-7a7467783830"


# ── the catalogue ────────────────────────────────────────────────────────────

def test_the_catalogue_loaded():
    """Every check below is silent when it did not, so this is what separates
    "nothing was wrong" from "nothing was checked"."""
    assert roles.loaded()
    assert len(roles.ROLES) > 100


@pytest.mark.parametrize("guid,name", [
    (UAA, "User Access Administrator"),
    (OWNER, "Owner"),
    (MIO, "Managed Identity Operator"),
    ("acdd72a7-3385-48ef-bd42-f606fba81ae7", "Reader"),
])
def test_the_well_known_ids_resolve(guid, name):
    assert roles.name_for(guid) == name


def test_a_guid_is_matched_whatever_case_it_was_written_in():
    assert roles.name_for(MIO.upper()) == "Managed Identity Operator"


def test_a_custom_role_guid_is_unknown_not_wrong():
    assert roles.name_for("11111111-2222-3333-4444-555555555555") == ""


# ── reading the variable name ────────────────────────────────────────────────

@pytest.mark.parametrize("identifier", [
    "UaaRoleId", "uaa_role_id", "UserAccessAdminRoleDefinitionId",
    "user_access_administrator_guid", "UAA_GUID",
])
def test_the_spellings_a_model_actually_writes(identifier):
    assert roles.intended(identifier) == "User Access Administrator"


def test_the_longest_alias_wins_so_a_substring_cannot_claim_it():
    """`Owner` is inside `Storage Blob Data Owner`. Resolving to the shorter one
    would report a correct detection as holding the wrong role."""
    assert roles.intended("StorageBlobDataOwnerId") == "Storage Blob Data Owner"


def test_a_name_that_says_nothing_about_a_role_resolves_to_nothing():
    """Almost every binding in a query. Silence here is what keeps the check
    from firing on correct work."""
    for name in ("TimeWindow", "AllowedActors", "LookbackStart", "Props"):
        assert roles.intended(name) == ""


# ── the check ────────────────────────────────────────────────────────────────

def test_the_detection_that_shipped_is_caught():
    found = issues(f'let UaaRoleId = "{MIO}";\nAzureActivity | take 1')
    assert len(found) == 1
    assert "User Access Administrator" in found[0]
    assert "Managed Identity Operator" in found[0]


def test_the_message_gives_the_id_that_should_have_been_used():
    """A finding a reader cannot act on is half a finding."""
    found = issues(f'let UaaRoleId = "{MIO}";\nT')
    assert UAA in found[0]


def test_the_second_one_that_shipped_is_caught():
    """`uaa_guid` holding the Owner id, on a detection that verified healthy
    because Owner removals do happen in that tenant."""
    found = issues(f'let uaa_guid = "{OWNER}";\nT')
    assert len(found) == 1 and "Owner" in found[0]


def test_a_correct_pairing_is_silent():
    assert issues(f'let UaaRoleId = "{UAA}";\nT') == []
    assert issues(f'let OwnerRoleId = "{OWNER}";\nT') == []


def test_an_unknown_guid_is_a_warning_not_an_error():
    """A custom role definition is real and tenant-specific, and this catalogue
    holds only built-ins. Erroring would refuse correct detections."""
    found = issues(f'let OwnerRoleId = "11111111-2222-3333-4444-555555555555";\nT')
    assert len(found) == 1 and found[0].startswith("WARNING: ")
    assert "custom role" in found[0]


def test_a_guid_in_a_comment_is_not_a_binding():
    assert issues(f'// UaaRoleId = "{MIO}"\nT | take 1') == []


def test_a_binding_whose_name_says_nothing_is_left_alone():
    assert issues(f'let TimeWindow = "{MIO}";\nT') == []


def test_an_extend_assignment_is_checked_too():
    found = issues(f'T\n| extend UaaRoleId = "{MIO}"')
    assert len(found) == 1


def test_a_query_with_no_guid_at_all_is_silent():
    assert issues("AzureActivity | where Caller == 'x'") == []


def test_an_unloadable_catalogue_reports_nothing_rather_than_everything(
        monkeypatch):
    """"Could not check" must not render as "checked and clean", and it must
    certainly not render as every detection being wrong."""
    monkeypatch.setattr(roles, "ROLES", {})
    assert issues(f'let UaaRoleId = "{MIO}";\nT') == []
