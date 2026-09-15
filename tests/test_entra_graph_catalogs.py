"""The vendored Entra directory-actions and Graph-permissions references."""

from pylon import entra_actions as ea
from pylon import graph_permissions as gp


# ── Entra directory actions ──────────────────────────────────────────────────
def test_entra_catalog_loads():
    data = ea._data()
    assert data["meta"]["actions"] >= 400
    assert data["meta"]["roles"] >= 60


def test_entra_describe_and_privileged():
    assert ea.describe("microsoft.directory/users/delete") == "Delete users"
    assert ea.is_privileged("microsoft.directory/users/delete")
    # description is clean — the '<br/>[![Privileged label]...]' markup is stripped
    assert "<br/>" not in ea.describe("microsoft.directory/users/delete")
    assert "![" not in ea.describe("microsoft.directory/users/delete")


def test_entra_case_insensitive():
    assert ea.is_known("MICROSOFT.DIRECTORY/USERS/DELETE")


def test_entra_roles_granting():
    roles = ea.roles_granting("microsoft.directory/users/delete")
    assert "User Administrator" in roles


def test_entra_reverse_inverse_sibling():
    rev = ea.reverse("microsoft.directory/servicePrincipals/create")
    assert rev is not None
    assert rev[0] == "microsoft.directory/servicePrincipals/delete"


def test_entra_reference_block():
    # A create action has a real containment inverse (delete); a delete does not
    # (undoing a deletion is recovery, so reverse() returns nothing for it).
    ref = ea.reference("microsoft.directory/users/create")
    assert ref["privileged"] is True
    assert ref["roles"]
    assert ref["reverse"]["action"] == "microsoft.directory/users/delete"


def test_entra_unknown():
    assert not ea.is_known("microsoft.directory/foo/frobnicate")
    assert ea.reference("microsoft.directory/foo/frobnicate") == {}


# ── Graph permissions ────────────────────────────────────────────────────────
def test_graph_catalog_loads():
    assert gp._data()["meta"]["scopes"] >= 800


def test_graph_describe_and_consent():
    assert "directory" in gp.describe("Directory.ReadWrite.All").lower()
    assert gp.admin_consent_required("Directory.ReadWrite.All", "application") is True


def test_graph_case_insensitive():
    assert gp.is_known("directory.readwrite.all")


def test_graph_reference_shape():
    ref = gp.reference("Directory.ReadWrite.All")
    assert ref["scope"] == "Directory.ReadWrite.All"
    assert "application" in ref["planes"]
    assert ref["application"]["id"]  # GUID present


def test_graph_unknown():
    assert not gp.is_known("Not.A.Real.Scope")
    assert gp.reference("Not.A.Real.Scope") == {}
    assert gp.describe("Not.A.Real.Scope") == ""
