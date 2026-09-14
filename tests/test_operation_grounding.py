"""Unified operation grounding + the catalog-backed validate_operation upgrade."""

from pylon import operation_grounding as og
from pylon.validation import validate_operation


# ── unified dispatch ─────────────────────────────────────────────────────────
def test_control_plane_reference():
    ref = og.reference("AzureActivity", "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE")
    assert ref["plane"] == "control"
    assert "role assignment" in ref["description"].lower()
    assert ref["reverse"]["operation"] == "Microsoft.Authorization/roleAssignments/delete"


def test_data_plane_reference():
    ref = og.reference("AZKVAuditLogs", "SecretGet")
    assert ref["plane"] == "data"
    assert ref["sensitive"] is True
    assert ref["field"] == "OperationName"


def test_no_catalog_key_returns_empty():
    # Entra AuditLogs phrases / sign-ins have no per-op key.
    assert og.reference("AuditLogs", "Add member to role") == {}
    assert og.reference("SigninLogs", "whatever") == {}


def test_grounding_block_text():
    block = og.grounding_block("AzureActivity", "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE")
    assert "Reverse operation (for containment)" in block
    assert og.grounding_block("SigninLogs", "x") == ""  # no catalog -> empty


# ── validate_operation catalog upgrade ───────────────────────────────────────
def test_real_control_plane_op_still_clean():
    assert validate_operation("MICROSOFT.KEYVAULT/VAULTS/WRITE", "AzureActivity") == []


def test_hallucinated_but_well_shaped_op_is_flagged():
    # Correct ARM shape, correct namespace, but not a real operation.
    warnings = validate_operation("MICROSOFT.KEYVAULT/VAULTS/EXFILTRATE", "AzureActivity")
    assert any("provider-operations catalog" in w for w in warnings)


def test_data_plane_known_op_clean_unknown_flagged():
    assert validate_operation("SecretGet", "AZKVAuditLogs") == []
    warnings = validate_operation("GetSecret", "AZKVAuditLogs")  # wrong: should be SecretGet
    assert len(warnings) == 1
    assert "is not a known" in warnings[0]


def test_uncovered_data_plane_table_left_alone():
    assert validate_operation("anything", "SigninLogs") == []
    assert validate_operation("whatever", "FunctionAppLogs") == []


# ── the two catalogs that shipped as "wiring lands next" ─────────────────────


def test_a_directory_action_is_grounded_from_the_entra_catalog():
    """`entra_actions` was imported by nothing in src/pylon while
    CODEBASE-WALKTHROUGH claimed it was fed into prompts. Gated on the catalog's
    own is_known(), so it grounds a real action and nothing else."""
    from pylon.operation_grounding import grounding_block, reference

    ref = reference("AuditLogs", "microsoft.directory/users/create")
    assert ref["plane"] == "directory"
    assert ref["privileged"] is True
    assert "User Administrator" in ref["roles"]
    block = grounding_block("AuditLogs", "microsoft.directory/users/create")
    assert "PRIVILEGED directory action." in block
    # The containment half: entra_actions keys its inverse "action", the other
    # catalogs key it "operation". Reading only one raised KeyError when wired.
    assert "Reverse operation (for containment): microsoft.directory/users/delete" in block


def test_a_graph_permission_scope_is_grounded_from_the_permissions_catalog():
    """Both Graph activity tables carry Scopes (delegated) and Roles
    (application) — the split this catalog models, and the direct key that was
    overlooked."""
    from pylon.operation_grounding import grounding_block, reference

    ref = reference("MicrosoftGraphActivityLogs", "Directory.ReadWrite.All")
    assert ref["plane"] == "graph-permission"
    assert set(ref["planes"]) == {"application", "delegated"}
    block = grounding_block("MicrosoftGraphActivityLogs", "Directory.ReadWrite.All")
    assert "admin consent required" in block
    # Its prose is per-plane, not top level; an empty description here would print
    # "(no description available)" for every scope.
    assert "no description available" not in block


def test_an_entra_auditlogs_phrase_still_has_no_key_and_says_so():
    """AuditLogs.OperationName is a human phrase, not an action string. The gap is
    real; grounding it would need a phrase->action mapping nobody has written, and
    inventing one is worse than returning nothing."""
    from pylon.operation_grounding import reference

    assert reference("AuditLogs", "Add member to role") == {}
    assert reference("AuditLogs", "Update user") == {}


def test_wiring_the_new_catalogs_changed_nothing_that_already_worked():
    """Both are gated on their own membership tests, so an operation that is not
    one of their keys must fall straight through to the previous answer."""
    from pylon.operation_grounding import reference

    assert reference("AZKVAuditLogs", "SecretGet")["plane"] == "data"
    assert reference("AzureActivity", "MICROSOFT.KEYVAULT/VAULTS/WRITE")["plane"] == "control"
    assert reference("SigninLogs", "") == {}
    assert reference("DeviceProcessEvents", "ProcessCreated") == {}


def test_both_catalogs_are_now_imported_by_the_product():
    """The finding was that nothing in src/pylon imported them. This fails if a
    future refactor drops the wiring and leaves the docs claiming it."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "src" / "pylon"
    importers = [
        p.name for p in root.rglob("*.py")
        if p.name not in {"entra_actions.py", "graph_permissions.py"}
        and ("entra_actions" in p.read_text(encoding="utf-8") or "graph_permissions" in p.read_text(encoding="utf-8"))
    ]
    assert "operation_grounding.py" in importers, importers


# ── three states, because "not in the catalog" is two different claims ───────


def test_a_catalogued_operation_is_silent():
    from pylon.provider_operations import KNOWN, coverage

    assert coverage("MICROSOFT.KEYVAULT/VAULTS/DELETE") == KNOWN
    assert validate_operation("MICROSOFT.KEYVAULT/VAULTS/DELETE", "AzureActivity") == []


def test_an_invented_operation_in_a_catalogued_provider_still_warns():
    """The only case carrying evidence: Microsoft.KeyVault has 122 operations
    here, and this is not one of them."""
    from pylon.provider_operations import UNKNOWN, coverage

    op = "MICROSOFT.KEYVAULT/VAULTS/TOTALLYMADEUP/ACTION"
    assert coverage(op) == UNKNOWN
    assert validate_operation(op, "AzureActivity"), "a hallucination must still warn"


def test_a_provider_the_catalog_never_heard_of_does_not_warn():
    """Absence of evidence. The operation catalog and the logs index it is
    checked against come from different places, so one can know a provider the
    other does not. Warning on every operation of a provider we hold nothing for
    is noise that costs the case above its credibility.

    The gap used to be wide: 40 providers, 62 indexed resource types. Harvesting
    from the ARM API instead of the docs took the catalog from 152 providers to
    323 and closed almost all of it -- Microsoft.NetworkCloud, which this test
    used to name, is now covered. One indexed resource type still is not, and it
    is what keeps the third state honestly exercised rather than hypothetical.
    """
    from pylon.provider_operations import PROVIDER_ABSENT, coverage

    op = "MICROSOFT.AGFOODPLATFORM/FARMBEATS/WRITE"
    assert coverage(op) == PROVIDER_ABSENT
    assert validate_operation(op, "AzureActivity") == [], "the catalog cannot judge this"


def test_the_status_is_recorded_even_when_nothing_is_warned():
    """Silent is not the same as clean. `operation_status` reports what the
    catalog could establish, so a gap in the catalog is measurable rather than
    merely quiet — the same distinction as ParseResult.unchecked."""
    from pylon.validation.operation import operation_status

    status, warnings = operation_status(
        "MICROSOFT.AGFOODPLATFORM/FARMBEATS/WRITE", "AzureActivity"
    )
    assert status == "provider-absent" and warnings == []
    status, warnings = operation_status("MICROSOFT.KEYVAULT/VAULTS/DELETE", "AzureActivity")
    assert status == "known" and warnings == []


def test_a_new_nested_model_must_be_checkpoint_registered():
    """OperationCheck hangs off ValidatedDetection, which is checkpointed. An
    unregistered nested type makes the checkpoint fail to DESERIALIZE, and the
    run then silently re-executes the phase it should have replayed — paying
    again for exactly the calls --resume exists to avoid. It warns on stderr and
    stops nothing."""
    from pylon.engine import CHECKPOINT_ALLOWED_TYPES

    assert "pylon.models:OperationCheck" in CHECKPOINT_ALLOWED_TYPES


def test_the_committed_catalog_says_when_it_was_harvested():
    """It used to say nothing, because the shipped file predated the harvester
    stamping a date and nobody was going to invent one. That is now settled: the
    catalog was refreshed from the ARM API and carries the timestamp of the run
    that produced it.

    The date is what makes "this catalog lags reality" a checkable claim rather
    than a feeling. Without it nobody can tell a month from two years, and the
    lag is what decides whether an operation missing from it means anything."""
    from pylon.provider_operations import harvested_at

    stamp = harvested_at()
    assert stamp, "the shipped catalog must say when it was harvested"
    assert stamp.endswith("Z") and stamp[:4].isdigit(), stamp


def test_the_harvester_stamps_a_date_when_it_actually_runs():
    """And the docstring no longer claims byte-for-byte determinism, which the
    timestamp breaks by design: a re-harvest diffs on exactly that line."""
    import pathlib

    src = pathlib.Path("scripts/refresh-provider-operations.py").read_text(encoding="utf-8")
    assert '"harvested": datetime.now(timezone.utc)' in src
    assert "The CONTENT is deterministic" in src
