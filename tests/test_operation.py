"""Tests for the conservative operation-string sanity check.

The check is warning-only: it must catch structurally-wrong and cross-provider
operations, and must NOT reject legitimate ones (no errors, ever).
"""

from pylon.validation import validate_operation


def test_empty_operation_is_silent():
    assert validate_operation("", "AzureActivity") == []
    assert validate_operation("   ", "AzureActivity", "Microsoft.KeyVault/vaults") == []


def test_non_arm_tables_are_not_shape_checked():
    # Data-plane / sign-in operation names have no single shape — leave them alone.
    assert validate_operation("SecretGet", "AZKVAuditLogs") == []
    assert validate_operation("anything at all", "SigninLogs") == []


def test_well_shaped_operation_matching_provider_has_no_warning():
    warnings = validate_operation(
        "MICROSOFT.KEYVAULT/VAULTS/WRITE", "AzureActivity", "Microsoft.KeyVault/vaults"
    )
    assert warnings == []


def test_bare_verb_is_flagged_as_wrong_shape():
    warnings = validate_operation("delete secret", "AzureActivity")
    assert len(warnings) == 1
    assert "not shaped like an ARM operation" in warnings[0]
    assert "never fire" in warnings[0]


def test_path_without_provider_namespace_is_flagged():
    # Has a slash but no "microsoft.<x>" namespace — still not an ARM operation.
    warnings = validate_operation("vaults/write", "AzureActivity")
    assert len(warnings) == 1
    assert "not shaped like an ARM operation" in warnings[0]


def test_wrong_provider_namespace_warns():
    warnings = validate_operation(
        "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
        "AzureActivity",
        "Microsoft.KeyVault/vaults",
    )
    assert len(warnings) == 1
    # The message echoes both namespaces verbatim (as the caller typed them) so
    # the operator can see the mismatch.
    assert "MICROSOFT.STORAGE" in warnings[0]
    assert "Microsoft.KeyVault" in warnings[0]
    assert "never fires" in warnings[0]


def test_cross_cutting_provider_is_allowlisted():
    # Role assignments / diagnostic settings legitimately apply to ANY resource,
    # so a namespace mismatch against them must NOT warn.
    for op in (
        "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
        "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE",
        "MICROSOFT.RESOURCES/TAGS/WRITE",
    ):
        assert validate_operation(op, "AzureActivity", "Microsoft.KeyVault/vaults") == []


def test_namespace_match_is_case_insensitive():
    warnings = validate_operation(
        "microsoft.keyvault/vaults/delete", "AzureActivity", "MICROSOFT.KEYVAULT/VAULTS"
    )
    assert warnings == []


def test_no_resource_provider_skips_namespace_check():
    # Single-service / free-text runs pass no provider — a well-shaped op is fine.
    assert validate_operation("MICROSOFT.STORAGE/STORAGEACCOUNTS/DELETE", "AzureActivity") == []


def test_check_never_returns_errors_only_warnings():
    # Contract: the return is always a list of strings (warnings), never raises.
    result = validate_operation("garbage", "AzureActivity", "Microsoft.KeyVault/vaults")
    assert isinstance(result, list)
    assert all(isinstance(w, str) for w in result)
