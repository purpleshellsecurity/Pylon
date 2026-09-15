"""The hand-curated data-plane audit operation vocabularies (Key Vault, Storage)."""

from pylon import data_plane_operations as dp


def test_covered_tables():
    assert dp.has_table("AZKVAuditLogs")
    assert dp.has_table("StorageBlobLogs")
    assert not dp.has_table("SomeUncoveredTable")


def test_keyvault_operations():
    assert dp.is_known("AZKVAuditLogs", "SecretGet")
    assert "secret" in dp.describe("AZKVAuditLogs", "SecretGet").lower()
    # SecretGet is exfil-relevant; SecretRestore is not
    assert dp.is_sensitive("AZKVAuditLogs", "SecretGet")
    assert not dp.is_sensitive("AZKVAuditLogs", "SecretRestore")


def test_storage_operations():
    assert dp.is_known("StorageBlobLogs", "GetBlob")
    assert dp.is_sensitive("StorageBlobLogs", "SetContainerACL")  # public-exposure
    ref = dp.reference("StorageBlobLogs", "GetUserDelegationKey")
    assert ref["service"] == "Azure Blob Storage"
    assert ref["verb"] == "crypto"
    assert ref["sensitive"] is True


def test_case_insensitive():
    assert dp.is_known("azkvauditlogs", "secretget")


def test_unknown_operation_falls_through_cleanly():
    # A real-but-uncatalogued op returns empty rather than a false rejection.
    assert not dp.is_known("AZKVAuditLogs", "SecretFooBar")
    assert dp.describe("AZKVAuditLogs", "SecretFooBar") == ""
    assert dp.reference("AZKVAuditLogs", "SecretFooBar") == {}
    # An uncovered table is empty, never an error.
    assert dp.operations("SomeUncoveredTable") == []


def test_operations_listing():
    ops = dp.operations("AZKVAuditLogs")
    assert "SecretGet" in ops and "KeyDecrypt" in ops
    assert len(ops) >= 20


def test_the_vocabulary_holds_the_tables_a_target_can_fire_on_and_no_others():
    """It used to hold ten tables when five could fire. The five extras -- SQL,
    Cosmos, Event Hub / Service Bus, and the two AKS streams -- were for resource
    types the gate refuses, so nothing could ever ask about them. Kubernetes verbs
    ("get, list, create, delete") sat in a shipped catalogue for a service this
    tool cannot support, which is how they reached a prompt in the first place."""
    from pylon.services import all_tables

    reachable = {t for t in all_tables() if t not in ("AzureActivity", "AuditLogs")}
    for table in reachable:
        # A contract's MEASURED values are a vocabulary too -- counted in a
        # workspace rather than harvested from a published reference. That is
        # what `_surface_refusal` accepts, so it is what this must accept.
        from pylon import contracts as _contracts

        measured, _complete = _contracts.vocabulary(table)
        assert dp.has_table(table) or measured, (
            f"{table} can fire and has no vocabulary, harvested or measured")
    for withdrawn in ("SQLSecurityAuditEvents", "CDBDataPlaneRequests",
                      "AZMSRunTimeAuditLogs", "AKSAudit", "AKSAuditAdmin"):
        assert not dp.has_table(withdrawn), (
            f"{withdrawn} is still in the catalogue and no target can fire on it")


def test_storage_data_plane_surfaces_have_distinct_vocab():
    # Each storage service carries its own OperationName vocabulary.
    assert dp.is_sensitive("StorageFileLogs", "GetFile")        # exfil
    assert dp.is_sensitive("StorageQueueLogs", "GetMessages")   # data access
    assert dp.is_sensitive("StorageTableLogs", "QueryEntities") # exfil
    assert dp.reference("StorageFileLogs", "GetFile")["service"].startswith("Azure Files")
    assert dp.field_for("StorageTableLogs") == "OperationName"


def test_the_operation_field_is_asked_for_never_assumed():
    """Every remaining table spells it OperationName, but the lookup stays -- the
    column is a per-table fact and a table that spells it differently is one
    catalogue entry away."""
    assert dp.field_for("AZKVAuditLogs") == "OperationName"
    assert dp.field_for("StorageQueueLogs") == "OperationName"
    assert dp.field_for("UncoveredTable") == ""


