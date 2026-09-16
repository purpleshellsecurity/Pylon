"""The cross-log correlation map + loader."""

from pylon import correlation as co


def test_map_loads_and_covers_the_planes():
    assert co.has_table("SigninLogs")
    assert co.plane("SigninLogs") == "identity"
    assert co.plane("AzureActivity") == "control"
    assert co.plane("AZKVAuditLogs") == "data"
    # every plane in the kill-chain is represented
    for p in co.PLANE_ORDER:
        assert co.tables_in_plane(p), p


def test_case_insensitive_and_uncovered():
    assert co.has_table("azureactivity")
    assert co.for_table("NotATable") == {}
    assert co.actor_fields("NotATable") == []
    assert co.ip_field("NotATable") is None


def test_actor_fields_are_ordered_oid_first():
    fields = co.actor_fields("SigninLogs")
    assert fields[0]["field"] == "UserId" and fields[0]["kind"] == "oid"
    assert any(f["kind"] == "upn" for f in fields)


def test_json_path_and_ip_casing_preserved():
    # AZKVAuditLogs buries the actor in the dynamic Identity column. Its IP is
    # CallerIpAddress — lowercase p; CallerIPAddress is the AzureDiagnostics
    # spelling and this dedicated table does not have it.
    kv = co.actor_fields("AZKVAuditLogs")
    assert kv[0] == {"field": "Identity", "kind": "oid", "json_path": "claim.oid"}
    assert co.ip_field("AZKVAuditLogs") == {"field": "CallerIpAddress"}
    # StorageBlobLogs uses lowercase IP — the two must NOT be conflated.
    assert co.ip_field("StorageBlobLogs") == {"field": "CallerIpAddress"}


def test_the_map_covers_every_table_a_detection_can_fire_on():
    """It drifted both ways at once. Five tables no target could fire on had
    entries, and three that could -- file, queue and table storage -- had none,
    so their playbooks fell back to prose and got no grounded pivot at all."""
    from pylon.services import all_tables

    for table in all_tables():
        assert co.has_table(table), f"{table} can fire and has no correlation entry"
    # AppServiceAuditLogs and FunctionAppLogs were on this list and have earned
    # their way off it: both now carry a measured contract, values counted from
    # real rows, and a correlation entry built from those measurements rather
    # than guessed.
    for withdrawn in ("SQLSecurityAuditEvents", "CDBDataPlaneRequests", "AKSAudit",
                      "AKSAuditAdmin", "AZMSRunTimeAuditLogs", "DeviceLogonEvents"):
        assert not co.has_table(withdrawn), f"{withdrawn} cannot fire and is still mapped"


def test_no_context_table_is_bolted_onto_every_playbook():
    """`context_tables()` was appended to EVERY pivot plan regardless of the fired
    table, so a Key Vault playbook ended with a FunctionAppLogs query -- an
    app-trace log with no operation column, for a resource the alert never
    touched. The entry is gone; the mechanism stays for a table that earns it."""
    assert co.is_detection_source("AzureActivity")
    assert co.context_tables() == []


def test_resource_field_scopes_same_resource_tier():
    assert co.resource_field("AZKVAuditLogs") == {"field": "_ResourceId", "kind": "arm_id"}
    assert co.resource_field("SigninLogs") is None  # identity tables aren't resource-scoped


def test_the_pivot_destinations_stay_even_though_nothing_fires_on_them():
    """SigninLogs and MicrosoftGraphActivityLogs are not targets and must remain
    mapped: a Key Vault detection pivots to them to ask how the actor
    authenticated and what else they called. A destination is not a source."""
    assert co.actor_fields("MicrosoftGraphActivityLogs")[0]["field"] == "UserId"
    assert co.has_table("SigninLogs")


def test_the_four_storage_services_share_their_identity_columns():
    """Measured against each table's schema asset, not assumed from the family
    name -- RequesterObjectId / RequesterUpn / RequesterAppId and CallerIpAddress
    with the lowercase p appear on all four."""
    for table in ("StorageBlobLogs", "StorageFileLogs", "StorageQueueLogs",
                  "StorageTableLogs"):
        fields = [f["field"] for f in co.actor_fields(table)]
        assert fields == ["RequesterObjectId", "RequesterUpn", "RequesterAppId"]
        assert co.ip_field(table)["field"] == "CallerIpAddress"
        assert co.resource_field(table) == {"field": "AccountName", "kind": "name"}
