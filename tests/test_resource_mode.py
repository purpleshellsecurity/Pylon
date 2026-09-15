"""Resource-centric generation: request routing, per-vector table selection,
prompt assembly, prerequisites."""

import asyncio

import pytest

from pylon.catalog import resolve_resource
from pylon.catalog.overlay import LogSurface
from pylon.catalog.resolver import resolve_full_surfaces
from pylon.engine import (
    EngineRequest,
    _build_prompt,
    _expected_for_vector,
    _is_resource_mode,
    _prerequisite_for,
    _resource_surfaces,
)
from pylon.models import AttackVector


def _surface(table: str, category: str = "Cat") -> LogSurface:
    return LogSurface(
        table=table, diagnostic_category=category, mode="resource-specific",
        covers=("read", "write"), volume="medium", note="",
    )


def test_resolve_full_surfaces_includes_control_and_data_plane():
    # Key Vault has an overlay -> offline (no network).
    surfaces = asyncio.run(resolve_full_surfaces("Microsoft.KeyVault/vaults"))
    tables = [s.table for s in surfaces]
    assert tables[0] == "AzureActivity"      # control plane first
    assert "AZKVAuditLogs" in tables         # data-plane surface


def test_engine_routes_over_threaded_surfaces_else_overlay():
    # Threaded surfaces (what the CLI resolves) are what generation routes over —
    # this is what makes --resource cover any resource's tables, not just overlays.
    threaded = (_surface("AADDomainServicesPrivilegeUse"), _surface("AADDomainServicesLogonLogoff"))
    req = EngineRequest(resource="Microsoft.AAD/DomainServices", surfaces=threaded)
    assert [s.table for s in _resource_surfaces(req)] == [
        "AADDomainServicesPrivilegeUse", "AADDomainServicesLogonLogoff",
    ]
    # No surfaces threaded -> curated-overlay fallback (back-compat / eval).
    fallback = _resource_surfaces(EngineRequest(resource="Microsoft.KeyVault/vaults"))
    assert "AZKVAuditLogs" in [s.table for s in fallback]


def test_expected_for_vector_uses_threaded_surfaces():
    threaded = (_surface("AADDomainServicesPrivilegeUse"), _surface("AADDomainServicesLogonLogoff"))
    req = EngineRequest(resource="Microsoft.AAD/DomainServices", surfaces=threaded)
    # A vector routed to a threaded table keeps it; an unknown one clamps to the first.
    assert _expected_for_vector(req, _vector("AADDomainServicesLogonLogoff")) == "AADDomainServicesLogonLogoff"
    assert _expected_for_vector(req, _vector("MadeUpTable")) == "AADDomainServicesPrivilegeUse"


def _vector(table: str) -> AttackVector:
    return AttackVector(
        name="v",
        priority="high",
        mitre_technique="T1078.004",
        operation="op",
        log_table=table,
        alert_condition="c",
        rationale="r.",
    )


def test_resolve_resource_aliases_and_types():
    assert resolve_resource("Key Vault") == "Microsoft.KeyVault/vaults"
    assert resolve_resource("aks") == "Microsoft.ContainerService/managedClusters"
    assert resolve_resource("Microsoft.KeyVault/vaults") == "Microsoft.KeyVault/vaults"
    assert resolve_resource("nonsense-xyz") is None


def test_is_resource_mode():
    assert _is_resource_mode(EngineRequest(resource="Microsoft.KeyVault/vaults"))
    assert not _is_resource_mode(EngineRequest(platform="arm", service="Key Vault"))


def test_expected_for_vector_honors_routing_within_resource():
    req = EngineRequest(resource="Microsoft.KeyVault/vaults")
    assert _expected_for_vector(req, _vector("AZKVAuditLogs")) == "AZKVAuditLogs"
    assert _expected_for_vector(req, _vector("AzureActivity")) == "AzureActivity"


def test_expected_for_vector_clamps_out_of_resource_table():
    req = EngineRequest(resource="Microsoft.KeyVault/vaults")
    # StorageBlobLogs is a real table but not one of Key Vault's surfaces ->
    # clamp to the resource's first (control-plane) table.
    assert _expected_for_vector(req, _vector("StorageBlobLogs")) == "AzureActivity"


def test_non_resource_mode_still_pins():
    req = EngineRequest(platform="arm", service="Key Vault")
    assert _expected_for_vector(req, _vector("AZKVAuditLogs")) == "AzureActivity"
    req2 = EngineRequest(platform="dataplane", service="StorageBlobLogs")
    assert _expected_for_vector(req2, _vector("AzureActivity")) == "StorageBlobLogs"


def test_prerequisite_resolves_for_resource_table():
    req = EngineRequest(resource="Microsoft.KeyVault/vaults")
    assert "AuditEvent" in _prerequisite_for(req, "AZKVAuditLogs")
    assert "Activity Log" in _prerequisite_for(req, "AzureActivity")
    # Not resource mode -> no prerequisite
    assert _prerequisite_for(EngineRequest(platform="arm", service="Key Vault"), "AzureActivity") == ""


def test_build_prompt_dispatches_to_resource_builder():
    req = EngineRequest(resource="Microsoft.KeyVault/vaults")
    prompt = _build_prompt(req, "threat")
    assert "<log_source_routing>" in prompt
    assert "Microsoft.KeyVault/vaults" in prompt
    # Non-resource dispatches to the platform builder (no routing block)
    plain = _build_prompt(EngineRequest(platform="arm", service="Key Vault"), "threat")
    assert "<log_source_routing>" not in plain


def test_resource_playbook_requires_target():
    req = EngineRequest(resource="Microsoft.KeyVault/vaults")
    with pytest.raises(ValueError):
        _build_prompt(req, "playbook")
    assert "Vault deletion" in _build_prompt(req, "playbook", playbook_target="Vault deletion")
