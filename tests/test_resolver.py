"""Logs-index routing resolver (catalog/resolver.py) — Layer 2 of the chain.

All offline: the supported-logs page fetch is monkeypatched, so these never
touch the network (CI-safe)."""

from pylon.catalog import resolver

# A supported-logs page whose categories all route to AzureDiagnostics (the
# common case — Key Vault, AKS, most resources), in the exact doc markdown shape.
FIXTURE_AZ_DIAG = """# Some Service Log Categories

|Category|Costs to export|Log table|[basic](/x)|[transform](/y)|Example queries|
|---|---|---|---|---|---|
|Audit Events|No|[AzureDiagnostics](/azure/azure-monitor/reference/tables/azurediagnostics)<p>Logs from multiple Azure resources.|No|No|[Queries](/q)|
|Request Logs|Yes|[AzureDiagnostics](/azure/azure-monitor/reference/tables/azurediagnostics)<p>Logs from multiple Azure resources.|No|No|[Queries](/q)|

## Next Steps
"""

# A page that DOES name a resource-specific table (e.g. API Management).
FIXTURE_RESOURCE_SPECIFIC = """|Category|Costs to export|Log table|[basic](/x)|[transform](/y)|Example queries|
|---|---|---|---|---|---|
|Gateway Logs|No|[APIMGatewayLogs](/azure/azure-monitor/reference/tables/apimgatewaylogs)<p>Gateway.|No|No|[Q](/q)|
"""


def _fake_fetch(md):
    async def _fetch(url):  # signature match for _fetch_cached
        return md
    return _fetch


# ── parsing ───────────────────────────────────────────────────────────────────

def test_parse_categories_azure_diagnostics():
    cats = resolver.parse_categories(FIXTURE_AZ_DIAG)
    assert [c.name for c in cats] == ["Audit Events", "Request Logs"]
    assert all(c.table == "AzureDiagnostics" for c in cats)
    assert cats[0].costs_to_export is False and cats[1].costs_to_export is True


def test_parse_categories_resource_specific_table():
    cats = resolver.parse_categories(FIXTURE_RESOURCE_SPECIFIC)
    assert cats[0].table == "APIMGatewayLogs"


def test_parse_categories_no_table_returns_empty():
    assert resolver.parse_categories("# just prose, no table") == []


def test_slug_from_url():
    url = "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-keyvault-vaults-logs"
    assert resolver._slug_from_url(url) == "microsoft-keyvault-vaults-logs"
    assert resolver._slug_from_url("https://example.com/nope") is None


# ── deriving surfaces ─────────────────────────────────────────────────────────

def test_derived_surfaces_collapses_azure_diagnostics():
    cats = resolver.parse_categories(FIXTURE_AZ_DIAG)
    surfaces = resolver.derived_surfaces("Microsoft.CognitiveServices/accounts", cats)
    assert len(surfaces) == 1
    s = surfaces[0]
    assert s.table == "AzureDiagnostics"
    assert s.mode == "azure-diagnostics"
    assert "MICROSOFT.COGNITIVESERVICES" in s.note  # provider scoping hint


def test_derived_surfaces_keeps_resource_specific_table():
    cats = resolver.parse_categories(FIXTURE_RESOURCE_SPECIFIC)
    surfaces = resolver.derived_surfaces("Microsoft.ApiManagement/service", cats)
    assert any(s.table == "APIMGatewayLogs" and s.mode == "resource-specific" for s in surfaces)


def test_derived_surfaces_empty_when_no_categories():
    assert resolver.derived_surfaces("Microsoft.Foo/bars", []) == []


# ── end-to-end route decision (fetch monkeypatched) ───────────────────────────

def test_route_uncurated_resource_goes_to_azure_diagnostics(monkeypatch):
    monkeypatch.setattr(resolver, "_fetch_cached", _fake_fetch(FIXTURE_AZ_DIAG))
    decision = resolver.resolve_dataplane_route("Microsoft.CognitiveServices/accounts")
    assert decision is not None
    assert decision.table == "AzureDiagnostics"
    assert decision.resource_specific is False
    assert decision.provider == "Microsoft.CognitiveServices"


def test_route_curated_resource_uses_overlay_without_fetching(monkeypatch):
    # An overlay resource must short-circuit before any network fetch.
    def _boom(url):
        raise AssertionError("should not fetch when an overlay exists")
    monkeypatch.setattr(resolver, "_fetch_cached", _boom)
    decision = resolver.resolve_dataplane_route("key vault")
    assert decision is not None
    assert decision.table == "AZKVAuditLogs"
    assert decision.resource_specific is True


def test_route_unknown_resource_returns_none():
    # Not in the vendored index and no overlay -> no decision (caller errors).
    assert resolver.resolve_dataplane_route("banana vault") is None


# A resource that publishes several resource-specific tables. The security-
# relevant gateway log is listed LAST — the pick must rank it above the
# dev-portal-usage and websocket tables, not take the first the docs list.
_FIXTURE_MULTI_TABLE = """|Category|Costs to export|Log table|[b](/x)|[t](/y)|Example queries|
|---|---|---|---|---|---|
|Developer Portal usage|No|[APIMDevPortalAuditDiagnosticLog](/azure/azure-monitor/reference/tables/apimdevportalauditdiagnosticlog)<p>Portal.|No|No|[Q](/q)|
|WebSocket Connections|No|[ApiManagementWebSocketConnectionLogs](/azure/azure-monitor/reference/tables/apimanagementwebsocketconnectionlogs)<p>WS.|No|No|[Q](/q)|
|ApiManagement Gateway|No|[ApiManagementGatewayLogs](/azure/azure-monitor/reference/tables/apimanagementgatewaylogs)<p>Gateway.|No|No|[Q](/q)|
"""


def test_primary_surface_prefers_security_relevant_table(monkeypatch):
    monkeypatch.setattr(resolver, "_fetch_cached", _fake_fetch(_FIXTURE_MULTI_TABLE))
    d = resolver.resolve_dataplane_route("Microsoft.ApiManagement/service")
    assert d is not None
    assert d.resource_specific is True
    # Gateway log wins the single --service pick despite being listed last.
    assert d.table == "ApiManagementGatewayLogs"
    # All tables are exposed for the "use --resource for full coverage" hint.
    assert set(d.tables) == {
        "APIMDevPortalAuditDiagnosticLog",
        "ApiManagementWebSocketConnectionLogs",
        "ApiManagementGatewayLogs",
    }


def test_friendly_name_reaches_the_generic_route(monkeypatch):
    # #1 + dynamic path together: a friendly name (not the exact type string)
    # resolves through to the AzureDiagnostics generic route with its provider.
    monkeypatch.setattr(resolver, "_fetch_cached", _fake_fetch(FIXTURE_AZ_DIAG))
    d = resolver.resolve_dataplane_route("cognitive services")
    assert d is not None
    assert d.table == "AzureDiagnostics"
    assert d.provider == "Microsoft.CognitiveServices"


_FIXTURE_AZDIAG_QUERIES = """# Queries

### CDN access
```query
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.CDN"
| where OperationName == "Microsoft.Cdn/Profiles/AccessLog/Write"
| project TimeGenerated, httpStatusCode_d
```

### KeyVault put
```query
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "VaultPut"
| project Message
```
"""


def test_azure_diagnostics_samples_scopes_to_provider(monkeypatch):
    import asyncio

    async def _fetch(url):
        return _FIXTURE_AZDIAG_QUERIES

    monkeypatch.setattr(resolver, "_fetch_cached", _fetch)
    cdn = asyncio.run(resolver.azure_diagnostics_samples("Microsoft.Cdn"))
    assert len(cdn) == 1 and "MICROSOFT.CDN" in cdn[0]
    # A provider the doc doesn't cover -> no samples (prompt falls back to categories).
    assert asyncio.run(resolver.azure_diagnostics_samples("Microsoft.CognitiveServices")) == []
