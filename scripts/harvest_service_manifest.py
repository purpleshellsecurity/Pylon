"""Harvest ONE master service manifest covering all 47 indexed Azure services.

For each resource type in service_logging_docs.json:
  - fetch its supported-logs page  -> the resource-specific tables it emits
  - fetch each table's reference    -> real column names + types

and write it all into src/pylon/catalog/service_manifest.json — the single
"grounding contract" file: for any service, the exact tables/columns that exist,
plus provenance URLs and a `curated` flag for tables that also carry hand-authored
quirks (gotchas / absent-field rules) in the prompt assets.

Re-run to refresh:  python scripts/harvest_service_manifest.py
Docs are fetched through the resolver's cache, so re-runs are cheap.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from pylon.catalog import service_logging_docs
from pylon.catalog.resolver import resolve_full_surfaces
from pylon.grounding import DOCS_BASE, _fetch_cached
from pylon.validation.live_schema import fetch_table_schema
from pylon.validation.schemas import TABLE_SCHEMAS

# Tables that are workspace/routing plumbing, not a service's own log surface.
_SKIP_TABLES = {"AzureActivity", "AzureDiagnostics", "AzureMetrics"}


def _resource_slug(resource_type: str) -> str:
    """Microsoft.KeyVault/vaults -> microsoft-keyvault-vaults (the per-resource-type
    Azure Monitor tables page slug)."""
    return resource_type.lower().replace(".", "-").replace("/", "-")


async def _resource_tables(resource_type: str) -> list[str]:
    """Resource-specific tables for a resource type, from the authoritative
    'Azure Monitor tables for <type>' reference page — a clean | Table | ... |
    grid listing the real tables (NOT the AzureDiagnostics legacy column)."""
    md = await _fetch_cached(f"{DOCS_BASE}/tables/{_resource_slug(resource_type)}.md")
    if not md:
        return []
    start = md.find("| Table ")
    if start == -1:
        return []
    tables: list[str] = []
    for line in md[start:].splitlines()[2:]:  # skip header + |---| separator
        line = line.strip()
        if not line.startswith("|"):
            break
        # First cell is "[TableName](link)<br>description".
        m = re.match(r"\|\s*\[([A-Za-z0-9_]+)\]", line)
        if m and m.group(1) not in _SKIP_TABLES and m.group(1) not in tables:
            tables.append(m.group(1))
    return tables

CATALOG = Path(__file__).resolve().parent.parent / "src" / "pylon" / "catalog"
OUT = CATALOG / "service_manifest.json"          # combined master (runtime reads this)
PARTS = CATALOG / "service_manifests"            # per-service files (reviewable source)
_CURATED = set(TABLE_SCHEMAS)
_SEM = asyncio.Semaphore(8)


async def _schema(table: str) -> dict[str, str]:
    async with _SEM:
        try:
            return await asyncio.wait_for(fetch_table_schema(table), timeout=30)
        except Exception:  # noqa: BLE001 - best-effort harvest; a miss just yields no columns
            return {}


async def _one_service(resource_type: str, entries: list[dict]) -> tuple[str, dict]:
    # Primary: authoritative per-resource-type Azure Monitor tables page.
    page_tables = await _resource_tables(resource_type)
    # Secondary: the tool's own resolver (overlay + derived) catches tables the
    # tables page misses — e.g. storage StorageBlobLogs, or KV/AKS via overlay.
    try:
        surfaces = await asyncio.wait_for(resolve_full_surfaces(resource_type), timeout=30)
    except Exception:  # noqa: BLE001
        surfaces = []
    resolver_tables = [
        s.table for s in surfaces if s.table and s.table not in _SKIP_TABLES
    ]
    # Union, page first, de-duped.
    table_names = list(dict.fromkeys(page_tables + resolver_tables))
    schemas = await asyncio.gather(*(_schema(t) for t in table_names))

    tables: dict[str, dict] = {}
    for table, cols in zip(table_names, schemas):
        tables[table] = {
            "columns": cols,          # {name: type} straight from the table doc
            "curated": table in _CURATED,
        }
    # One resource type can back multiple products (App Service + Functions);
    # keep each product's provenance URLs.
    first = entries[0]
    out = {
        "service_name": first.get("service_name"),
        "products": [e.get("product") for e in entries],
        "sources": {
            "resource_tables_page": f"{DOCS_BASE}/tables/{_resource_slug(resource_type)}",
            "supported_logs_reference": first.get("supported_logs_reference"),
            "monitoring_data_reference": first.get("monitoring_data_reference"),
            "dedicated_logging_page": first.get("dedicated_logging_page"),
            "monitor_page": first.get("monitor_page"),
        },
        "tables": tables,
    }
    # Genuinely no resource-specific table on the tables page -> AzureDiagnostics-only.
    if not tables:
        out["routing"] = "AzureDiagnostics"
    return resource_type, out


async def main() -> None:
    docs = service_logging_docs()  # resource_type(lower) -> [entries]
    # Preserve original casing from the entries.
    by_rt: dict[str, list[dict]] = {}
    for entries in docs.values():
        by_rt[entries[0]["resource_type"]] = entries

    results = await asyncio.gather(*(_one_service(rt, e) for rt, e in by_rt.items()))
    services = dict(sorted(results))

    n_tables = sum(len(s["tables"]) for s in services.values())
    n_cols = sum(len(t["columns"]) for s in services.values() for t in s["tables"].values())
    metadata = {
        "purpose": "Master grounding contract: per Azure service, the exact tables and "
        "columns (harvested from the per-resource-type Azure Monitor tables pages) plus "
        "provenance. The allowlist the model is bound to when building detections "
        "and playbooks.",
        "services": len(services),
        "tables": n_tables,
        "columns": n_cols,
        "note": "Harvested by scripts/harvest_service_manifest.py from "
        "{DOCS_BASE}/tables/<resource-type>. 'curated' tables also carry hand-authored "
        "quirks in prompts/assets/tables/. Re-run to refresh.",
    }

    # 1) Per-service files (reviewable, hand-tunable source).
    PARTS.mkdir(parents=True, exist_ok=True)
    for rt, svc in services.items():
        (PARTS / f"{_resource_slug(rt)}.json").write_text(
            json.dumps({"resource_type": rt, **svc}, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    # 2) Combined master (what the runtime loads).
    OUT.write_text(
        json.dumps({"metadata": metadata, "services": services}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {OUT}")
    print(f"  + {len(services)} per-service files under {PARTS}")
    print(f"  services: {len(services)}   tables: {n_tables}   columns: {n_cols}")
    empty = [rt for rt, s in services.items() if not s["tables"]]
    if empty:
        print(f"  AzureDiagnostics-only (no resource-specific table) ({len(empty)}): {', '.join(empty)}")


if __name__ == "__main__":
    asyncio.run(main())
