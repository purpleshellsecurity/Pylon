#!/usr/bin/env python3
"""Vendor every table's real column TYPES from Azure Monitor's table reference.

`validation/schemas.py` carries column NAMES only. Everything downstream that
needs a type therefore assumed `string`, and `kusto_offline` builds its empty
`datatable` from exactly that. Two consequences, both of which make the offline
KQL engine useless until this exists:

  * a real column the name list omits fails as "unresolved". AzureActivity's
    reference carries 37 columns and the validator claimed 16, so a query using
    `EventDataId` -- a real column -- would be rejected by a gate that is
    supposed to catch fabricated ones.
  * a `dynamic` column declared `string` breaks the queries that matter.
    AuditLogs `InitiatedBy`, `TargetResources` and `AdditionalDetails` are all
    dynamic, and the Entra rules require extracting from `InitiatedBy` before an
    `mv-expand` over `TargetResources`. Declared as strings, every one of those
    queries fails for a reason that has nothing to do with the detection.

A gate that fires on correct queries gets ignored, so this has to be right
before kustainer is switched on at all.

The reference parser lives in `audit-table-schemas.py` and is imported rather
than copied -- that script already treats these pages as the authority, and two
parsers for one page is how the two copies drift.

Network, no credentials. Writes src/pylon/catalog/table-column-types.json.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from urllib.request import ProxyHandler, build_opener, getproxies

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "src" / "pylon" / "catalog" / "table-column-types.json"


def _audit_module():
    """The reference fetcher/parser, as ONE definition."""
    path = Path(__file__).with_name("audit-table-schemas.py")
    spec = importlib.util.spec_from_file_location("auditmod", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["auditmod"] = module          # dataclasses need it importable
    spec.loader.exec_module(module)
    return module


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    from pylon.validation.schemas import TABLE_SCHEMAS

    audit = _audit_module()
    opener = build_opener(ProxyHandler(getproxies()))

    out: dict[str, dict[str, str]] = {}
    missing: list[str] = []
    for table in sorted(TABLE_SCHEMAS):
        try:
            markdown = audit.fetch(table, opener)
        except Exception as exc:  # noqa: BLE001 - one bad page must not stop the run
            print(f"  ! {table}: {exc}", file=sys.stderr)
            missing.append(table)
            continue
        if not markdown:
            print(f"  - {table}: no reference page (404)", file=sys.stderr)
            missing.append(table)
            continue
        ref = audit.parse_reference(markdown)
        if not ref:
            print(f"  - {table}: reference page carries no column table", file=sys.stderr)
            missing.append(table)
            continue
        out[table] = dict(sorted(ref.items()))
        claimed = len(TABLE_SCHEMAS[table])
        dynamic = sum(1 for t in ref.values() if t == "dynamic")
        print(f"  {table:34} {len(ref):3} columns "
              f"({dynamic} dynamic), name list had {claimed}")

    OUT.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nwrote {OUT.relative_to(ROOT)}: {len(out)} tables")
    if missing:
        # Named, not silent. A table with no types falls back to all-string,
        # which is the bug this file exists to remove.
        print(f"no types for {len(missing)}: {', '.join(missing)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
