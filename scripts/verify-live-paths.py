#!/usr/bin/env python3
"""Exercise the Azure SDK paths the deterministic tests cannot reach.

The test suite fakes every SDK client, so it proves the logic and proves nothing
about the calls. This script makes the real calls, read-only, with NO model calls
and NO generation run — so it costs nothing but a few seconds of API time.

What it actually checks, and why each one is a real risk:

  1. Resource Graph inventory. Whether DefaultAzureCredential resolves for ARG at
     all, and whether the SDK returns rows in `Table` form ({columns, rows}) or
     `ObjectArray` form (list of dicts). Both are handled; only one has ever run.

The retrohunt checks (2 and 3) went with `sentinel` when the gap-scan subtree
was removed; they exercised SDK paths nothing in the tool reaches any more.

Usage:

    pip install -e ".[assess]"
    az login
    export AZURE_LOG_ANALYTICS_WORKSPACE_ID=<workspace GUID>   # for 2 and 3
    python scripts/verify-live-paths.py

Every call is read-only: a Resource Graph query and Log Analytics queries. It
writes nothing, to the workspace or to disk.
"""

from __future__ import annotations

import sys
import traceback

OK, FAIL, SKIP = "PASS", "FAIL", "SKIP"
results: list[tuple[str, str, str]] = []


def record(name: str, status: str, detail: str = "") -> None:
    results.append((name, status, detail))
    mark = {OK: "  ok ", FAIL: " FAIL", SKIP: " skip"}[status]
    print(f"[{mark}] {name}" + (f"\n         {detail}" if detail else ""), flush=True)


def check_inventory() -> None:
    """1. Resource Graph: credential, query, and which response shape comes back."""
    from pylon.inventory import fetch_inventory

    inv = fetch_inventory()
    if inv.errors:
        record("Resource Graph query", FAIL, "; ".join(inv.errors))
        return

    record(
        "Resource Graph query",
        OK,
        f"{inv.total_resources} resources across {len(inv.types)} types"
        + ("  (TRUNCATED — service returned fewer rows than matched)" if inv.truncated else ""),
    )

    if not inv.types:
        record("Response shape", FAIL, "query succeeded but parsed zero types — "
                                      "the response shape may not be one of the two handled")
        return

    sample = inv.types[0]
    # Name the shape rather than just "it parsed". Which branch ran was one of the
    # three questions this script exists to answer, and the first version reported
    # success without ever saying which one — so it proved the parse worked and
    # left the actual question open.
    shape = "unknown"
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest

        from pylon.inventory import INVENTORY_QUERY

        raw = ResourceGraphClient(DefaultAzureCredential()).resources(
            QueryRequest(query=INVENTORY_QUERY)
        )
        data = getattr(raw, "data", None)
        if isinstance(data, dict):
            shape = "Table ({columns, rows})"
        elif isinstance(data, list):
            shape = "ObjectArray (list of dicts)"
        else:
            shape = f"unexpected: {type(data).__name__}"
    except Exception as exc:  # noqa: BLE001 - diagnostic only; the parse already passed
        shape = f"could not determine ({type(exc).__name__})"

    record(
        "Response shape",
        OK,
        f"SDK returned {shape}; parsed e.g. {sample.type} x{sample.count}",
    )

    known = inv.known()
    record(
        "Catalog bridge",
        OK if known else FAIL,
        f"{len(known)} of {len(inv.types)} types mapped to a log surface; "
        f"{len(inv.unindexed())} unrecognized",
    )


def main() -> int:
    # Before either check reads a credential or a workspace id. Without it this
    # ignores ~/.config/pylon/config.env and only runs when the variables happen
    # to be exported — and the AZURE_LOG_ANALYTICS_WORKSPACE_ID check below then
    # reports SKIP for a workspace that IS configured, in a file it never read.
    from pylon import config

    config.apply()

    print(__doc__.split("Usage:")[0].strip())
    print("\n" + "-" * 72)

    try:
        check_inventory()
    except Exception:  # noqa: BLE001 - report and keep going; the other check is independent
        record("Resource Graph query", FAIL, traceback.format_exc(limit=2).strip())

    print("-" * 72)
    failed = [r for r in results if r[1] == FAIL]
    skipped = [r for r in results if r[1] == SKIP]
    print(
        f"{len(results) - len(failed) - len(skipped)} passed, "
        f"{len(failed)} failed, {len(skipped)} skipped"
    )
    if failed:
        print("\nPaste the FAIL lines back and they name the exact call that broke.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
