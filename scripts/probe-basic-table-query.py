#!/usr/bin/env python3
"""Settle one question: does query_workspace work against a Basic table, or error?

THE ONLY THING IN THIS PROJECT THAT WRITES TO A TENANT, and it is deliberately
not reachable from the CLI. `pylon` performs no create, update or delete
anywhere — that guarantee is load-bearing for what the tool claims about itself,
and a read-only product with one write hidden in it is not a read-only product.
This is an operator running an experiment by hand, and it stays that way.

The question it answers
-----------------------
Basic and Auxiliary tables are documented as needing the `/search` API rather
than `/query`, and `azure-monitor-query` offers only `/query`. What is NOT
documented is what `/query` DOES when pointed at such a table: a clean error, or
a successful query that quietly bills by the gigabyte.

`table_plans` refused to send those queries either way, so this was defence in
depth. It went with the gap-scan removal, and nothing gates the workspace reads
that remain -- which makes the measurement this script takes worth more, not
less: it is now the only thing that can say what `/query` does to a Basic table.

Why an empty table answers it
-----------------------------
The plan is a property of the TABLE, not of the data in it. Zero rows exercises
exactly the same API path and scans zero gigabytes, so this costs nothing. How
much a Basic query bills is documented and does not need measuring; whether the
call works at all is not.

What it does, in order
----------------------
1. PUT a DCR-based custom table with `plan: Basic` set AT CREATION. Creating it
   as Basic rather than switching an existing table matters: plan changes are
   "limited to one switch per table per week", so a switch-and-revert would strand
   a real table on the wrong plan for seven days.
2. Run one `| count` through the same client the scan uses, and record exactly
   what came back.
3. DELETE the table.

The name carries a timestamp because "when you delete a table, the table name
remains reserved for fifteen days" — a fixed name would work once and then fail
confusingly for a fortnight.

Usage:
    python scripts/probe-basic-table-query.py --confirm-write

Needs AZURE_SUBSCRIPTION_ID / AZURE_SENTINEL_RESOURCE_GROUP /
AZURE_SENTINEL_WORKSPACE_NAME / AZURE_LOG_ANALYTICS_WORKSPACE_ID, and write
access to the workspace's tables (Log Analytics Contributor).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

ARM = (
    "https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}"
    "/providers/Microsoft.OperationalInsights/workspaces/{ws}/tables/{table}"
    "?api-version=2025-02-01"
)


def _env() -> tuple[str, str, str, str]:
    try:
        return (
            os.environ["AZURE_SUBSCRIPTION_ID"],
            os.environ["AZURE_SENTINEL_RESOURCE_GROUP"],
            os.environ["AZURE_SENTINEL_WORKSPACE_NAME"],
            os.environ["AZURE_LOG_ANALYTICS_WORKSPACE_ID"],
        )
    except KeyError as missing:
        raise SystemExit(f"{missing} is not set — see .env.example") from None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--confirm-write", action="store_true",
                    help="required: this creates and deletes a table in your workspace")
    ap.add_argument("--keep", action="store_true",
                    help="leave the probe table behind (its name is reserved 15 days)")
    args = ap.parse_args()
    if not args.confirm_write:
        print(__doc__.strip().split("Usage:")[0], file=sys.stderr)
        print("Refusing to write without --confirm-write.", file=sys.stderr)
        return 2

    import httpx
    from azure.identity import DefaultAzureCredential

    sys.path.insert(0, "src")
    from pylon import config

    config.apply()
    sub, rg, ws, workspace_id = _env()

    # Reserved for fifteen days after deletion, so never a fixed name.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    table = f"PylonPlanProbe{stamp}_CL"
    url = ARM.format(sub=sub, rg=rg, ws=ws, table=table)

    credential = DefaultAzureCredential()
    arm_token = credential.get_token("https://management.azure.com/.default").token
    headers = {"Authorization": f"Bearer {arm_token}", "Content-Type": "application/json"}
    body = {
        "properties": {
            "plan": "Basic",
            "schema": {
                "name": table,
                "columns": [
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "Message", "type": "string"},
                ],
            },
        }
    }

    result = {"table": table, "created": None, "query": None, "deleted": None}
    with httpx.Client(timeout=120) as client:
        print(f"creating {table} with plan=Basic ...", flush=True)
        made = client.put(url, headers=headers, content=json.dumps(body))
        result["created"] = made.status_code
        print(f"  HTTP {made.status_code}")
        if made.status_code not in (200, 201, 202):
            print(made.text[:600])
            return 1

        # Provisioning is not instant and querying a half-made table would answer
        # a different question.
        for _ in range(30):
            state = client.get(url, headers=headers)
            provisioning = (state.json().get("properties") or {}).get("provisioningState")
            plan = (state.json().get("properties") or {}).get("plan")
            if provisioning == "Succeeded":
                print(f"  provisioned, plan={plan}")
                break
            time.sleep(4)
        else:
            print("  never reached Succeeded; querying anyway", flush=True)

        # THE MEASUREMENT: the same client the scan uses, against a Basic table.
        print(f"querying: {table} | count   (via LogsQueryClient.query_workspace)", flush=True)
        result["query"] = asyncio.run(_query(workspace_id, table))
        print("  " + json.dumps(result["query"], indent=2).replace("\n", "\n  "))

        if not args.keep:
            print(f"deleting {table} ...", flush=True)
            gone = client.delete(url, headers=headers)
            result["deleted"] = gone.status_code
            print(f"  HTTP {gone.status_code}  (name reserved for ~15 days)")

    print("\nRESULT")
    print(json.dumps(result, indent=2))
    return 0


async def _query(workspace_id: str, table: str) -> dict:
    """One count, and exactly what came back — status, code, message or success."""
    from azure.core.exceptions import HttpResponseError
    from azure.identity.aio import DefaultAzureCredential
    from azure.monitor.query.aio import LogsQueryClient

    credential = DefaultAzureCredential()
    client = LogsQueryClient(credential)
    try:
        response = await client.query_workspace(
            workspace_id, f"{table}\n| count", timespan=timedelta(days=1)
        )
        status = getattr(response.status, "value", response.status)
        rows = response.tables[0].rows if response.tables else []
        return {"outcome": "returned", "status": str(status), "rows": [list(r) for r in rows]}
    except HttpResponseError as exc:
        model = getattr(exc, "model", None)
        return {
            "outcome": "HttpResponseError",
            "status_code": getattr(exc, "status_code", None),
            "code": getattr(model, "code", None),
            "message": (getattr(model, "message", None) or str(exc))[:400],
        }
    except Exception as exc:  # noqa: BLE001 — record whatever it was
        return {"outcome": type(exc).__name__, "message": str(exc)[:400]}
    finally:
        await client.close()
        await credential.close()


if __name__ == "__main__":
    raise SystemExit(main())
