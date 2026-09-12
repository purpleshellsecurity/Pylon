#!/usr/bin/env python3
"""Regenerate the vendored Azure built-in role catalog.

Source of truth: the ARM API.

    GET /subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions
        ?api-version=2022-04-01&$filter=type eq 'BuiltInRole'

WHY THIS EXISTS. A detection that names a role writes the role's GUID as a
string literal:

    let UaaRoleId = "f1a07417-d97a-45cb-824c-7a7467783830";

That GUID is Managed Identity Operator. User Access Administrator is
18d7d88d-d35e-4fb5-a5c3-7773c20a72d9. The detection shipped, passed every
static check, ran clean against a live workspace and returned nothing, because
it was searching for a different role than the one it is named for.

Nothing could catch it. The validator checks columns against real schemas and
cmdlets against installed modules, but a GUID is a string literal to a parser
and to a schema. It is the third fabricated Azure identifier to ship, after a
PowerShell parameter that does not exist and an AzureDiagnostics column name on
a resource-specific table.

Built-in roles are the right thing to vendor: there are a few hundred, Azure
assigns the IDs and they never change, and they are identical in every tenant.
A CUSTOM role is tenant-specific and deliberately absent -- an unrecognised
GUID is "not a built-in role", never "wrong".

Usage:
    az login
    python scripts/refresh-builtin-roles.py

Re-run when Azure publishes new built-in roles.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import datetime

OUT = pathlib.Path(__file__).resolve().parents[1] / "src/pylon/catalog/builtin-roles.json"
API = "2022-04-01"


def _az(args: list[str]) -> str:
    done = subprocess.run(["az", *args], capture_output=True, text=True, timeout=180)
    if done.returncode != 0:
        sys.exit(f"az {' '.join(args[:2])} failed: {(done.stderr or '').strip()[:300]}")
    return done.stdout


def main() -> int:
    sub = _az(["account", "show", "--query", "id", "-o", "tsv"]).strip()
    if not sub:
        sys.exit("no subscription in context -- run `az login` first")
    raw = _az(["rest", "--method", "get", "--url",
               f"https://management.azure.com/subscriptions/{sub}/providers"
               f"/Microsoft.Authorization/roleDefinitions?api-version={API}"
               "&$filter=type%20eq%20'BuiltInRole'", "-o", "json"])
    payload = json.loads(raw)

    roles: dict[str, str] = {}
    for entry in payload.get("value", []):
        # `name` is the GUID; `properties.roleName` is the human name. The
        # full `id` is a scoped ARM path and is deliberately not stored -- a
        # detection compares the trailing GUID, not the path it came in on.
        guid = (entry.get("name") or "").lower()
        label = (entry.get("properties") or {}).get("roleName") or ""
        if guid and label:
            roles[guid] = label
    if len(roles) < 100:
        sys.exit(f"only {len(roles)} built-in roles came back; refusing to "
                 "overwrite the catalog with a partial answer")

    OUT.write_text(json.dumps({
        "meta": {
            "source": "Microsoft.Authorization/roleDefinitions",
            "api_version": API,
            "harvested": datetime.datetime.now(datetime.UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "count": len(roles),
        },
        # GUID -> role name, lowercase keys so a lookup never depends on how
        # the model happened to case the literal.
        "roles": dict(sorted(roles.items())),
    }, indent=1) + "\n")
    print(f"wrote {OUT} with {len(roles)} built-in roles")
    return 0


if __name__ == "__main__":
    sys.exit(main())
