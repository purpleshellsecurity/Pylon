"""Azure built-in role definition IDs, so a detection's GUID can be checked.

A detection that names a role writes its GUID as a string literal:

    let UaaRoleId = "f1a07417-d97a-45cb-824c-7a7467783830";

That GUID is Managed Identity Operator. User Access Administrator is
18d7d88d-d35e-4fb5-a5c3-7773c20a72d9. The query parsed, passed every static
check, ran clean against a live workspace and matched nothing, because it was
looking for a different role than the one it is named for.

Nothing could catch it. Columns are checked against real schemas and cmdlets
against installed modules; a GUID is a string literal to a parser and carries
no type a schema could contradict. It is the third fabricated Azure identifier
to reach a shipped artifact, after a PowerShell parameter that does not exist
and an AzureDiagnostics column name on a resource-specific table.

Built-in roles are vendorable because Azure assigns the IDs, they never change,
and they are identical in every tenant. CUSTOM roles are tenant-specific and
deliberately absent: an unrecognised GUID means "not a built-in role", never
"wrong". Refresh with `scripts/refresh-builtin-roles.py`.
"""

from __future__ import annotations

import json
import os
import re

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "catalog", "builtin-roles.json")

try:
    with open(_PATH) as _f:
        _DATA = json.load(_f)
except (OSError, ValueError) as _exc:  # pragma: no cover - install damage
    # An empty catalogue is not a world with no roles. Every caller checks
    # `loaded()` so a missing data file cannot read as "nothing was wrong",
    # which is the failure mode `mitre.py` records for the same situation.
    _DATA, LOAD_ERROR = {"roles": {}, "meta": {}}, str(_exc)
else:
    LOAD_ERROR = ""

ROLES: dict[str, str] = {k.lower(): v for k, v in (_DATA.get("roles") or {}).items()}
BY_NAME: dict[str, str] = {v.lower(): k for k, v in ROLES.items()}

GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                  r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")


def loaded() -> bool:
    """Whether the catalogue is available. False means "could not check"."""
    return bool(ROLES)


def name_for(guid: str) -> str:
    """The built-in role a GUID names, or "" if it is not a built-in role."""
    return ROLES.get((guid or "").strip().lower(), "")


# Every way a role's name shows up in an identifier, mapped to the built-in
# role it means. Only roles worth naming in a detection are listed: this is a
# vocabulary for reading a VARIABLE NAME, not a second copy of the catalogue,
# and a term that could mean two roles is left out entirely rather than guessed.
#
# "admin" alone is absent for that reason -- it appears in User Access
# Administrator, Storage Blob Data Owner's docs, and a dozen service-specific
# administrator roles.
ALIASES: dict[str, str] = {
    "useraccessadministrator": "User Access Administrator",
    "useraccessadmin": "User Access Administrator",
    "uaa": "User Access Administrator",
    "owner": "Owner",
    "contributor": "Contributor",
    "reader": "Reader",
    "managedidentityoperator": "Managed Identity Operator",
    "keyvaultadministrator": "Key Vault Administrator",
    "keyvaultsecretsofficer": "Key Vault Secrets Officer",
    "keyvaultsecretsuser": "Key Vault Secrets User",
    "keyvaultcryptoofficer": "Key Vault Crypto Officer",
    "storageblobdataowner": "Storage Blob Data Owner",
    "storageblobdatacontributor": "Storage Blob Data Contributor",
    "virtualmachinecontributor": "Virtual Machine Contributor",
}


def intended(identifier: str) -> str:
    """The built-in role an identifier claims to hold, or "".

    Reads `UaaRoleId`, `uaa_role_id`, `UserAccessAdminRoleDefinitionId` and the
    like. Case and separators are stripped, then the LONGEST alias that appears
    wins -- so `StorageBlobDataOwnerId` resolves to Storage Blob Data Owner
    rather than to Owner, which is a substring of it.

    Returns "" when nothing matches, which is the common case and is not a
    finding: most literals in a query are not role ids.
    """
    flat = re.sub(r"[^a-z0-9]", "", (identifier or "").lower())
    if not flat:
        return ""
    best = ""
    for alias, role in ALIASES.items():
        if alias in flat and len(alias) > len(best):
            best, match = alias, role
    return ALIASES[best] if best else ""


def version_note() -> str:
    if LOAD_ERROR:
        return f"built-in role catalogue FAILED TO LOAD from {_PATH} ({LOAD_ERROR})"
    meta = _DATA.get("meta") or {}
    return (f"{meta.get('count', len(ROLES))} built-in roles, harvested "
            f"{meta.get('harvested', 'unknown')}")
