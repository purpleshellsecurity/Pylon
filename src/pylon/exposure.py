"""Who holds privileged rights over what, read over REST.

Deliberately not `az role assignment list`. The CLI truncated a subscription
diagnostic-settings read earlier in this project -- returned 1 of 5 with exit
0 -- and produced a confident wrong finding. The failure is worse here: an
undercount does not show up as a missing value, it shows up as a resource
placed in the "checked and clean" tier. So this follows `nextLink` explicitly
and reports the page count, and any failure poisons the whole subscription to
unrated rather than letting a partial answer look like a complete one.

Two more ways this read undercounts, both recorded rather than silently
accepted:

  * a role held through a GROUP is not returned by this API as a role the
    member holds. Expanding it needs directory reads this scan does not make.
  * `roleDefinitionId` is a GUID. Only the three built-in roles that actually
    confer control-plane authority are matched; a custom role granting the
    same rights under another name is not seen.

Both mean the privileged-role signal is a FLOOR. It never overstates.
"""

from __future__ import annotations

import json

from . import apiversions
from . import azcli

API = apiversions.AUTHORIZATION

# The built-in roles that confer control-plane authority over a resource.
# Matched by definition GUID, which is stable across tenants; the display name
# is not carried on the assignment.
PRIVILEGED = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
}


def _get(url: str) -> tuple[dict | None, str]:
    p = azcli.run(["rest", "--method", "get", "--url", url, "-o", "json"],
                  timeout=azcli.CONTROL_TIMEOUT)
    if p.returncode != 0:
        return None, (p.stderr or "").strip().splitlines()[-1][:200] if p.stderr else "failed"
    try:
        return json.loads(p.stdout), ""
    except json.JSONDecodeError:
        return None, "response was not JSON"


def read(subscription_id: str) -> dict:
    """Every privileged assignment in the subscription, by the scope it sits at.

    Returns `{"ran": bool, "detail": str, "by_scope": {scope: [role, ...]}}`.
    `ran=False` means nothing may be concluded about any resource in this
    subscription -- not that no privileged roles exist.
    """
    url = (f"https://management.azure.com/subscriptions/{subscription_id}"
           f"/providers/Microsoft.Authorization/roleAssignments"
           f"?api-version={API}")
    by_scope: dict[str, list[str]] = {}
    seen = pages = 0
    while url:
        payload, err = _get(url)
        if payload is None:
            # A partial answer is the dangerous outcome, so it is discarded.
            return {"ran": False, "by_scope": {},
                    "detail": (f"role assignment read failed after {pages} page(s): "
                               f"{err}. No resource in this subscription can be "
                               "placed, so all are left unrated.")}
        rows = payload.get("value") or []
        seen += len(rows)
        pages += 1
        for row in rows:
            props = row.get("properties") or {}
            guid = (props.get("roleDefinitionId") or "").rsplit("/", 1)[-1]
            role = PRIVILEGED.get(guid)
            if role:
                by_scope.setdefault(props.get("scope") or "", []).append(role)
        url = payload.get("nextLink")
    n = sum(len(v) for v in by_scope.values())
    return {
        "ran": True, "by_scope": by_scope,
        "detail": (f"{seen} role assignment(s) over {pages} page(s); {n} are "
                   f"Owner/Contributor/User Access Administrator, across "
                   f"{len(by_scope)} scope(s). Roles held through a group, and "
                   "custom roles granting the same rights, are not counted -- "
                   "this is a floor."),
    }


def covering(resource_id: str, by_scope: dict[str, list[str]]) -> tuple[list[str], bool]:
    """(privileged roles covering this resource, whether any is above it).

    "Above it" means the assignment sits on something that contains resources
    other than this one -- a management group, a subscription, or a resource
    group. The ladder's two positions are about BLAST RADIUS, and a resource
    group holds many resources, so grouping it with a single-resource
    assignment would understate it. An assignment whose scope IS the resource
    id covers only this resource.
    """
    rid = resource_id.lower()
    roles: list[str] = []
    above = False
    for scope, names in by_scope.items():
        s = scope.lower()
        if s == rid:
            roles.extend(names)
        elif s == "/" or rid.startswith(s.rstrip("/") + "/"):
            roles.extend(names)
            above = True
    return sorted(set(roles)), above
