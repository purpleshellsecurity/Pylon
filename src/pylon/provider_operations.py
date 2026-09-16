"""Vendored Azure control-plane provider-operations reference.

A lookup over every ARM operation Microsoft documents (~18k across ~150
providers) with its human-readable description. Sourced from the RBAC permission
docs (MicrosoftDocs/azure-docs) and refreshed by
`scripts/refresh-provider-operations.py` — no Azure credentials involved.

Two consumers:
  * Playbook grounding — describe the operation a detection fires on, plus its
    likely reverse (containment) sibling, so response steps are grounded in real
    operations instead of invented.
  * Operation validation — confirm an ARM operation string is real, upgrading
    `validate_operation`'s structural-only warning to a catalog check.

Operation strings in logs (AzureActivity `OperationNameValue`) are UPPERCASE, so
every lookup here is case-insensitive. This is a CONTROL-PLANE catalog (ARM
operations, what AzureActivity logs); data-plane audit vocabularies are separate.
"""

import gzip
import json
from functools import lru_cache
from importlib import resources

_CATALOG = "provider-operations.json.gz"

# Containment/inverse verb pairs — an attacker's `write` is undone by a `delete`,
# a member `add` by a `remove`, and so on. Used only to PROPOSE a reverse; the
# proposal is returned only when that sibling actually exists in the catalog, so
# we never invent an operation. `delete` has no entry: undoing a deletion is
# recovery (restore-from-backup), not a sibling ARM operation.
_REVERSE = {
    "write": "delete",
    "create": "delete",
    "add": "remove",
    "remove": "add",
    "start": "stop",
    "stop": "start",
    "enable": "disable",
    "disable": "enable",
    "register": "unregister",
    "unregister": "register",
    "join": "leave",
    "leave": "join",
}


@lru_cache(maxsize=1)
def _data() -> dict:
    """The decompressed provider-operations catalog JSON (cached)."""
    raw = (resources.files("pylon.catalog") / _CATALOG).read_bytes()
    return json.loads(gzip.decompress(raw))


@lru_cache(maxsize=1)
def _ops_ci() -> dict[str, tuple[str, dict]]:
    """Lowercased operation -> (canonical operation, fields).

    TWO ON-DISK SHAPES, and both stay readable on purpose. The harvester used to
    write `operation -> description`, a bare string; harvested from the ARM API
    it writes a dict carrying `isDataAction`, `displayName` and `resourceType`
    as well. A string is normalised to `{"description": ...}` here so the older
    file keeps working and the new fields simply read as absent.

    Absent is the honest answer for them. `isDataAction` was never in the docs,
    and the alternative -- inferring it from "/action" in the operation string --
    is the kind of plausible guess this repo keeps getting caught by.
    """
    out: dict[str, tuple[str, dict]] = {}
    for k, v in _data()["operations"].items():
        out[k.lower()] = (k, {"description": v} if isinstance(v, str) else dict(v))
    return out


def _lookup(op: str) -> tuple[str, dict] | None:
    """(canonical operation, fields) for `op`, or None (case-insensitive)."""
    return _ops_ci().get(op.strip().lower())


def is_data_action(op: str) -> bool | None:
    """Azure's own answer to whether `op` is a data-plane permission.

    None means the vendored catalog predates the ARM-API harvest and does not
    say -- NOT that the operation is control plane. The difference decides which
    log a detection should query, so a default here would be a guess with
    consequences: a control action lands in AzureActivity, a data action lands in
    the resource's own audit table or nowhere at all.
    """
    hit = _lookup(op)
    if not hit:
        return None
    return hit[1].get("isDataAction")


def resource_type(op: str) -> str:
    """The resource type this operation acts on ("secrets", "keys"), or "".

    Azure's own grouping, which is the same one the data-plane catalog builds by
    hand. Empty where the catalog predates the ARM-API harvest.
    """
    hit = _lookup(op)
    return hit[1].get("resourceType", "") if hit else ""


def harvested_at() -> str:
    """When the vendored catalog was harvested (UTC, ISO-ish), or "" if unknown.

    Empty for the snapshot committed before the harvester stamped a date: it was
    not re-fetched to add one. Stamping today's date on a file nobody fetched
    today would turn "unknown" into a confident wrong answer — the exact failure
    the three-state operation check exists to stop — so it stays empty until a
    real harvest replaces it.

    Read it before concluding anything from an operation's absence. A miss in a
    catalog of unknown age says less than a miss in one harvested last week.
    """
    return str(_data().get("meta", {}).get("harvested", "") or "")


def is_known(op: str) -> bool:
    """True if `op` is a documented ARM operation (case-insensitive).

    One bit, and it cannot distinguish "this operation does not exist" from
    "this catalog has never heard of this provider". Callers that act on a miss
    want `coverage` instead; this stays for callers that only need a lookup."""
    return _lookup(op) is not None


# The three answers a lookup can honestly give.
KNOWN = "known"                   # the catalog has this exact operation
UNKNOWN = "unknown"               # the provider IS catalogued; this operation is not
PROVIDER_ABSENT = "provider-absent"  # the catalog holds nothing for this provider


@lru_cache(maxsize=1)
def _covered_providers() -> frozenset[str]:
    """Lowercased provider namespaces the catalog has at least one operation for."""
    return frozenset(op.split("/", 1)[0].lower() for op in _data()["operations"])


def coverage(op: str) -> str:
    """KNOWN / UNKNOWN / PROVIDER_ABSENT for `op`.

    `is_known` collapses the last two into False, and they are opposite claims.
    UNKNOWN is evidence — the provider is documented, and this operation is not
    among its operations, so it is probably invented. PROVIDER_ABSENT is the
    absence of evidence: nothing about the operation can be concluded, because
    the catalog holds no operations for that provider at all.

    That distinction is not hypothetical. This catalog is harvested from the
    RBAC permission docs; the supported-logs index it is checked against comes
    from Azure Monitor's reference. Completing the logs index took it from 47
    resource types to 212, and the operation catalog did not grow with it — so
    40 providers, covering 62 of those 212 types, now have no operations here.
    Reporting every one of their operations as suspect is noise that teaches a
    reader to ignore the warning that matters.
    """
    if _lookup(op) is not None:
        return KNOWN
    provider = op.split("/", 1)[0].strip().lower()
    return UNKNOWN if provider in _covered_providers() else PROVIDER_ABSENT


def control_plane_operations(resource_type: str) -> set[str]:
    """Operations for `resource_type` that could appear in AzureActivity.

    `resource_type` is a full ARM type like "Microsoft.Network/networkSecurityGroups".
    Matching is on Azure's OWN resourceType grouping rather than a string prefix,
    which is the difference between a target meaning what it says and meaning its
    whole provider: Microsoft.Network holds 750 control-plane writes across 249
    resource types, and networkSecurityGroups is 16 of them. A prefix match would
    hand someone load balancers, DNS zones and VPN gateways under the name
    "Network Security Group".

    Sub-types are included. Asking for networkSecurityGroups also returns
    networkSecurityGroups/securityRules, because a rule change IS a change to the
    NSG and nobody thinks of them as separate surfaces.

    TWO FILTERS, AND THEY ARE NOT EQUALLY SOLID:

      isDataAction  Azure's own field. A data action lands in the resource's own
                    audit log, not here. Solid.
      trailing /read
                    Rests on this repo's note that AzureActivity is write-side
                    only, applied through a NAMING CONVENTION rather than a
                    field. If that note is wrong the result is too small, and the
                    cost is operations that never get a decision -- not wrong
                    decisions. Worth verifying against a real tenant one day.

    Empty for a resource type the catalog has never seen, which is not the same
    as a resource type with no operations. The caller has the type it asked for
    and can say which it got.
    """
    provider, _, rest = resource_type.partition("/")
    want = rest.lower()
    out: set[str] = set()
    for op, fields in _ops_ci().values():
        if not op.lower().startswith(provider.lower() + "/"):
            continue
        if op.rsplit("/", 1)[-1].lower() == "read" or fields.get("isDataAction"):
            continue
        rtype = (fields.get("resourceType") or "").lower()
        if rtype == want or rtype.startswith(want + "/"):
            out.add(op)
    return out


def describe(op: str) -> str:
    """Microsoft's description for `op`, or '' if unknown / undocumented."""
    hit = _lookup(op)
    return hit[1].get("description", "") if hit else ""


def service_for(op: str) -> str:
    """Friendly Azure service name for the operation's provider, or ''."""
    provider = op.split("/", 1)[0].lower()
    for name, svc in _data()["providers"].items():
        if name.lower() == provider:
            return svc
    return ""


def reverse(op: str) -> tuple[str, str] | None:
    """The likely containment/inverse operation for `op`, as
    (canonical operation, description), or None. Returns a sibling only when it
    genuinely exists in the catalog — never a fabricated operation."""
    hit = _lookup(op)
    if not hit:
        return None
    canon = hit[0]
    path, _, verb = canon.rpartition("/")
    rev_verb = _REVERSE.get(verb.lower())
    if not rev_verb:
        return None
    hit = _lookup(f"{path}/{rev_verb}")
    return (hit[0], hit[1].get("description", "")) if hit else None


def reference(op: str) -> dict:
    """Grounding block for one operation — what it does, its service, and its
    reverse (containment) operation. Empty dict when the operation is unknown, so
    callers can cleanly fall back."""
    hit = _lookup(op)
    if not hit:
        return {}
    canon, fields = hit
    desc = fields.get("description", "")
    block: dict = {"operation": canon, "description": desc, "service": service_for(canon)}
    rev = reverse(canon)
    if rev:
        block["reverse"] = {"operation": rev[0], "description": rev[1]}
    return block
