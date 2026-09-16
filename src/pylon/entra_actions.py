"""Vendored Entra ID directory roles/actions reference.

Every `microsoft.directory/...` action across the built-in directory roles, with
Microsoft's description, a privileged flag, and the set of roles that grant it.
Sourced from the entra-docs permission reference and refreshed by
`scripts/refresh-entra-graph-catalogs.py` — no tenant/credentials involved.

Grounds directory-change (AuditLogs) playbooks: what a directory action does, is
it privileged, which roles can perform it, and its containment inverse. This is
the Entra analog of `provider_operations` (which covers ARM/AzureActivity).
Note the keying difference: AuditLogs `OperationName` is a human phrase, not the
RBAC action string, so this is a vocabulary/context lookup, not a 1:1 op match.
"""

import gzip
import json
from functools import lru_cache
from importlib import resources

_CATALOG = "entra-directory-actions.json.gz"

# Containment inverses for directory actions. Only create/delete and
# enable/disable have clean, real sibling actions; a proposal is returned only
# when the sibling exists in the catalog.
_REVERSE = {"create": "delete", "enable": "disable", "disable": "enable"}


@lru_cache(maxsize=1)
def _data() -> dict:
    """The decompressed directory-actions catalog JSON (cached)."""
    raw = (resources.files("pylon.catalog") / _CATALOG).read_bytes()
    return json.loads(gzip.decompress(raw))


@lru_cache(maxsize=1)
def _actions_ci() -> dict[str, tuple[str, dict]]:
    """Lowercased action -> (canonical action, metadata)."""
    return {k.lower(): (k, v) for k, v in _data()["actions"].items()}


@lru_cache(maxsize=1)
def _granting_index() -> dict[str, list[str]]:
    """Lowercased action -> sorted list of roles that grant it."""
    idx: dict[str, list[str]] = {}
    for role, actions in _data()["roles"].items():
        for act in actions:
            idx.setdefault(act.lower(), []).append(role)
    return {k: sorted(v) for k, v in idx.items()}


def _lookup(action: str) -> tuple[str, dict] | None:
    """(canonical action, metadata) for `action`, or None (case-insensitive)."""
    return _actions_ci().get(action.strip().lower())


def is_known(action: str) -> bool:
    """True if `action` is a documented directory action (case-insensitive)."""
    return _lookup(action) is not None


def describe(action: str) -> str:
    """Microsoft's description for `action`, or '' if unknown."""
    hit = _lookup(action)
    return hit[1]["d"] if hit else ""


def is_privileged(action: str) -> bool:
    """Whether Microsoft tags `action` as privileged (False if unknown)."""
    hit = _lookup(action)
    return bool(hit and hit[1].get("p"))


def roles_granting(action: str) -> list[str]:
    """Built-in directory roles that grant `action` (empty if none/unknown)."""
    return _granting_index().get(action.strip().lower(), [])


def reverse(action: str) -> tuple[str, dict] | None:
    """The containment/inverse directory action (create->delete, enable->disable),
    or None. Only returns a sibling that exists in the catalog."""
    hit = _lookup(action)
    if not hit:
        return None
    path, _, verb = hit[0].rpartition("/")
    rev = _REVERSE.get(verb.lower())
    return _lookup(f"{path}/{rev}") if rev else None


def reference(action: str) -> dict:
    """Grounding block: what the action does, privileged flag, granting roles, and
    its inverse. Empty dict when unknown."""
    hit = _lookup(action)
    if not hit:
        return {}
    canon, meta = hit
    block: dict = {
        "action": canon,
        "description": meta["d"],
        "privileged": bool(meta.get("p")),
        "roles": roles_granting(canon),
    }
    rev = reverse(canon)
    if rev:
        block["reverse"] = {"action": rev[0], "description": rev[1]["d"]}
    return block
