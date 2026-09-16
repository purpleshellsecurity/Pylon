"""Vendored Microsoft Graph permissions (OAuth scopes / app roles) reference.

Every Graph permission (e.g. `Directory.ReadWrite.All`) with its Application and
Delegated variants — identifier GUID, display text, description, and whether it
requires admin consent. Sourced from the microsoft-graph-docs-contrib permission
reference and refreshed by `scripts/refresh-entra-graph-catalogs.py`.

Grounds MicrosoftGraphActivityLogs playbooks: what a scope grants, and the
security-relevant application-vs-delegated distinction (an application permission
acts without a signed-in user — the higher-risk path). Lookups are
case-insensitive.
"""

import gzip
import json
from functools import lru_cache
from importlib import resources

_CATALOG = "graph-permissions.json.gz"


@lru_cache(maxsize=1)
def _data() -> dict:
    """The decompressed Graph-permissions catalog JSON (cached)."""
    raw = (resources.files("pylon.catalog") / _CATALOG).read_bytes()
    return json.loads(gzip.decompress(raw))


@lru_cache(maxsize=1)
def _scopes_ci() -> dict[str, tuple[str, dict]]:
    """Lowercased scope -> (canonical scope, entry)."""
    return {k.lower(): (k, v) for k, v in _data()["scopes"].items()}


def _lookup(scope: str) -> tuple[str, dict] | None:
    """(canonical scope, entry) for `scope`, or None (case-insensitive)."""
    return _scopes_ci().get(scope.strip().lower())


def is_known(scope: str) -> bool:
    """True if `scope` is a documented Graph permission (case-insensitive)."""
    return _lookup(scope) is not None


def describe(scope: str, plane: str = "application") -> str:
    """Description for `scope`. Prefers the requested plane ('application' or
    'delegated'), falling back to the other if only one exists. '' if unknown."""
    hit = _lookup(scope)
    if not hit:
        return ""
    entry = hit[1]
    other = "delegated" if plane == "application" else "application"
    for p in (plane, other):
        if entry.get(p, {}).get("desc"):
            return entry[p]["desc"]
    return ""


def admin_consent_required(scope: str, plane: str = "application") -> bool | None:
    """Whether `scope` requires admin consent on the given plane. None when the
    scope (or that plane) is unknown — distinct from a definite False."""
    hit = _lookup(scope)
    if not hit or plane not in hit[1]:
        return None
    return bool(hit[1][plane].get("adminConsent"))


def reference(scope: str) -> dict:
    """Grounding block: the canonical scope plus each available plane's display,
    description, admin-consent, and GUID. Empty dict when unknown."""
    hit = _lookup(scope)
    if not hit:
        return {}
    canon, entry = hit
    block: dict = {"scope": canon, "planes": sorted(entry.keys())}
    for plane in ("application", "delegated"):
        if plane in entry:
            block[plane] = entry[plane]
    return block


@lru_cache(maxsize=1)
def permission_planes() -> tuple[frozenset[str], frozenset[str]]:
    """(delegated, application) scope names, for checking a scope someone WROTE
    rather than describing one they asked about.

    Here rather than in the caller because this catalog was vendored twice —
    `catalog/graph-permissions.json` alongside the `.gz` this module reads — and
    the two harvests drifted 153 scopes apart. The PowerShell scope gate read the
    smaller one and rejected 163 real permissions. A second loader is how that
    happened, so there is one.
    """
    scopes = _data()["scopes"]
    return (
        frozenset(n for n, e in scopes.items() if e.get("delegated")),
        frozenset(n for n, e in scopes.items() if e.get("application")),
    )
