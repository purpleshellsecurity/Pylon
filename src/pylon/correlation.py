"""Cross-log correlation map loader.

Per-table metadata for following one actor across log surfaces — actor/IP/
resource fields, plane, and detection-vs-context role. Sourced from the vendored
`catalog/correlation-map.yaml` (hand-curated from the table assets). Consumed by
the Phase-1 pivot generator (playbook Investigation section) and, later, by
Phase-2 correlation detections.

Lookups are case-insensitive; an uncovered table returns empty structures, never
an error, so callers degrade gracefully. See
docs/correlation-pivot-layer-spec.md.
"""

from functools import lru_cache
from importlib import resources

import yaml

_CATALOG = "correlation-map.yaml"

# Kill-chain ordering of planes for detection-anchored traversal.
PLANE_ORDER = ("identity", "control", "data")


@lru_cache(maxsize=1)
def _tables() -> dict:
    """The `tables` mapping from the vendored correlation-map YAML (cached)."""
    text = (resources.files("pylon.catalog") / _CATALOG).read_text(encoding="utf-8")
    return (yaml.safe_load(text) or {}).get("tables", {})


def for_table(table: str) -> dict:
    """The full correlation entry for `table` (case-insensitive), or {}."""
    tl = table.lower()
    return next((v for k, v in _tables().items() if k.lower() == tl), {})


def has_table(table: str) -> bool:
    """True if `table` is covered by the correlation map (case-insensitive)."""
    return bool(for_table(table))


def plane(table: str) -> str:
    """The table's plane ('identity'/'control'/'data'/…), '' if uncovered."""
    return for_table(table).get("plane", "")


def role(table: str) -> str:
    """The table's role ('detection' or 'context'), '' if uncovered."""
    return for_table(table).get("role", "")


def is_context(table: str) -> bool:
    """True if `table` is a context table (resource/time-scoped, not a source)."""
    return role(table) == "context"


def is_detection_source(table: str) -> bool:
    """True if `table` is a detection-source table."""
    return role(table) == "detection"


def actor_fields(table: str) -> list[dict]:
    """Ordered actor field specs (oid first). Empty when the table has no
    reliable actor field (e.g. Cosmos key-auth, or a context table)."""
    return for_table(table).get("actor") or []


def ip_field(table: str) -> dict | None:
    """The table's source-IP field spec, or None if it has none / is uncovered."""
    return for_table(table).get("ip")


def resource_field(table: str) -> dict | None:
    """The table's resource field spec, or None if it has none / is uncovered."""
    return for_table(table).get("resource")


def tables_in_plane(plane_name: str) -> list[str]:
    """Covered table names in a given plane (canonical casing)."""
    return sorted(k for k, v in _tables().items() if v.get("plane") == plane_name)


def detection_sources() -> list[str]:
    """All covered detection-source table names, sorted (canonical casing)."""
    return sorted(k for k, v in _tables().items() if v.get("role") == "detection")


def context_tables() -> list[str]:
    """All covered context table names, sorted (canonical casing)."""
    return sorted(k for k, v in _tables().items() if v.get("role") == "context")
