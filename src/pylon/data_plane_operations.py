"""Vendored data-plane audit operation vocabularies, keyed by log table.

Unlike the ARM / Entra / Graph catalogs (auto-pulled from Microsoft docs), the
data-plane audit `OperationName` values (`SecretGet`, `GetBlob`, …) have no
single machine-readable source, so `catalog/data-plane-operations.yaml` is a
hand-curated, per-service file. This loads it and answers lookups keyed by
(table, operation) — grounding data-plane playbooks/detections the same way
`provider_operations` grounds control-plane ones.

Lookups are case-insensitive. A table we don't yet cover returns cleanly empty
(callers fall back to the table's prose asset — never a false rejection).
"""

from functools import lru_cache
from importlib import resources

import yaml

_CATALOG = "data-plane-operations.yaml"


@lru_cache(maxsize=1)
def _tables() -> dict:
    """The `tables` mapping from the vendored data-plane-operations YAML (cached)."""
    text = (resources.files("pylon.catalog") / _CATALOG).read_text(encoding="utf-8")
    return (yaml.safe_load(text) or {}).get("tables", {})


@lru_cache(maxsize=1)
def _index() -> dict[tuple[str, str], tuple[str, str, dict]]:
    """(table.lower, op.lower) -> (canonical table, canonical op, meta)."""
    idx: dict[tuple[str, str], tuple[str, str, dict]] = {}
    for table, block in _tables().items():
        for op, meta in (block.get("operations") or {}).items():
            idx[(table.lower(), op.lower())] = (table, op, meta)
    return idx


def has_table(table: str) -> bool:
    """True if we have a curated vocabulary for `table`."""
    tl = table.lower()
    return any(t == tl for t, _ in _index())


def _lookup(table: str, op: str) -> tuple[str, str, dict] | None:
    """(canonical table, canonical op, meta) for (`table`, `op`), or None (ci)."""
    return _index().get((table.strip().lower(), op.strip().lower()))


def is_known(table: str, op: str) -> bool:
    """True if (`table`, `op`) is a curated data-plane operation (case-insensitive)."""
    return _lookup(table, op) is not None


def describe(table: str, op: str) -> str:
    """Curated description for the operation, or '' if the table/op is uncovered."""
    hit = _lookup(table, op)
    return hit[2].get("desc", "") if hit else ""


def is_sensitive(table: str, op: str) -> bool:
    """Whether the operation is flagged security-sensitive (False if uncovered)."""
    hit = _lookup(table, op)
    return bool(hit and hit[2].get("sensitive"))


def _block(table: str) -> dict | None:
    """The raw YAML block for `table` (case-insensitive), or None if uncovered."""
    return next((b for t, b in _tables().items() if t.lower() == table.lower()), None)


def operations(table: str) -> list[str]:
    """Every curated operation name for `table` (empty if uncovered)."""
    return sorted((_block(table) or {}).get("operations", {}).keys())


def field_for(table: str) -> str:
    """The column this table's operation lives in (OperationName / action_name_s /
    Verb). '' if uncovered. The KQL filter/validator keys off this."""
    return (_block(table) or {}).get("field", "")


def reference(table: str, op: str) -> dict:
    """Grounding block for one data-plane operation. Empty dict when unknown."""
    hit = _lookup(table, op)
    if not hit:
        return {}
    canon_table, canon_op, meta = hit
    return {
        "table": canon_table,
        "operation": canon_op,
        "field": _tables()[canon_table].get("field", ""),
        "service": _tables()[canon_table].get("service", ""),
        "description": meta.get("desc", ""),
        "verb": meta.get("verb", ""),
        "sensitive": bool(meta.get("sensitive")),
        # Three states, never two. "none" says the catalogue establishes that
        # nothing reverses this operation; an operation name says what does;
        # absent says it was never established. A playbook that cannot tell the
        # last two apart writes a hopeful restore step for a purge.
        "recovery": meta.get("recovery", ""),
    }
