"""Loader for the "will never produce a detection" declarations.

Splits one grey bucket into two, because they are different claims:

    NONE              Azure documents no resource logs for this type at all.
    OPERATIONAL_ONLY  Logs exist; they describe availability, performance or
                      attack mitigation rather than identity. A detection built
                      on them alerts on weather, not on a person.

The second is a judgement this project is making, not a fact about Azure, so the
declaration carries the log categories it is judging — a reader who disagrees
can see exactly what was set aside and argue with it.

Everything here is asserted deliberately. A type merely ABSENT from the
supported-logs index is not entered: the vendored snapshot can be stale and a
type can be new, so silence stays "not in the catalog" rather than becoming a
claim nobody made.
"""

from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

import yaml

_FILE = "no-detection-surface.yaml"

NONE = "none"
OPERATIONAL_ONLY = "operational-only"


@dataclass(frozen=True)
class NoSurface:
    """Why a resource type can never carry a detection."""

    resource_type: str
    reason: str               # NONE | OPERATIONAL_ONLY
    logs: tuple[str, ...]     # the categories being set aside (OPERATIONAL_ONLY)
    # Why, at length, for a reader of THIS FILE. Free to argue with itself and
    # to record how the classification was reached. Never rendered into a report:
    # a reader of a coverage report wants the reason, not the reasoning, and
    # these were being printed verbatim — including one that opened by narrating
    # a mistake its author had made.
    basis: str
    # The same thing in a clause, for a report line. Falls back to `basis` where
    # the basis is already short enough to be one.
    summary: str = ""
    # The Activity Log operation a detection WOULD use for this type. Present so
    # a report can say what to do instead of only what is absent — every one of
    # these resources is detectable at the control plane.
    activity_operation: str = ""

    @property
    def short(self) -> str:
        """The reason, at report length."""
        return self.summary or self.basis

    def label(self) -> str:
        """The phrasing a report shows. Two sentences on purpose, and NEITHER
        says undetectable — both types are detectable through the Activity Log."""
        if self.reason == OPERATIONAL_ONLY:
            return "Activity Log only — its resource logs are operational"
        return "Activity Log only — no resource logs exist"


@lru_cache(maxsize=1)
def _load() -> dict[str, NoSurface]:
    try:
        text = (resources.files(__name__.rsplit(".", 1)[0]) / _FILE).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return {}
    doc = yaml.safe_load(text) or {}
    out: dict[str, NoSurface] = {}
    for rt, block in (doc.get("types") or {}).items():
        reason = str((block or {}).get("reason", NONE))
        out[rt.lower()] = NoSurface(
            resource_type=rt,
            reason=reason if reason in (NONE, OPERATIONAL_ONLY) else NONE,
            logs=tuple(str(x) for x in ((block or {}).get("logs") or [])),
            basis=" ".join(str((block or {}).get("basis", "")).split()),
            summary=" ".join(str((block or {}).get("summary", "")).split()),
            activity_operation=str((block or {}).get("activity_operation", "")),
        )
    return out


def lookup(resource_type: str) -> NoSurface | None:
    """The declaration for a type, or None when nothing is claimed about it."""
    return _load().get((resource_type or "").lower())


def declared() -> dict[str, NoSurface]:
    """Every declaration."""
    return dict(_load())
