"""Live per-run progress the CLI spinner reads.

Phase 2 fans out one agent call per attack vector concurrently, so its single
workflow event carries no sub-progress. This tiny in-process counter lets
run_detection_phase report detections as they land and the CLI render a live
(done/total). Reset at the start of each run.
"""
from dataclasses import dataclass


@dataclass
class _Phase2:
    """Mutable counter state (total/done/label) for the current counted phase."""

    total: int = 0
    done: int = 0
    label: str = "generated"


_state = _Phase2()


def reset() -> None:
    """Clear the counter back to its initial (empty) state for a new run."""
    _state.total = 0
    _state.done = 0
    _state.label = "generated"


def set_total(n: int, label: str = "generated") -> None:
    """Start a counted phase of ``n`` items. ``label`` names them for the bar
    (e.g. 'generated' for detections, 'playbooks built' for Phase 3)."""
    _state.total = n
    _state.done = 0
    _state.label = label


def mark_done() -> None:
    """Increment the done counter by one."""
    _state.done += 1
    from .logs import get_logger

    done, total = _state.done, _state.total
    get_logger(__name__).info(
        "  %s %d/%d", _state.label, done, total,
        extra={"event": "unit_done", "done": done, "total": total, "label": _state.label},
    )


def snapshot() -> tuple[int, int]:
    """(done, total) — total is 0 until a counted phase starts."""
    return _state.done, _state.total


def label() -> str:
    """The noun for the current counted phase (shown after done/total)."""
    return _state.label
