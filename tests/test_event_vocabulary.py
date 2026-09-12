"""The structured event names are a contract, so they are written down.

Fourteen `extra={"event": ...}` literals lived across four modules with nothing
naming them. A typo makes a new event silently; deleting the last call site of
one removes it from the record with nothing to notice. Anything reading the
JSONL -- a dashboard, an alert, a "did this run get past phase 2" check -- is
coupled to these names.

This is the same drift that let the eval harness classify validator warnings by
grepping their prose: two places holding one fact, kept in step by memory.
"""

import re
from pathlib import Path

from pylon.logs import EVENTS

SRC = Path(__file__).resolve().parent.parent / "src" / "pylon"
_EMITTED = re.compile(r'"event"\s*:\s*"([a-z_]+)"')


def _emitted() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "logs.py":          # the declaration, not an emitter
            continue
        for name in _EMITTED.findall(path.read_text(encoding="utf-8")):
            out.setdefault(name, []).append(path.name)
    return out


def test_nothing_emits_an_undeclared_event():
    """A typo is a brand new event that nothing downstream is watching for."""
    undeclared = {n: w for n, w in _emitted().items() if n not in EVENTS}
    assert undeclared == {}, (
        "emitted but not declared in logs.EVENTS: "
        + "; ".join(f"{n} ({', '.join(w)})" for n, w in sorted(undeclared.items())))


def test_nothing_declared_has_lost_its_last_emitter():
    """An event that stopped being emitted is a silent hole in the record."""
    emitted = set(_emitted())
    orphaned = sorted(EVENTS - emitted)
    assert orphaned == [], (
        f"declared but never emitted: {orphaned}. Either a call site was "
        "removed and the record lost an event, or the name was renamed at one "
        "end only.")


def test_the_names_are_machine_readable():
    """These are grouped and filtered on, not read as prose."""
    bad = [e for e in EVENTS if not re.fullmatch(r"[a-z][a-z0-9_]*", e)]
    assert bad == [], f"event names must be snake_case: {bad}"
