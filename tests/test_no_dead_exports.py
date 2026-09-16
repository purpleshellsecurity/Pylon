"""A name in `__all__` that nothing calls is a promise nothing keeps.

`prompts.is_grounded_table` was exported, defined, and called from nowhere. It
asked "do we have both KQL rules and a schema asset for this table", which
stopped being the right question once a table could be grounded by a measured
CONTRACT instead of an asset file -- so it returned False for the three App
Service tables, all of which are grounded.

Nothing called it, so the wrong answer never reached a run. That is exactly why
it survived: an export nothing uses is an export nothing tests, and the next
caller would have inherited the wrong answer with no warning at all.

This does not ban dead code in general. It asks a narrower question: is every
name a module PUBLISHES actually used somewhere, or is it an interface nobody
has ever exercised?
"""

import ast
import pathlib

import pytest

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "pylon"
TESTS = pathlib.Path(__file__).resolve().parent
SCRIPTS = SRC.parent.parent / "scripts"

MODULES = sorted(p for p in SRC.rglob("*.py") if "__pycache__" not in str(p))


def _exports(path: pathlib.Path) -> list[str]:
    """The names in a module's `__all__`, or [] when it declares none."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(getattr(t, "id", "") == "__all__" for t in node.targets):
            continue
        if isinstance(node.value, (ast.List, ast.Tuple)):
            return [e.value for e in node.value.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    return []


_WITH_EXPORTS = [(p, n) for p in MODULES for n in _exports(p)]
_IDS = [f"{p.name}:{n}" for p, n in _WITH_EXPORTS]


def test_some_module_declares_exports():
    """A parametrize over a shrinking list is green all the way to empty."""
    assert len(_WITH_EXPORTS) >= 5, f"only {len(_WITH_EXPORTS)} export(s) found"


@pytest.mark.parametrize("module,name", _WITH_EXPORTS, ids=_IDS)
def test_every_exported_name_is_used_somewhere(module, name):
    """Used by another module, a script, or a test. A test counts: it means
    somebody has at least exercised the thing and recorded what it should do."""
    hits = 0
    for path in list(MODULES) + sorted(TESTS.glob("*.py")) + sorted(SCRIPTS.glob("*.py")):
        if path == module:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if name in text:
            hits += 1
    assert hits, (
        f"{module.name} exports {name!r} and nothing references it. An export "
        f"nothing uses is an export nothing tests, and the next caller inherits "
        f"whatever it happens to return -- which is how `is_grounded_table` came "
        f"to answer False for three tables that are grounded."
    )


def test_an_ambiguous_name_is_told_what_it_could_have_meant():
    """`resource_candidates` was exported and reached nobody, so an ambiguous
    name got the same "not a target" wall as a typo -- even though the catalogue
    had always been able to tell the two apart."""
    from pylon.cli import _candidates

    storage = _candidates("storage")
    assert len(storage) == 4, storage
    assert all(c.startswith("Microsoft.Storage/") for c in storage)
    # Narrowed to targets the tool can be AIMED at. `sql` resolves in the
    # catalogue to managedInstances and servers/databases, neither of which is
    # a target, so suggesting them would send a reader somewhere that refuses.
    assert _candidates("sql") == []
    assert _candidates("nonsense") == []
