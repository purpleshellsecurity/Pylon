"""`asyncio.run` must not be called inside a loop.

Round nine printed a raw `RuntimeError: Event loop is closed` traceback in the
middle of `design playbooks`. The playbooks were written correctly either side
of it, so it did no damage and looked exactly like a crash that had.

The cause was `asyncio.run` per playbook, inside the `for`. Each call opens a
loop and closes it; the provider SDK's HTTP client outlives one iteration and is
bound to the loop that made it, so its finaliser runs against a closed loop and
the interpreter prints a traceback with no line of ours in it.
"""
import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src/pylon"


def _runs_inside_a_loop(tree: ast.AST) -> list[int]:
    """Line numbers of `asyncio.run(...)` calls with a loop in their ancestry."""
    bad, stack = [], []

    class Walk(ast.NodeVisitor):
        def visit_For(self, node):
            stack.append(node)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFor = visit_For

        def visit_While(self, node):
            stack.append(node)
            self.generic_visit(node)
            stack.pop()

        def visit_FunctionDef(self, node):
            # A function defined inside a loop body still runs once per
            # iteration only if CALLED there; its own body is not the loop's.
            outer, stack[:] = list(stack), []
            self.generic_visit(node)
            stack[:] = outer

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            f = node.func
            if (isinstance(f, ast.Attribute) and f.attr == "run"
                    and isinstance(f.value, ast.Name) and f.value.id == "asyncio"
                    and stack):
                bad.append(node.lineno)
            self.generic_visit(node)

    Walk().visit(tree)
    return bad


@pytest.mark.parametrize("path", sorted(SRC.rglob("*.py")), ids=lambda p: p.name)
def test_asyncio_run_is_not_called_per_iteration(path):
    hits = _runs_inside_a_loop(ast.parse(path.read_text(encoding="utf-8")))
    assert hits == [], (
        f"{path.name} calls asyncio.run inside a loop at line(s) {hits}. Each "
        f"call closes its event loop while a client bound to it is still alive, "
        f"which prints a bare 'Event loop is closed' traceback mid-run. Open one "
        f"loop around the whole phase instead.")
