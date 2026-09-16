"""Every module either ships or is parked on purpose.

The gap-scan subtree — `gap_detection` and the `sentinel` stack under it — was
deleted rather than parked: it came across byte-for-byte in the generation lift
and lost its caller when the CLI became four verbs, and code nobody can run is
not worth carrying. It is recoverable from this repository's history.

What remains parked is the harness half: modules `scripts/` drives that no
`pylon` command reaches. Those are used, just not by the CLI, so reachability
alone would read them as dead.

This test is what keeps the distinction honest. A parked module that gains a CLI
caller fails here, and so does a new module that reaches nothing.
"""

import ast
import re
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src" / "pylon"

# module -> why it ships nothing today. Removing an entry means it must be
# reachable from `pylon.cli`; adding one means writing down why it is not.
_PARKED = {
    # `golden_eval` was parked here, and being parked is what let it sit
    # unreachable: `design record` wrote fixtures and nothing in the product
    # read them. `design grade` reaches it now, which is the whole point of
    # this test -- a module nobody can run is a feature nobody has.
    "eval_metrics": "scripts/eval.py only, not the CLI",
    "refresh": "scripts/refresh-*.py only, not the CLI",
}


def _imports(path: Path, module: str) -> set[str]:
    """Sibling modules `module` imports, at any depth (function-level included)."""
    package = module.rsplit(".", 1)[0] if "." in module else ""
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:  # from . / .. import
                base = f"{package}.{base}".strip(".") if node.level == 1 else base
            elif base.startswith("pylon"):
                base = base.removeprefix("pylon").lstrip(".")
            else:
                continue
            found.add(base)
            found.update(f"{base}.{a.name}".lstrip(".") for a in node.names)
        elif isinstance(node, ast.Import):
            found.update(a.name.removeprefix("pylon").lstrip(".")
                         for a in node.names if a.name.startswith("pylon"))
    return found


def _module_names() -> dict[str, Path]:
    out = {}
    for path in _SRC.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        name = path.relative_to(_SRC).with_suffix("").as_posix().replace("/", ".")
        # `pylon/__init__.py` is the package itself, not a module named
        # "__init__"; `catalog/__init__.py` is "catalog".
        out["" if name == "__init__" else name.removesuffix(".__init__")] = path
    return out


def _reachable() -> set[str]:
    mods = _module_names()
    graph = {m: {t for t in _imports(p, m) if t in mods} for m, p in mods.items()}
    seen: set[str] = set()
    stack = ["cli", ""]
    while stack:
        m = stack.pop()
        if m in seen or m not in graph:
            continue
        seen.add(m)
        stack.extend(graph[m])
    return seen


def test_every_module_ships_or_is_parked_on_purpose():
    reachable = _reachable()
    unreachable = {m for m in _module_names() if m not in reachable and m}
    top_level = {m for m in unreachable if "." not in m}

    stranded = sorted(top_level - set(_PARKED))
    assert not stranded, (
        f"unreachable from `pylon.cli` and not on the parked list: {stranded}. "
        "Wire it to a verb, or add it to _PARKED with the reason."
    )

    revived = sorted(m for m in _PARKED if m in reachable)
    assert not revived, (
        f"parked but now reachable: {revived}. Good -- remove it from _PARKED. "
        "If it is `sentinel` or anything under it, arm the billing interlock first: "
        "`set_table_plans` still has no callers, so `_guard` allows every query."
    )


def test_no_two_files_claim_the_same_import_name():
    """`foo.py` beside `foo/__init__.py` is a silent deletion.

    Python resolves the package and never the module, so the module keeps
    passing import, keeps passing lint, and every attribute its callers reach
    for is suddenly gone. It happened here: `services.py` (the Content Hub
    solution catalogue) was shadowed the day `services/` was added, and
    `pylon analyze` raised `AttributeError` on a tenant read while the whole
    suite stayed green -- because this file keys modules by name, so one of
    the two simply overwrote the other and reachability could not see it.

    The check has to walk the paths, not the names the walk produces.
    """
    claims: dict[str, list[str]] = {}
    for path in _SRC.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        name = path.relative_to(_SRC).with_suffix("").as_posix().replace("/", ".")
        name = "" if name == "__init__" else name.removesuffix(".__init__")
        claims.setdefault(name, []).append(path.relative_to(_SRC).as_posix())

    collisions = {n: sorted(p) for n, p in claims.items() if len(p) > 1}
    assert not collisions, (
        f"two files import as the same name: {collisions}. The package wins and "
        "the module is unreachable -- rename one of them."
    )


def _pyproject() -> dict:
    import tomllib

    return tomllib.loads((_SRC.parents[1] / "pyproject.toml").read_text(encoding="utf-8"))


def test_the_free_commands_need_nothing_from_the_paid_extra():
    """A command that costs no money must run on a base install.

    `pyyaml` was declared only under the `design` extra. Three catalogues are
    YAML and are read outside a paid run -- the technique judgements behind
    `design list`, the correlation map, the data-plane operations -- so a base
    install crashed with "No module named 'yaml'" on `pylon design list`, which
    is the first command a new reader runs to see what the tool can do. It cost
    nothing and it failed anyway.

    Found by installing the published wheel with `uv tool install` and running
    it outside the repository, which is how a reader meets it and is not what
    `uv run` inside a synced checkout exercises.
    """
    project = _pyproject()["project"]
    base = {re.split(r"[<>=!\[ ]", d, maxsplit=1)[0].lower() for d in project["dependencies"]}
    extra = {re.split(r"[<>=!\[ ]", d, maxsplit=1)[0].lower()
             for d in project["optional-dependencies"]["design"]}

    assert "pyyaml" in base, (
        "the YAML catalogues are read by free commands; declaring pyyaml only "
        "under `design` breaks `pylon design list` on a base install"
    )
    assert not (base & extra), (
        f"declared twice: {sorted(base & extra)}. One dependency, one home -- "
        f"two declarations drift on the next version bump."
    )


def test_every_module_a_free_command_reaches_is_importable_without_the_extra():
    """The guard behind the one above, derived rather than listed.

    Walks what `analyze`, `validate`, `tabledrift`, `config` and
    `design list` import, and fails on a third-party module that is in the
    `design` extra and not in the base dependencies.
    """
    project = _pyproject()["project"]
    base = {re.split(r"[<>=!\[ ]", d, maxsplit=1)[0].lower().replace("-", "_")
            for d in project["dependencies"]}
    paid = {re.split(r"[<>=!\[ ]", d, maxsplit=1)[0].lower().replace("-", "_")
            for d in project["optional-dependencies"]["design"]} - base
    # Distribution names are not always import names.
    paid_imports = {"pyyaml": "yaml", "agent_framework_core": "agent_framework",
                    "agent_framework_openai": "agent_framework",
                    "azure_identity": "azure", "azure_mgmt_securityinsight": "azure",
                    "azure_monitor_query": "azure"}
    banned = {paid_imports.get(p, p) for p in paid}

    free = ["cli", "inventory", "report",
            "validate", "tabledrift", "config", "services", "catalog",
            "catalog.table_techniques", "correlation", "data_plane_operations"]
    modules = _module_names()
    # A name on that list that is not in the tree used to `continue`, so the
    # list failed OPEN: `report_detections` was deleted and silently stopped
    # being checked, and `recommend` went the same way. A rename would have
    # quietly dropped any of these. Missing now means the list is wrong and
    # says so.
    absent = sorted(n for n in free if modules.get(n) is None)
    assert absent == [], (
        f"these are on the free-command list and not in the tree: {absent}. "
        "Remove them, or fix the name -- do not let the check skip them."
    )
    offenders = []
    for name in free:
        path = modules.get(name)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [(node.module or "").split(".")[0]] if not node.level else []
            else:
                continue
            offenders += [(name, n) for n in names if n in banned]
    assert offenders == [], (
        f"free commands import {sorted({n for _m, n in offenders})}, which is "
        f"only in the `design` extra: {offenders[:4]}"
    )
