"""`@workflow` changed shape, and six call sites called the old one.

agent_framework 1.13 returned a `FunctionalWorkflow` from `@workflow` and you
called `.run` on it. From 1.18 it returns a `FunctionalWorkflowDefinition`,
`.run` is gone, and the runnable comes from `.build()`:

    AttributeError: 'FunctionalWorkflowDefinition' object has no attribute 'run'

Twelve integration tests failed on the bump, and `cli.py` called it too -- so
`pylon design detections` was broken, not only the suite. The `.run` signature
is identical either side; the build hop is the whole difference.

`engine.runnable()` owns that hop, in one place, because functional workflows
are flagged EXPERIMENTAL upstream ("may change or be removed in future versions
without notice") and there were six callers: the CLI, the eval harness, and four
test files.

WHAT THIS CANNOT DO
-------------------
It exercises whichever version is installed. The suite was run green against
BOTH 1.13.0 and 1.18.0 by hand when this landed; nothing here re-pins the
dependency to prove it again, and CI runs one version at a time.
"""

import inspect

import pytest

from pylon import engine


def test_the_runnable_has_a_run():
    """The whole point: whatever `@workflow` produced, this can be run."""
    assert hasattr(engine.runnable(), "run")


def test_it_is_built_once():
    """1.13's `pylon` WAS the workflow -- one module-level object reused across
    runs. `build()` hands back a fresh one per call, so building per run would
    quietly change that, and checkpoint resume runs `.run` twice against what
    has to be one workflow."""
    assert engine.runnable() is engine.runnable()


def test_the_run_signature_still_takes_what_the_callers_pass():
    """The callers pass `message`, `stream`, `responses` and
    `checkpoint_storage`. If a future version drops one, fail here rather than
    in a paid run."""
    sig = inspect.signature(engine.runnable().run)
    for name in ("message", "stream", "responses", "checkpoint_storage"):
        assert name in sig.parameters, f"`run` no longer takes {name}: {sig}"


def test_nothing_calls_the_old_name_any_more():
    """Six call sites had to move. A seventh added later would fail only on the
    version that is not installed, which is the worst way to find out."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    offenders = []
    for sub in ("src", "tests", "scripts"):
        for path in (root / sub).rglob("*.py"):
            if path.name == pathlib.Path(__file__).name:
                continue
            for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "pylon.run(" in line.replace("engine.", ""):
                    offenders.append(f"{path.relative_to(root)}:{i}")
    assert offenders == [], (
        "these call the workflow object directly instead of `engine.runnable()`, "
        f"which breaks on agent_framework >= 1.18: {offenders}")


@pytest.mark.parametrize("name", ["agent-framework-core", "agent-framework-openai"])
def test_the_pin_is_exact(name):
    """Both are pinned with `==`, deliberately: this dependency has now made a
    breaking change inside a minor bump, and the API is flagged experimental."""
    import pathlib
    import re

    text = (pathlib.Path(__file__).resolve().parents[1]
            / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(rf'"{re.escape(name)}==\d+\.\d+\.\d+"', text), (
        f"{name} is not pinned to an exact version")
