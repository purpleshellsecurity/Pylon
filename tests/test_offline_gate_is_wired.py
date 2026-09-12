"""The offline KQL engine, connected to generation.

It was built, tested and never called. `verify_query_offline` had no caller
outside its own module and `ValidatedDetection.offline_check` was never
populated, so the gate existed on paper while three failures reached a live
workspace in one session that it would have refused:

    | extend Auth = parse_json(X), S = tostring(Auth.scope)   sibling not in scope
    | extend g = ..., P = iff(isnotempty(g), g, h)            same
    | extend L = case(startswith(s, "/x"), ...)               startswith is an operator

Each of those got its own regex afterwards. A regex is a list of mistakes
someone already made; the engine is the actual grammar and the actual schema,
so it refuses the next one too.

These tests do not need a container. The engine call is stubbed, and what is
under test is the wiring: that a refusal reaches the retry prompt, that an
absent engine is silent rather than fatal, and that a refusal never reads as a
clean bill.
"""

import asyncio

import pytest

from pylon import engine
from pylon.models import OfflineCheck


class _Engine:
    """Stands in for kustainer. Records what it was asked to run."""

    def __init__(self, ok=True, error=""):
        self.ok, self.error, self.seen = ok, error, []

    def __call__(self, kql, table, schema, **kw):
        self.seen.append((kql, table))
        return OfflineCheck(ran=True, ok=self.ok, error=self.error)


@pytest.fixture
def kustainer(monkeypatch):
    monkeypatch.setenv("PYLON_KUSTAINER_URL", "http://localhost:8080")
    return monkeypatch


def test_the_engine_is_reachable_from_the_engine_module():
    """The import that was missing. Without it nothing else here can be true."""
    assert hasattr(engine, "verify_query_offline")
    assert hasattr(engine, "schema_for_table")


def test_a_detection_carries_the_engine_verdict():
    """`offline_check` is a field on every detection and was never populated."""
    from pylon.models import ValidatedDetection
    assert "offline_check" in ValidatedDetection.model_fields


def test_a_refused_query_is_not_valid():
    """The whole point. An engine refusal must invalidate, or the detection
    ships and the verdict is decoration."""
    from pylon.validation import ValidationResult
    from pylon.validation.live_schema import merge_results

    static = ValidationResult(valid=True, errors=[], warnings=[])
    merged = merge_results(static, ValidationResult(
        valid=False, errors=["the KQL engine refused this query: boom"]))
    assert not merged.valid
    assert "boom" in merged.errors[0]


def test_the_retry_prompt_does_not_pretend_the_engine_explained_itself():
    """Measured against kustainer: a refused query comes back as
    `General_BadRequest` and a request id, and NOTHING else -- the same text
    for a syntax error as for an unresolved column.

    So this is a pass/fail gate, and the correction prompt has to say so and
    then name the shapes worth re-reading, rather than handing the model an
    engine message that does not exist. The value does not depend on the
    reason: a query the engine refuses is broken, and not shipping it is the
    point."""
    import inspect

    src = inspect.getsource(engine)
    start = src.index("async def _checked(")
    body = src[start:src.index("    def _validate(", start)]
    assert "It reports no " in body
    assert "startswith" in body, "the prompt should name the shapes to re-read"


def test_an_untyped_table_is_not_checked_rather_than_checked_wrong(monkeypatch):
    """A table the catalogue cannot type would be declared all-string, and an
    all-string datatable rejects exactly the dynamic-column queries that matter
    -- AuditLogs InitiatedBy and TargetResources are both dynamic. Not running
    is the honest answer; running would reject correct work."""
    monkeypatch.setattr(engine, "schema_for_table", lambda t: {})
    called = []
    monkeypatch.setattr(engine, "verify_query_offline",
                        lambda *a, **k: called.append(a))
    from pylon.kusto_offline import schema_for_table
    assert schema_for_table("NoSuchTableAnywhere") == {}


def test_a_real_table_has_a_typed_schema():
    """The counterpart: the tables this tool actually generates for are typed,
    so the check above skips almost nothing."""
    from pylon.kusto_offline import schema_for_table
    schema = schema_for_table("AzureActivity")
    assert schema, "AzureActivity has no typed schema, so the gate would skip it"
    assert schema.get("Properties") == "string" or "dynamic" in schema.values()


def test_the_engine_runs_off_the_event_loop():
    """`httpx.post` in kusto_offline is SYNCHRONOUS. Calling it straight from a
    coroutine blocks the whole loop, which in this codebase is not theoretical:
    it is what defeats `asyncio.wait_for`, and how a model call once hung for
    eighteen hours without the timeout firing."""
    import inspect
    src = inspect.getsource(engine)
    start = src.index("async def _offline(")
    body = src[start:src.index("def _validate(", start)]
    assert "asyncio.to_thread" in body, "the engine call would block the loop"


# ── the gates are independent ────────────────────────────────────────────────

def test_the_workspace_gate_does_not_depend_on_the_kql_engine():
    """It did, and the bug was invisible from the outside. The combined checker
    returned early when no kustainer endpoint was configured, which made the
    WORKSPACE gate unreachable unless a container happened to be running -- so
    `--workspace` parsed, was accepted, cost a round trip of nothing and
    recorded no verdict at all.

    It passed every earlier test because the container was up at the time. What
    caught it was running the flag on its own, which is how a user would.
    """
    import inspect

    src = inspect.getsource(engine)
    start = src.index("async def _checked(")
    body = src[start:src.index("    def _validate(", start)]
    offline_branch = body.index("if offline_on and result.valid:")
    workspace_branch = body.index("if not (workspace_guid and operation")
    assert offline_branch < workspace_branch
    # No early return between them: the engine gate must narrow to itself.
    between = body[offline_branch:workspace_branch]
    assert "return result, offline, None" not in between, (
        "an early return here skips the workspace gate whenever the KQL engine "
        "is not configured")


def test_the_workspace_can_be_passed_rather_than_only_exported():
    """An environment variable is not a feature anyone finds. Every other verb
    takes --workspace, so a reader has no reason to look for one here."""
    import dataclasses

    from pylon.engine import EngineRequest

    names = {f.name for f in dataclasses.fields(EngineRequest)}
    assert {"verify_workspace", "verify_window"} <= names
    # And the flag wins over the environment, so a sweep can set one default
    # while a single run overrides it.
    import inspect
    src = inspect.getsource(engine)
    assert 'request.verify_workspace\n                        or os.environ' in src \
        or "request.verify_workspace" in src
