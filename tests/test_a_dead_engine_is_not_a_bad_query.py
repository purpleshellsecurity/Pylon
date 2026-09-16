"""An unreachable KQL engine has no opinion about your query.

Round ten ran with a kustainer that died mid-run -- the documented Rosetta crash
on Apple silicon, exit 133 -- and every detection after it was condemned:

    BAD  the real KQL engine refused this query: ConnectError: [Errno 61]
         Connection refused  Fix exactly what it names.

The engine refused nothing. Five correct detections were marked invalid, each
re-prompted, and the run cost $0.45 to produce nothing valid. The same five
scored 5 of 5 for $0.22 against a live container.

The cause was that `_http_executor` caught `httpx.HTTPError` -- which
`ConnectError` is -- and returned `(False, message)`, the same pair a semantic
rejection returns. The caller could not tell "your query is wrong" from "I could
not ask".
"""
import httpx
import pytest

from pylon import kusto_offline
from pylon.models import OfflineCheck


def test_a_refused_connection_raises_rather_than_returning_a_verdict(monkeypatch):
    def boom(*_a, **_k):
        raise httpx.ConnectError("[Errno 61] Connection refused")

    monkeypatch.setattr(httpx, "post", boom)
    run = kusto_offline._http_executor("http://localhost:8080")
    with pytest.raises(kusto_offline.EngineUnreachable) as exc:
        run("StorageBlobLogs | count")
    assert "Connection refused" in str(exc.value)


def test_a_kusto_semantic_error_is_still_a_verdict(monkeypatch):
    """The other half. A 400 carrying Kusto's own message IS about the query and
    must keep flowing through as a refusal."""
    class Res:
        status_code = 400
        text = '{"error": {"message": "Failed to resolve column \'Nope\'"}}'

    monkeypatch.setattr(httpx, "post", lambda *_a, **_k: Res())
    ok, error = kusto_offline._http_executor("http://localhost:8080")("q")
    assert ok is False
    assert "Failed to resolve" in error


def test_unreachable_leaves_the_gate_unrun_not_failed():
    """`ran=False` means the gate did not run, so nothing downstream may read a
    verdict out of it. `unreachable` separates a dead engine from one that was
    never configured -- the first is a broken run, the second is a choice."""
    dead = OfflineCheck(ran=False, unreachable=True, error="ConnectError")
    absent = OfflineCheck(ran=False, error="no kustainer endpoint configured")
    assert dead.ran is False and dead.ok is False
    assert dead.unreachable and not absent.unreachable


def test_the_engine_stops_the_run_rather_than_billing_for_ungated_queries():
    """Continuing would ship every remaining detection unparsed while still
    paying for model calls. The codebase's own position is that an unparseable
    detection shipping clean is the thing this gate exists to stop."""
    import inspect

    from pylon import engine

    # `_checked` is nested inside `run_detection_phase`, so the gate is read
    # from the enclosing function.
    src = inspect.getsource(engine.run_detection_phase)
    assert "offline.unreachable" in src, (
        "the engine does not distinguish a dead parser from a rejected query")
    assert "EngineGone" in src, "a dead parser does not stop the run"
    # And it must NOT fold the transport error into the detection's errors.
    between = src.split("offline.unreachable")[1].split('_gate("engine"')[0]
    assert "merge_results" not in between, (
        "a transport failure is being merged into the detection's result")


def test_engine_gone_is_its_own_error_not_a_validation_failure():
    """Raised rather than returned, because it is not a fact about a detection.
    Anything that catches it must not treat it as 'this query was bad'."""
    from pylon.engine import EngineGone

    assert issubclass(EngineGone, RuntimeError)
    from pylon.validation.validate_kql import ValidationResult
    assert not issubclass(EngineGone, ValidationResult.__class__)
