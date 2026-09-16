"""Diagnostics must survive the conditions that most need them.

The old live meter was gated on `sys.stdout.isatty()`, so a redirected or CI run
emitted nothing at all — and a run that stalls at 03:00 in CI is precisely the one
with no terminal to scroll back through. These pin the properties that made that
possible, so it cannot come back.
"""

import json
import logging

import pytest

from pylon import logs


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    """configure() is idempotent by design; reset it between tests."""
    monkeypatch.setattr(logs, "_configured", False)
    monkeypatch.setattr(logs, "_jsonl_path", None)
    root = logging.getLogger("pylon")
    for h in list(root.handlers):
        root.removeHandler(h)
    yield
    for h in list(root.handlers):
        root.removeHandler(h)


def _events(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_the_jsonl_file_is_written_with_no_tty(tmp_path, capsys):
    """The whole defect in one assertion: not a terminal, still a record."""
    p = tmp_path / "run.jsonl"
    logs.configure(jsonl=p)
    logs.get_logger("pylon.test").info("phase 2 started", extra={"event": "phase_start"})
    assert p.exists(), "a run with redirected output must still leave a log"
    assert _events(p)[0]["event"] == "phase_start"


def test_diagnostics_go_to_stderr_not_stdout(tmp_path, capsys):
    """stdout is the ARTIFACT. A diagnostic line landing there corrupts a piped
    report, which is why the two channels are separate rather than levelled."""
    logs.configure(jsonl=tmp_path / "run.jsonl")
    logs.get_logger("pylon.test").warning("backing off 5s")
    captured = capsys.readouterr()
    assert "backing off" in captured.err
    assert captured.out == "", "diagnostics must never touch stdout"


def test_structured_fields_survive_into_the_file(tmp_path):
    """Prose is not enough. `backoff_s` has to be a number a query can sum."""
    p = tmp_path / "run.jsonl"
    logs.configure(jsonl=p)
    logs.get_logger("pylon.test").warning(
        "rate limited", extra={"event": "retry", "backoff_s": 40.0, "attempt": 3}
    )
    row = _events(p)[0]
    assert row["backoff_s"] == 40.0
    assert row["attempt"] == 3


def test_the_file_records_debug_even_when_the_console_does_not(tmp_path, capsys):
    """The console stays readable at INFO; the file keeps everything, because the
    cost of a line is nothing next to not being able to answer 'what was it doing
    for those fifteen minutes'."""
    p = tmp_path / "run.jsonl"
    logs.configure(level="INFO", jsonl=p)
    logs.get_logger("pylon.test").debug("model call started")
    assert "model call started" not in capsys.readouterr().err
    assert any(r["msg"] == "model call started" for r in _events(p))


def test_an_unwritable_log_location_does_not_kill_the_run(tmp_path, capsys):
    """A paid run must not die because a log directory is read-only."""
    blocked = tmp_path / "afile"
    blocked.write_text("not a directory", encoding="utf-8")
    assert logs.configure(jsonl=blocked / "nested" / "run.jsonl") is None
    logs.get_logger("pylon.test").info("still alive")
    assert "still alive" in capsys.readouterr().err


def test_configure_is_idempotent(tmp_path):
    """Entry points may each call it; handlers must not stack up and duplicate
    every line."""
    p = tmp_path / "run.jsonl"
    logs.configure(jsonl=p)
    logs.configure(jsonl=tmp_path / "other.jsonl")
    logs.get_logger("pylon.test").info("once")
    assert len(_events(p)) == 1


def test_a_retry_announces_its_reason_and_backoff(tmp_path, monkeypatch):
    """The single most expensive silence today. A call backing off 5s -> 60s
    printed nothing, so a throttled run and a working run looked identical from
    outside — three runs were killed on guesses because of it."""
    import asyncio

    from pylon import engine

    p = tmp_path / "run.jsonl"
    logs.configure(jsonl=p)
    async def _no_sleep(_seconds):
        """Not `asyncio.sleep(0)` — engine.asyncio IS the asyncio module, so a stub
        that calls asyncio.sleep calls itself. Recursion, not a fast test."""
        return

    monkeypatch.setattr(engine.asyncio, "sleep", _no_sleep)

    calls = {"n": 0}

    class _Throttled:
        async def run(self, prompt, options=None):
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("Error code: 429 - rate_limit_exceeded")

            class R:
                text = "ok"

                def __init__(self):
                    self.usage_details = {"input_token_count": 1, "output_token_count": 1}

            return R()

    asyncio.run(engine._run_with_retry(_Throttled(), "prompt", options={}))

    retries = [r for r in _events(p) if r.get("event") == "retry"]
    assert len(retries) == 2, "every retry must be announced, not just the last"
    assert retries[0]["reason"] == "rate_limit"
    assert retries[0]["backoff_s"] > 0, "the operator needs to know HOW LONG"
    assert retries[1]["backoff_s"] > retries[0]["backoff_s"], "backoff growth is visible"


def test_a_hung_model_call_times_out_and_retries(tmp_path, monkeypatch):
    """Measured, not hypothesised: a call started 20:13:14 and had still not
    returned 103 minutes later, with 0 retries and 0 failures logged. The retry
    path fires only on EXCEPTIONS, so a call that hangs rather than erroring was
    invisible to it and blocked the whole run indefinitely.

    The ceiling is deliberately generous. Calls on this deployment finish in
    38-145s and the slowest that ever COMPLETED took 680s; abandoning one that
    would have succeeded pays for the same work twice. The timeout breaks a hang,
    it does not trim a slow call.
    """
    import asyncio

    from pylon import engine

    p = tmp_path / "run.jsonl"
    logs.configure(jsonl=p)
    monkeypatch.setattr(engine, "MODEL_CALL_TIMEOUT", 0.05)

    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(engine.asyncio, "sleep", _no_sleep)

    state = {"n": 0}

    class _HangsOnce:
        async def run(self, prompt, options=None):
            state["n"] += 1
            if state["n"] == 1:
                # NOT asyncio.sleep — that is stubbed to a no-op for the backoff,
                # which would make this "hang" return instantly and test nothing.
                # An Event nobody sets blocks for real.
                await asyncio.Event().wait()

            class R:
                text = "ok"

                def __init__(self):
                    self.usage_details = {"input_token_count": 1, "output_token_count": 1}

            return R()

    asyncio.run(engine._run_with_retry(_HangsOnce(), "prompt", options={}))

    rows = _events(p)
    assert any(r.get("event") == "model_call_timeout" for r in rows), (
        "a hung call must be abandoned and SAID so"
    )
    assert any(r.get("event") == "retry" for r in rows), (
        "and it must take the retry path, not raise straight out of the run"
    )
    assert state["n"] == 2, "the retry actually happened"
