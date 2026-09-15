"""Every log line carries the run id, and the log says what was asked for.

The JSONL was already structured and still could not be joined to anything. A
run writes a plan, detections, playbooks and verdicts, all of which now carry a
run id, and the record of what produced them carried none -- so "which log line
belongs to this report" had no answer.

The filter sits on the HANDLERS, not the logger. A Logger's filters run only for
records logged directly to it; a record from `pylon.engine` reaches the root
logger's handlers without ever passing the root logger's filters. The first
version of this put it on the logger and stamped nothing, because every real
call site uses a child logger.
"""

import json
import logging

import pytest

from pylon import logs, provenance


@pytest.fixture
def fresh(monkeypatch, tmp_path):
    monkeypatch.setattr(logs, "_configured", False)
    monkeypatch.setattr(logs, "_jsonl_path", None)
    monkeypatch.setattr(provenance, "_RUN_ID", None)
    monkeypatch.setenv("PYLON_RUN_ID", "test-run-7")
    root = logging.getLogger("pylon")
    for h in list(root.handlers):
        root.removeHandler(h)
    path = tmp_path / "run.jsonl"
    logs.configure(jsonl=path)
    yield path
    for h in list(root.handlers):
        root.removeHandler(h)


def _lines(path):
    return [json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def test_a_record_from_a_child_logger_is_stamped(fresh):
    """Every real call site is a child. This is the case the first fix missed."""
    logs.get_logger("pylon.engine").info("x", extra={"event": "e"})
    assert _lines(fresh)[0]["run_id"] == "test-run-7"


def test_the_structured_fields_survive_alongside_it(fresh):
    logs.get_logger("pylon.validate").warning(
        "failed", extra={"event": "workspace_query_failed", "elapsed_s": 1.5})
    got = _lines(fresh)[0]
    assert got["event"] == "workspace_query_failed"
    assert got["elapsed_s"] == 1.5
    assert got["run_id"] == "test-run-7"


def test_an_explicit_run_id_is_not_overwritten(fresh):
    """A caller replaying someone else's run must be able to say whose."""
    logs.get_logger("pylon.x").info("x", extra={"run_id": "someone-elses"})
    assert _lines(fresh)[0]["run_id"] == "someone-elses"


def test_the_id_matches_what_the_artefacts_are_stamped_with(fresh):
    """One id, or the join does not close."""
    logs.get_logger("pylon.x").info("x")
    assert _lines(fresh)[0]["run_id"] == provenance.stamp("x").run_id


# --- which phase a record belongs to ----------------------------------------
# `model_call` recorded its tokens and elapsed time and had no idea which phase
# it belonged to, so the log could say what a run cost in total and never what
# phase 2 cost. Carried ambiently rather than threaded through every call site.

import asyncio

from pylon import logs as _logs


def test_a_record_inside_a_phase_is_tagged(fresh):
    with _logs.phase("run_detection_phase"):
        _logs.get_logger("pylon.engine").info("x", extra={"event": "model_call", "tokens": 1800})
    got = _lines(fresh)[0]
    assert got["phase"] == "run_detection_phase" and got["tokens"] == 1800


def test_a_record_outside_one_is_not(fresh):
    _logs.get_logger("pylon.engine").info("x")
    assert "phase" not in _lines(fresh)[0]


def test_the_phase_does_not_leak_past_the_block(fresh):
    """Entering by hand without exiting would tag everything after it."""
    with _logs.phase("run_threat_phase"):
        pass
    _logs.get_logger("pylon.engine").info("after")
    assert "phase" not in _lines(fresh)[0]


def test_the_decorator_covers_an_async_body_and_survives_awaits(fresh):
    """The phases are async and the model calls inside them are awaited, so the
    context has to cross an await or it tags nothing that matters."""

    @_logs.in_phase("run_playbook_phase")
    async def work():
        await asyncio.sleep(0)
        _logs.get_logger("pylon.engine").info("deep", extra={"event": "model_call"})

    asyncio.run(work())
    assert _lines(fresh)[0]["phase"] == "run_playbook_phase"


def test_an_explicit_phase_wins(fresh):
    with _logs.phase("run_threat_phase"):
        _logs.get_logger("pylon.x").info("x", extra={"phase": "run_detection_phase"})
    assert _lines(fresh)[0]["phase"] == "run_detection_phase"
