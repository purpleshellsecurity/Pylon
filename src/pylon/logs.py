"""Diagnostics channel, separate from the product's output.

pylon had ~300 `print()` calls and no logger. Most of those prints are the
ARTIFACT — the report, the summary, the detection table — and they belong on
stdout. What was missing is the other thing entirely: a record of what the run is
DOING. Conflating the two is why a redirected run went completely dark.

So the split is explicit and load-bearing:

  stdout   what pylon produced. Stays `print()`. Pipe it, redirect it, diff it.
  stderr   what pylon is doing, human-readable. Never pollutes a piped artifact.
  jsonl    the same events, structured, always written to a file.

The last one matters most. A run that dies at 03:00 in CI leaves no terminal to
scroll back through, and the existing live meter was gated on
`sys.stdout.isatty()` — so exactly the runs that most needed a record produced
none. This file is written whether or not anyone is watching.

Level comes from PYLON_LOG_LEVEL (default INFO). The JSONL file always records
DEBUG regardless, because the cost of writing a line is nothing next to being
unable to answer "what was it doing for those fifteen minutes".
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import json
import logging
import os
import sys
import time
from pathlib import Path

_ROOT = "pylon"

# Every `extra={"event": ...}` name the codebase emits, declared once.
#
# These were fourteen string literals scattered across four modules with nothing
# naming them. A typo produces a new event silently, and deleting the last call
# site of one removes it from the record with nothing to notice -- which is the
# same drift that let the eval harness classify warnings by grepping the
# validator's prose. Anything reading this log (a dashboard, an alert, a "did
# the run get past phase 2" check) is coupled to these names, so they are a
# contract, and a contract nobody wrote down is one nobody can keep.
#
# `tests/test_event_vocabulary.py` holds this to the source in both directions:
# nothing emits an undeclared name, and nothing declared has lost its last
# emitter.
EVENTS: frozenset[str] = frozenset({
    # The invocation itself.
    "command",
    # Engine phases and the model calls inside them.
    "phase_start",
    "fanout",
    "model_call_started",
    "model_call",
    "model_call_failed",
    "model_call_timeout",
    "retry",
    "playbook_fill_retry",
    # Progress, for a run nobody is watching.
    "heartbeat",
    "unit_done",
    # The wall-clock backstop, when the loop-based timeout could not fire.
    "deadline_exceeded",
    # What the plan gate said about a vector, before a detection was paid for.
    # Phase 1 used to be told to cover the surface without being told how big it
    # is, so a two-operation surface produced five vectors. This records each
    # vector that could not be told apart from its siblings.
    "plan_gate",
    # Each validation gate's verdict on each ATTEMPT, with the query's hash.
    # The run log used to show two model calls and two workspace queries and
    # nothing about which gate rejected the first attempt or what it produced.
    # The hash is the join: three attempts that differ in text and land on the
    # same verdict is a loop cycling rather than converging, and that is only
    # visible with both halves recorded per attempt.
    "gate",
    # The workspace, and what was measured against it.
    "workspace_query",
    "workspace_query_failed",
    "verification",
})
_configured = False
_jsonl_path: Path | None = None


class _Human(logging.Formatter):
    """`HH:MM:SS  LEVEL  message` — timestamps, because the question is almost
    always "how long has it been sitting there"."""

    def format(self, record: logging.LogRecord) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(record.created))
        # INFO is every routine progress line, so labelling it says nothing and
        # costs a column. A level is shown only where it changes what the reader
        # should do -- which is what makes a warning stand out at a glance.
        mark = "" if record.levelno <= logging.INFO else f"  {record.levelname.lower()}"
        return f"  {ts}{mark}  {record.getMessage()}"


class _Jsonl(logging.Formatter):
    """One JSON object per line. Every `extra=` field is carried through, so a
    structured event ("detection 3 of 14 done, 4.2s, 1800 tokens") stays
    machine-readable instead of being flattened into prose."""

    _SKIP = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
        "message", "asctime", "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k not in self._SKIP:
                try:
                    json.dumps(v)
                    payload[k] = v
                except TypeError:
                    payload[k] = repr(v)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def log_path() -> Path | None:
    """Where this process is writing its JSONL run log, or None before setup."""
    return _jsonl_path


# The phase a record was emitted during, carried ambiently rather than passed.
#
# `model_call` already recorded its tokens and elapsed time and had no idea
# which phase it belonged to, so the run log could say what a run cost in total
# and never what phase 2 cost. Threading a `phase` argument down to every model
# call means changing every call site and getting it wrong somewhere; a context
# variable is set once at the phase boundary and every record inside it -- at
# any depth, across awaits -- carries it.
_PHASE: contextvars.ContextVar[str] = contextvars.ContextVar("pylon_phase", default="")


@contextlib.contextmanager
def phase(name: str):
    """Mark everything logged inside this block as belonging to `name`."""
    token = _PHASE.set(name)
    try:
        yield
    finally:
        _PHASE.reset(token)


def in_phase(name: str):
    """Mark an async function's whole body as one phase.

    A decorator rather than a `with` inside each body: the three phases ARE
    whole functions, and entering a context manager by hand without a matching
    exit leaks the phase into everything logged afterwards.
    """
    def decorate(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            with phase(name):
                return await fn(*args, **kwargs)
        return wrapper
    return decorate


class _RunId(logging.Filter):
    """Stamp the run id onto every record.

    The JSONL was already structured and still could not be joined to anything.
    A run writes a plan, detections, playbooks and verdicts, all of which now
    carry a run id -- and the log of what produced them carried none, so
    "which log line belongs to this report" had no answer. One field closes it.

    Imported lazily: `provenance` mints an id on first use, and a logging
    module that mints one at import time would do it before an entry point had
    a chance to honour PYLON_RUN_ID.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "run_id"):
            from .provenance import run_id
            record.run_id = run_id()
        current = _PHASE.get()
        if current and not hasattr(record, "phase"):
            record.phase = current
        return True


def configure(level: str | None = None, jsonl: Path | None = None) -> Path | None:
    """Install the handlers. Idempotent — safe to call from any entry point.

    Returns the JSONL path so the caller can tell the operator where to look;
    a log nobody can find is barely better than no log.
    """
    global _configured, _jsonl_path
    if _configured:
        return _jsonl_path

    root = logging.getLogger(_ROOT)
    root.setLevel(logging.DEBUG)  # handlers filter; the logger must not
    root.propagate = False

    # On the HANDLERS, not the logger. A Logger's filters run only for records
    # logged directly to it; a record from `pylon.engine` propagates to this
    # logger's handlers without ever passing its filters. Put it on the logger
    # and every real call site -- all of which use child loggers -- is missed,
    # which is exactly what the first version of this did.
    run_id_filter = _RunId()

    human = logging.StreamHandler(sys.stderr)
    human.addFilter(run_id_filter)
    human.setFormatter(_Human())
    human.setLevel(
        getattr(logging, (level or os.environ.get("PYLON_LOG_LEVEL", "INFO")).upper(), logging.INFO)
    )
    root.addHandler(human)

    target = jsonl or (
        Path(os.environ["PYLON_LOG_FILE"]) if os.environ.get("PYLON_LOG_FILE") else None
    )
    if target is None:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        target = Path(".pylon") / "logs" / f"run-{stamp}.jsonl"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # delay=True: the file is opened on the FIRST record, so a verb that
        # logs nothing (`config show`, `design list`) leaves no empty file
        # behind. Every entry point can then configure unconditionally.
        fh = logging.FileHandler(target, encoding="utf-8", delay=True)
        fh.addFilter(run_id_filter)
        fh.setFormatter(_Jsonl())
        fh.setLevel(logging.DEBUG)  # the file always gets everything
        root.addHandler(fh)
        _jsonl_path = target
    except OSError as exc:
        # An unwritable log directory must not kill a paid run. Say so once, on
        # the channel that still works, and carry on.
        root.warning("could not open the run log at %s (%s) — stderr only", target, exc)
        _jsonl_path = None

    _configured = True
    return _jsonl_path


def get_logger(name: str) -> logging.Logger:
    """A child of the pylon logger. `name` is normally __name__."""
    short = name.removeprefix("pylon.").removeprefix("pylon")
    return logging.getLogger(f"{_ROOT}.{short}" if short else _ROOT)
