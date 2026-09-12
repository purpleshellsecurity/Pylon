"""A deadline that fires even when the event loop cannot.

`_arun` wraps every model call in `asyncio.wait_for`, and a run still sat for
EIGHTEEN HOURS on a call with a fifteen-minute limit. Its log holds two lines
and then nothing:

    00:13:05  phase_start         writing the incident-response playbook
    00:13:05  model_call_started  model call started

`wait_for` schedules its cancellation ON the event loop, so it can only fire if
the loop is still turning and the callee honours cancellation. Measured, both
assumptions break:

    inner behaviour                        0.5s wait_for
    an async await                         fires
    a SYNC call blocking the event loop    NEVER FIRES (ran 3.0s)
    asyncio.to_thread                      fires
    swallowing CancelledError              NEVER FIRES (ran 3.5s)

Neither failing case is under Pylon's control: they are inside the HTTP and
agent client stack. So the guard cannot live on the loop.

SIGALRM is delivered by the kernel and interrupts a blocked syscall, which is
exactly the case `wait_for` cannot reach. It is a BACKSTOP, not a replacement:
`wait_for` stays, because it unwinds cleanly and lets a hung call take the
ordinary retry path. This fires only when that has already failed to, and its
job is to end the process with a log line rather than to recover.

Main thread and Unix only -- `signal.setitimer` requires both. Elsewhere it is a
no-op, which leaves `wait_for` alone as the guard, exactly as before.
"""

from __future__ import annotations

import contextlib
import signal
import threading

from .logs import get_logger

log = get_logger(__name__)


class DeadlineExceeded(Exception):
    """The wall-clock deadline passed with the call still in flight."""


def available() -> bool:
    """True when a real deadline can be armed here."""
    return (hasattr(signal, "SIGALRM")
            and hasattr(signal, "setitimer")
            and threading.current_thread() is threading.main_thread())


@contextlib.contextmanager
def deadline(seconds: float, what: str):
    """Raise DeadlineExceeded in the main thread if `seconds` elapse.

    A no-op when `seconds` is zero or the platform cannot arm a timer, so the
    caller never has to ask which it got.
    """
    if seconds <= 0 or not available():
        yield
        return

    def fire(signum, frame):
        # The only record that will exist. Whatever is holding the process is
        # about to be interrupted at an arbitrary point, so say what was
        # outstanding before unwinding anything.
        log.error("%s exceeded its %.0fs deadline and was interrupted", what, seconds,
                  extra={"event": "deadline_exceeded", "what": what, "limit_s": seconds})
        raise DeadlineExceeded(f"{what} exceeded {seconds:.0f}s")

    previous = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
