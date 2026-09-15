"""A deadline that fires when the event loop cannot.

Every model call is wrapped in `asyncio.wait_for`, and a run still sat for
eighteen hours on a call with a fifteen-minute limit. Its log holds two lines:

    00:13:05  phase_start         writing the incident-response playbook
    00:13:05  model_call_started  model call started

`wait_for` schedules its cancellation ON the loop, so it fires only if the loop
is turning and the callee honours cancellation. Both assumptions are breakable
from inside a third-party client, and the tests below break them.
"""

import asyncio
import time

import pytest

from pylon.watchdog import DeadlineExceeded, available, deadline

pytestmark = pytest.mark.skipif(not available(), reason="no SIGALRM on the main thread")


async def _blocks_the_loop():
    """A synchronous call inside a coroutine. `wait_for` cannot interrupt it:
    its cancellation is a callback on a loop that is not turning."""
    time.sleep(2)


async def _swallows_cancellation():
    try:
        await asyncio.sleep(30)
    except asyncio.CancelledError:
        await asyncio.sleep(2)


def _run(coro_fn, *, soft, hard):
    async def main():
        with deadline(hard, "model call"):
            await asyncio.wait_for(coro_fn(), timeout=soft)
    started = time.monotonic()
    try:
        asyncio.run(main())
        return "completed", time.monotonic() - started
    except DeadlineExceeded:
        return "deadline", time.monotonic() - started
    except (asyncio.TimeoutError, TimeoutError):
        return "wait_for", time.monotonic() - started


def test_the_loop_timeout_alone_cannot_stop_a_blocking_call():
    """The failure that cost eighteen hours, reproduced."""
    async def main():
        await asyncio.wait_for(_blocks_the_loop(), timeout=0.2)
    started = time.monotonic()
    asyncio.run(main())                     # returns normally despite the limit
    assert time.monotonic() - started > 1.5, (
        "if this ever raises TimeoutError the backstop is no longer needed")


def test_the_deadline_stops_a_call_that_blocks_the_loop():
    outcome, elapsed = _run(_blocks_the_loop, soft=0.2, hard=0.6)
    assert outcome == "deadline", outcome
    assert elapsed < 1.5, "it must not wait for the blocking call to finish"


def test_the_deadline_stops_a_call_that_swallows_cancellation():
    outcome, _ = _run(_swallows_cancellation, soft=0.2, hard=0.6)
    assert outcome == "deadline", outcome


def test_the_soft_timeout_still_leads_on_an_ordinary_hang():
    """The backstop must not pre-empt the path that unwinds cleanly and retries."""
    async def ordinary():
        await asyncio.sleep(30)
    outcome, _ = _run(ordinary, soft=0.2, hard=5)
    assert outcome == "wait_for", outcome


def test_a_call_that_finishes_is_untouched():
    async def quick():
        await asyncio.sleep(0)
    assert _run(quick, soft=5, hard=10)[0] == "completed"


def test_the_timer_is_disarmed_afterwards():
    """A timer left armed fires during whatever runs next."""
    with deadline(0.5, "first"):
        pass
    time.sleep(0.8)          # would raise here if the timer survived the block


def test_a_zero_deadline_is_a_no_op():
    with deadline(0, "disabled"):
        time.sleep(0.1)
