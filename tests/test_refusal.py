"""Resilience to stochastic model refusals of structured-output calls.

A reasoning model occasionally answers a defensive-security prompt with prose
("I'm sorry, but I cannot assist...") instead of the required JSON, which makes
the structured-output parse raise. That must not crash a whole run on the first
try — retry, and only give up (cleanly) if it persists.
"""

import asyncio

import pytest

from pylon import engine
from pylon.engine import (
    ModelRefusalError,
    _is_rate_limit,
    _is_refusal,
    _run_with_retry,
)


class _Resp:
    def __init__(self):
        self.usage_details = None
        self.value = "ok"
        self.text = "ok"


class _FlakyAgent:
    """Raises `exc` for the first `fails` calls, then succeeds."""

    def __init__(self, fails, exc):
        self.fails = fails
        self.exc = exc
        self.calls = 0

    async def run(self, prompt, options=None):
        self.calls += 1
        if self.calls <= self.fails:
            raise self.exc
        return _Resp()


# The parse failure the OpenAI client raises when the model returns a refusal.
_REFUSAL = ValueError(
    "1 validation error for ThreatAnalysis\n  Invalid JSON: expected ident "
    '[type=json_invalid, input_value="I\'m sorry, but I cannot assist with that request."]'
)


def test_is_refusal_recognizes_the_parse_failure():
    assert _is_refusal(_REFUSAL)
    assert not _is_rate_limit(_REFUSAL)


def test_is_rate_limit_still_recognized():
    assert _is_rate_limit(RuntimeError("Error code: 429 rate_limit exceeded"))


def test_retry_recovers_from_a_transient_refusal(monkeypatch):
    monkeypatch.setattr(engine.asyncio, "sleep", lambda _s: _aret(None))
    agent = _FlakyAgent(fails=2, exc=_REFUSAL)  # refuses twice, then complies
    resp = asyncio.run(_run_with_retry(agent, "p", options={"response_format": object}))
    assert resp.value == "ok"
    assert agent.calls == 3


def test_persistent_refusal_raises_clean_error(monkeypatch):
    monkeypatch.setattr(engine.asyncio, "sleep", lambda _s: _aret(None))
    agent = _FlakyAgent(fails=99, exc=_REFUSAL)  # never complies
    with pytest.raises(ModelRefusalError):
        asyncio.run(_run_with_retry(agent, "p", options={"response_format": object}))
    assert agent.calls == engine.MAX_RETRIES


def test_non_retryable_error_propagates_immediately(monkeypatch):
    monkeypatch.setattr(engine.asyncio, "sleep", lambda _s: _aret(None))
    agent = _FlakyAgent(fails=99, exc=KeyError("boom"))
    with pytest.raises(KeyError):
        asyncio.run(_run_with_retry(agent, "p", options={"response_format": object}))
    assert agent.calls == 1  # not retried


async def _aret(v):
    return v
