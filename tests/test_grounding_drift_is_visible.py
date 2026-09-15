"""A remote grounding file changing must leave a trace.

`DOCS_BASE` tracks `main` and its markdown is fetched at RUN TIME, then appended
to the model's context inside <live_documentation> (`engine.fetch_grounding`).
It is grounding, not verification: a change upstream changes this tool's output,
and there was no signal at all.

A reviewer's first version of this finding said to pin both remote URLs to
commits. That is right for the docs and wrong for MITRE -- freezing ATT&CK data
is the opposite of what a detection tool wants -- and the rebuttal that followed
covered MITRE and quietly generalised to both. A hash keeps the content current
and makes the change visible, which is what was actually missing.

NOT a gate, deliberately. A documentation page legitimately changes, and
refusing to run because Microsoft edited a table reference would be worse than
the drift.
"""
import asyncio

import httpx
import pytest

from pylon import grounding


@pytest.fixture(autouse=True)
def _leave_the_cache_as_we_found_it():
    """These tests put fabricated bodies in the module-level fetch cache, keyed
    by the real MITRE URL. Clearing only at the START leaked them into whatever
    ran next -- the phase-two technique checks read that cache and saw "first
    ever read" instead of the ATT&CK bundle. Four tests failed in the suite and
    passed alone, which is the signature."""
    saved_cache = dict(grounding._cache)
    saved_seen = dict(grounding._SEEN)
    grounding._cache.clear()
    grounding._SEEN.clear()
    yield
    grounding._cache.clear()
    grounding._cache.update(saved_cache)
    grounding._SEEN.clear()
    grounding._SEEN.update(saved_seen)


def _serve(body: str, monkeypatch):
    class _Resp:
        status_code = 200
        text = body

    class _Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, _url): return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)


def test_a_changed_source_is_logged_with_both_hashes(monkeypatch, caplog):
    url = grounding.MITRE_URL

    _serve("original documentation", monkeypatch)
    asyncio.run(grounding._fetch_cached(url))

    grounding._cache.clear()                 # force a refetch, not a TTL hit
    _serve("documentation, edited upstream", monkeypatch)
    with caplog.at_level("WARNING"):
        body = asyncio.run(grounding._fetch_cached(url))

    assert body == "documentation, edited upstream", "the fetch was blocked"
    assert any("grounding source changed" in r.message for r in caplog.records), \
        [r.message for r in caplog.records]


def test_an_unchanged_source_is_silent(monkeypatch, caplog):
    url = grounding.MITRE_URL
    _serve("same every time", monkeypatch)
    asyncio.run(grounding._fetch_cached(url))
    grounding._cache.clear()
    with caplog.at_level("WARNING"):
        asyncio.run(grounding._fetch_cached(url))
    assert not [r for r in caplog.records if "grounding source changed" in r.message]


def test_the_first_fetch_is_silent(monkeypatch, caplog):
    """Nothing to compare against yet. Warning on a first read would make the
    signal noise on every fresh process."""
    _serve("first ever read", monkeypatch)
    with caplog.at_level("WARNING"):
        asyncio.run(grounding._fetch_cached(grounding.MITRE_URL))
    assert not [r for r in caplog.records if "grounding source changed" in r.message]


def test_drift_does_not_block_the_run(monkeypatch):
    """A gate here would refuse to run because Microsoft edited a doc page."""
    _serve("a", monkeypatch)
    asyncio.run(grounding._fetch_cached(grounding.MITRE_URL))
    grounding._cache.clear()
    _serve("b", monkeypatch)
    assert asyncio.run(grounding._fetch_cached(grounding.MITRE_URL)) == "b"


def test_the_event_name_is_declared():
    from pylon.logs import EVENTS
    assert "grounding_drift" in EVENTS
