"""A redirect must not carry a grounding fetch off the allowlist.

`_is_allowed_fetch_url` is evaluated ONCE, against the URL about to be
requested. With `follow_redirects=True` a 30x response then fetched whatever it
named, with neither the host check nor the pinned-path check re-run -- so both
layers of a deliberately two-layer guard could be stepped around by the server
being asked.

OWASP's SSRF sheet is explicit: "disable the support for the following of the
redirection in your web client in order to prevent the bypass of the input
validation".

Not live: raw.githubusercontent.com does not redirect valid paths off-host. It
is the guard that has to hold, not the current behaviour of one host -- and what
lands on the other side is text interpolated into a model prompt.
"""
import asyncio
import inspect

import httpx
import pytest

from pylon import grounding


def test_the_client_does_not_follow_redirects():
    src = inspect.getsource(grounding._fetch_cached)
    assert "follow_redirects=False" in src, (
        "the grounding client follows redirects, which leaves the allowlist "
        "behind on the first hop")
    assert "follow_redirects=True" not in src


def test_a_redirect_yields_nothing_rather_than_the_redirect_target(monkeypatch):
    """Behavioural, not just the flag. A 302 is a non-200, so the body is
    discarded and the run grounds on nothing -- which is the safe failure."""
    calls = []

    class _Resp:
        status_code = 302
        text = "attacker content that must never be grounded on"

    class _Client:
        def __init__(self, *a, **k):
            calls.append(k)
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url):    return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    grounding._cache.clear()
    body = asyncio.run(grounding._fetch_cached(grounding.MITRE_URL))

    assert body == "", "a redirect body reached the caller"
    assert calls and calls[0].get("follow_redirects") is False, calls


def test_an_off_allowlist_url_makes_no_request_at_all(monkeypatch):
    """The first layer still holds: a rejected URL must not even open a client."""
    opened = []
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda *a, **k: opened.append(1))
    grounding._cache.clear()
    assert asyncio.run(grounding._fetch_cached("https://evil.example/x")) == ""
    assert opened == [], "a rejected URL still opened a connection"


@pytest.mark.parametrize("url", [
    "https://raw.githubusercontent.com/../../../attacker/repo/main/payload",
    "https://raw.githubusercontent.com/attacker/repo/main/payload",
    "https://evil.example/enterprise-attack.json",
    "http://169.254.169.254/latest/meta-data/",          # cloud metadata
])
def test_the_allowlist_still_rejects_what_it_was_written_for(url):
    assert grounding._is_allowed_fetch_url(url) is False, url
