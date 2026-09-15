"""A throttled run must say what was hit and how to fix it.

The default was 7,500 bytes of stack trace ending in `rate_limit_exceeded`. That
does not tell an operator — least of all a new one — that the cause is a capacity
number on their own Azure deployment, typically provisioned far below what their
subscription already grants. This repo names the exact RBAC permission when a
table read fails; a throttle earns the same.
"""

import pytest

from pylon.clients import rate_limit_help
from pylon.usage import record, reset_meter


@pytest.fixture
def azure_env(monkeypatch):
    monkeypatch.setenv("PYLON_PROVIDER", "azure-openai")
    monkeypatch.setenv("OPENAI_CHAT_MODEL", "gpt-5")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://acme-aoai.openai.azure.com")


def test_it_names_the_deployment_and_the_resource(azure_env):
    out = rate_limit_help()
    assert "gpt-5" in out
    assert "resource           acme-aoai" in out, (
        "the labelled resource line is what an operator scans for; finding the "
        "name buried in an az command further down is not the same thing"
    )


def test_it_reports_what_the_run_had_already_spent(azure_env):
    reset_meter()
    record({"input_token_count": 40_000, "output_token_count": 60_000})
    assert "100,000" in rate_limit_help(), (
        "the spend so far is the number that makes the limit concrete"
    )


def test_it_gives_the_command_that_fixes_it(azure_env):
    out = rate_limit_help()
    assert "az cognitiveservices account deployment create" in out
    assert "--sku-capacity" in out
    assert "usage list" in out, "checking the entitlement is half the answer"


def test_it_says_a_higher_ceiling_does_not_cost_more(azure_env):
    """The reason someone does not raise it is fear of the bill. GlobalStandard
    bills per token consumed, so the ceiling is free — say so, or the advice is
    ignored."""
    out = rate_limit_help().lower()
    assert "bills per token used" in out
    assert "does not cost more" in out


def test_it_offers_the_no_azure_change_path(azure_env):
    """Not everyone can or wants to change a deployment."""
    out = rate_limit_help()
    assert "PYLON_MAX_CONCURRENCY=1" in out


def test_a_non_azure_provider_gets_no_azure_advice(monkeypatch):
    """Telling an OpenAI-direct user to run `az` is worse than saying nothing."""
    monkeypatch.setenv("PYLON_PROVIDER", "openai")
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    out = rate_limit_help()
    assert "az cognitiveservices" not in out
    assert "rate limit" in out.lower()


def test_the_retry_path_raises_the_typed_error():
    """Without this the CLI cannot tell a throttle from any other failure, and the
    operator gets the traceback back."""
    import inspect

    from pylon import engine

    src = inspect.getsource(engine._run_with_retry)
    code = "\n".join(line.split("#", 1)[0] for line in src.splitlines())
    assert "RateLimitExhausted" in code
