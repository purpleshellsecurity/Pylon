"""The guards in conftest, tested — they are worthless if they rot silently.

Both exist because of something that actually happened: the suite billed a real
Azure OpenAI deployment twice, and a test failed on a configured laptop while
passing in CI. Neither failure was visible from inside the suite, which is
exactly why the guards need tests of their own.
"""

import os

import pytest

from pylon import clients, engine


def test_reaching_the_model_client_factory_raises_instead_of_calling_out():
    # Asserted as RuntimeError rather than by importing conftest's class: what
    # matters is that it raises rather than calls out, and tests/ is not a
    # package, so the relative import would only work by accident.
    for factory in (clients.make_chat_client, engine.make_chat_client):
        with pytest.raises(RuntimeError, match="billed a real deployment"):
            factory()


def test_the_error_says_how_to_fix_it_rather_than_just_refusing():
    with pytest.raises(RuntimeError) as caught:
        engine.make_chat_client()
    message = str(caught.value)
    assert "monkeypatch.setattr" in message
    assert "real_chat_client" in message


@pytest.mark.real_chat_client
def test_the_marker_lets_a_test_reach_the_real_factory():
    # test_clients.py needs this: the factory IS its subject. It still never
    # reaches a network — an unknown provider is rejected by name first.
    os.environ["PYLON_PROVIDER"] = "gemini"
    try:
        with pytest.raises(ValueError, match="gemini"):
            clients.make_chat_client()
    finally:
        del os.environ["PYLON_PROVIDER"]


@pytest.mark.parametrize("name", [
    "PYLON_PROVIDER",
    "OPENAI_API_KEY", "OPENAI_CHAT_MODEL",
    "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AZURE_SUBSCRIPTION_ID", "AZURE_SENTINEL_RESOURCE_GROUP",
    "AZURE_SENTINEL_WORKSPACE_NAME", "AZURE_LOG_ANALYTICS_WORKSPACE_ID",
])
def test_no_credential_or_workspace_variable_is_inherited(name):
    """A developer who exports these is otherwise in the same position as one
    with a config file on disk — the environment wins over a file by design."""
    assert name not in os.environ


def test_config_file_discovery_finds_nothing():
    from pylon import config

    assert config.candidate_paths() == []
