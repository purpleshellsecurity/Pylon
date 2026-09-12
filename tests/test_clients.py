"""Provider wiring: the one piece of client config that is shared with a script.

`azure_v1_base_url` exists because scripts/preflight-provider.py has to build the
SAME URL as make_chat_client() — a preflight that authenticates against a
different endpoint than the run would prove nothing. Duplicating the two lines
would have let them drift silently, so they share a function and these tests pin
its contract.
"""

import pytest

from pylon.clients import azure_v1_base_url, make_chat_client


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://psec-triage-aoai.openai.azure.com",
        "https://psec-triage-aoai.openai.azure.com/",
        # A deployment URL pasted from the portal: everything after the host is
        # discarded rather than appended, because the v1 surface is host-rooted.
        "https://psec-triage-aoai.openai.azure.com/openai/deployments/gpt-4.1",
    ],
)
def test_any_form_of_the_endpoint_normalizes_to_the_v1_surface(endpoint):
    assert azure_v1_base_url(endpoint) == "https://psec-triage-aoai.openai.azure.com/openai/v1/"


def test_the_scheme_is_preserved_rather_than_assumed():
    # Not http-hardcoded and not https-hardcoded: whatever was configured.
    assert azure_v1_base_url("http://localhost:8080").startswith("http://localhost:8080/")


@pytest.mark.real_chat_client
def test_an_unknown_provider_is_rejected_by_name(monkeypatch):
    monkeypatch.setenv("PYLON_PROVIDER", "gemini")
    with pytest.raises(ValueError, match="gemini"):
        make_chat_client()


@pytest.mark.real_chat_client
def test_the_provider_name_is_case_insensitive(monkeypatch):
    # Errors on the missing endpoint, not on the provider name — which is the
    # proof that "Azure-OpenAI" resolved to the azure-openai branch.
    monkeypatch.setenv("PYLON_PROVIDER", "Azure-OpenAI")
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    with pytest.raises(KeyError, match="AZURE_OPENAI_ENDPOINT"):
        make_chat_client()
