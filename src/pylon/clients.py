"""Provider selection — the only module that knows which model backend runs.

Every Agent Framework provider yields the same agent surface (run, tools,
middleware, structured outputs), so the rest of the engine is
provider-agnostic. Pick with PYLON_PROVIDER:

  openai        (default)  OpenAI API.
                Env: OPENAI_API_KEY, OPENAI_CHAT_MODEL (e.g. gpt-4.1)
  azure-openai  Azure OpenAI via the v1 API (no dated api-version): a plain
                OpenAI client pointed at the resource's /openai/v1/ surface.
                Env: AZURE_OPENAI_ENDPOINT (resource root, e.g.
                https://NAME.openai.azure.com), AZURE_OPENAI_API_KEY (or omit
                the key to use Entra ID via DefaultAzureCredential),
                OPENAI_CHAT_MODEL = your DEPLOYMENT name.
  anthropic     Model parity with adversary-lab-pylon (it used
                Claude) — useful while A/B-ing outputs against it as the
                test oracle. Env: ANTHROPIC_API_KEY, ANTHROPIC_CHAT_MODEL
"""

import os
from urllib.parse import urlparse


def azure_v1_base_url(endpoint: str) -> str:
    """The /openai/v1/ base URL for an Azure OpenAI resource root.

    Azure's "v1" API: point a plain OpenAI client at the resource's /openai/v1/
    surface, with no dated api-version. This is Microsoft's current guidance
    (https://learn.microsoft.com/azure/foundry/openai/api-version-lifecycle).
    Any path or trailing slash on the configured endpoint is discarded, so both
    the bare resource root and a full deployment URL normalize to the same base.
    """
    parsed = urlparse(endpoint.rstrip("/"))
    return f"{parsed.scheme}://{parsed.netloc}/openai/v1/"


def cacheable(instructions: str) -> str | list[dict]:
    """System instructions in whatever form the provider can cache.

    The same system prompt is handed to one Agent and then run many times --
    the detection phase runs it once per attack vector -- so the prefix is
    identical across every call in a phase and is pure repetition to re-bill.

    The two providers reach that differently and only one needs help:

      openai / azure-openai   caches automatically on an exact prefix over
                              1024 tokens. Built prompts here measure 2.4k-3k,
                              so this already hits. A plain string is correct
                              and a structured block would not be accepted.
      anthropic               caches only where a `cache_control` breakpoint
                              is set, which the API takes on structured system
                              blocks rather than a bare string.

    Marking the whole prompt as one block is deliberate: the split point that
    would matter (static prefix vs per-phase task) is also the point where the
    prompt stops being identical, so a second breakpoint would buy nothing and
    cost a cache entry.
    """
    if os.environ.get("PYLON_PROVIDER", "openai").lower() != "anthropic":
        return instructions
    return [{"type": "text", "text": instructions,
             "cache_control": {"type": "ephemeral"}}]


def make_chat_client():
    """Construct the Agent Framework chat client for PYLON_PROVIDER
    (openai, azure-openai, or anthropic). Raises ValueError for an unknown provider."""
    provider = os.environ.get("PYLON_PROVIDER", "openai").lower()

    if provider == "openai":
        from agent_framework.openai import OpenAIChatClient

        return OpenAIChatClient()

    if provider == "azure-openai":
        from agent_framework.openai import OpenAIChatClient

        # Azure "v1" API (see azure_v1_base_url): the OpenAI client against
        # /openai/v1/, not AzureOpenAI with a dated api-version. That older route
        # sent our structured-output request down a preview surface that rejected
        # the schema ("Unsupported data type"). OPENAI_CHAT_MODEL is your
        # DEPLOYMENT name; AZURE_OPENAI_ENDPOINT is the resource root.
        base_url = azure_v1_base_url(os.environ["AZURE_OPENAI_ENDPOINT"])

        api_key = os.environ.get("AZURE_OPENAI_API_KEY")
        if api_key:
            return OpenAIChatClient(base_url=base_url, api_key=api_key)

        # No key -> Microsoft Entra ID. The async OpenAI client refreshes its
        # key by *awaiting* the provider, but azure-identity's
        # get_bearer_token_provider is synchronous — awaiting its str result
        # raises "object str can't be used in 'await' expression". Wrap it in an
        # async callable so the refresh works.
        import asyncio

        from azure.identity import DefaultAzureCredential, get_bearer_token_provider

        sync_token = get_bearer_token_provider(
            DefaultAzureCredential(), "https://ai.azure.com/.default"
        )

        async def token_provider() -> str:
            """Async wrapper around the sync Entra bearer-token provider so the
            OpenAI client can await its key refresh."""
            return await asyncio.to_thread(sync_token)

        return OpenAIChatClient(base_url=base_url, api_key=token_provider)

    if provider == "anthropic":
        from agent_framework.anthropic import AnthropicClient

        return AnthropicClient()

    raise ValueError(f"Unknown PYLON_PROVIDER: {provider}")


def rate_limit_help() -> str:
    """What to tell an operator whose deployment throttled the whole run.

    Everything here is read from config and the meter — no `az` call, because an
    error path that makes a network request can hang on the way to explaining why
    something hung. The two `az` commands are printed for the operator to run,
    rather than run for them.

    The number that matters is the COMPARISON: a capacity of 10 means nothing on
    its own, and means everything next to an entitlement of 3000. That gap is what
    turns "I am blocked" into "that is just set wrong".
    """
    import os

    from .usage import current_meter

    provider = os.environ.get("PYLON_PROVIDER", "openai").lower()
    model = os.environ.get("AZURE_OPENAI_CHAT_MODEL") or os.environ.get(
        "OPENAI_CHAT_MODEL", "(unset)"
    )
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
    resource = endpoint.replace("https://", "").split(".openai.azure.com")[0] or "(unknown)"
    m = current_meter()
    spent = m.input_tokens + m.output_tokens

    lines = [
        "",
        "Rate limited — the deployment throttled every retry, so the run stopped.",
        "",
        f"  provider           {provider}",
        f"  deployment/model   {model}",
    ]
    if provider == "azure-openai":
        lines += [
            f"  resource           {resource}",
            "",
            f"  tokens this run    {spent:,} before it was cut off",
            "",
            "A run of this shape needs roughly 250,000 tokens. If the deployment is",
            "provisioned at 10 (10,000 tokens/minute), that is ~25 minutes of quota",
            "spent in under ten — which no amount of waiting between calls fixes.",
            "",
            "Check what it is set to, and what you are entitled to:",
            "",
            f"  az cognitiveservices account deployment list --name {resource} \\",
            "      --resource-group <rg> -o table",
            "  az cognitiveservices usage list -l <region> -o table",
            "",
            "Deployments are commonly created far below the subscription's own",
            "limit, so the second number is usually much larger than the first.",
            "Raise the deployment (GlobalStandard bills per token USED, not per",
            "capacity provisioned — a higher ceiling does not cost more):",
            "",
            f"  az cognitiveservices account deployment create --name {resource} \\",
            "      --resource-group <rg> --deployment-name <deployment> \\",
            "      --model-name <model> --model-version <version> \\",
            "      --model-format OpenAI --sku-name GlobalStandard --sku-capacity 300",
        ]
    else:
        lines += [
            "",
            f"  tokens this run    {spent:,} before it was cut off",
            "",
            "Check your provider's rate limits for this key and model.",
        ]
    lines += [
        "",
        "Or work within the current limit:",
        "  PYLON_MAX_CONCURRENCY=1   one detection call at a time",
        "  PYLON_MAX_RETRIES=8       wait longer before giving up",
        "and leave several minutes between runs.",
        "",
    ]
    return "\n".join(lines)
