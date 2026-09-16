"""Keep the suite off the developer's own machine, and off the developer's bill.

Three things leak in from a configured laptop, and each has cost something real.

**A config file on disk.** Found by a full run on a configured machine: two tests
failed there and passed in CI and in a bare container. Nothing about the code
differed — the laptop had `~/.config/pylon/config.env`, and the suite read it.
`config.candidate_paths()` returns three places, and anything that consults them
picks up real settings mid-test. `cli.main()` calls `_load_config_file()` before
the parser is built, so a test that deletes AZURE_LOG_ANALYTICS_WORKSPACE_ID to
prove the CLI refuses without it gets the real value put straight back, the
refusal never happens, and the run proceeds into a live Azure call carrying the
fixture subscription id. One test tried to guard against this by pointing
PYLON_CONFIG at a nonexistent path, which rules out the FIRST candidate only.

**Exported environment variables.** Neutralising file discovery is half the job:
a developer who exports the same settings into their shell is in exactly the same
position, and the environment wins over a file by design. That is why
`test_ready_is_claimed_when_everything_verified` failed on a configured machine
and passed in CI — one workspace variable was exported, so the setup check
reported "workspace incomplete" and the report said "Probably ready".

**The model client.** Twice, a test reached generation and billed a real Azure
OpenAI deployment: once when --gap-scan learned to write a detection and the CLI
test followed it there, and once more before the seams were sealed. Both times
the suite passed, because a real model answers. Unlikely is not good enough for
something that spends money, so the factory itself raises here — every path to a
model goes through `make_chat_client`, which makes it the one chokepoint worth
holding.

Deliberately NOT a `socket.socket` patch: pytest plugins and coverage open local
sockets, and blanket-blocking them breaks the runner rather than the test. If a
network-wide guard is wanted on top of this, `pytest-socket` is the tool — it
handles the localhost carve-out properly.
"""
import os

import pytest

from pylon import clients, config, engine

# Everything the tool will read from a file, it will also read from the
# environment — the environment wins, by design. So the same set has to go.
# Prefixes rather than a list: a variable added to `config._ALLOWED` later must
# not silently start leaking into tests.
_LEAKY_PREFIXES = ("PYLON_", "OPENAI_", "AZURE_OPENAI_", "ANTHROPIC_")
_LEAKY_NAMES = (
    "AZURE_SUBSCRIPTION_ID",
    "AZURE_SENTINEL_RESOURCE_GROUP",
    "AZURE_SENTINEL_WORKSPACE_NAME",
    "AZURE_LOG_ANALYTICS_WORKSPACE_ID",
)


class ModelCallInTests(RuntimeError):
    """A test reached the model client factory."""


def _refuse_to_build_a_model_client(*args, **kwargs):
    raise ModelCallInTests(
        "A test reached make_chat_client(), which is how the suite billed a real "
        "deployment twice. Stub the seam the code under test uses — "
        "monkeypatch.setattr(engine, 'make_chat_client', ...) or pass phase=/verify= "
        "to generate_for_gap — or, if exercising the factory IS the test, mark it "
        "@pytest.mark.real_chat_client."
    )


@pytest.fixture(autouse=True)
def _no_developer_config(monkeypatch, request):
    # 1. No config file, whichever of the three locations it sits in. Tests that
    #    exercise the loader are unaffected: they pass explicit paths to
    #    `apply([path])`, which bypasses discovery by design.
    monkeypatch.setattr(config, "candidate_paths", list)

    # 2. No inherited credentials or workspace settings.
    for name in list(os.environ):
        if name in _LEAKY_NAMES or name.startswith(_LEAKY_PREFIXES):
            monkeypatch.delenv(name, raising=False)

    # 3. No model client. Patched at the source AND at engine's module-level
    #    import, because `from .clients import make_chat_client` binds a
    #    reference that patching `clients` alone would not reach. A test that
    #    stubs `engine.make_chat_client` itself runs after this and wins, which
    #    is what the existing stubbing tests rely on.
    #
    #    A fourth clause reset `sentinel._TABLE_PLANS`, the billing interlock's
    #    process-global map. It went with `sentinel` — see the gap-scan removal.

    if "real_chat_client" not in request.keywords:
        monkeypatch.setattr(clients, "make_chat_client", _refuse_to_build_a_model_client)
        monkeypatch.setattr(engine, "make_chat_client", _refuse_to_build_a_model_client)


@pytest.fixture
def sample_report():
    """A minimal finished EngineReport, for tests about how a run is REPORTED
    rather than how it is produced.

    Lives here because more than one test module needs one, and a test importing
    a helper out of another test module works locally and fails in CI — pytest
    only puts the rootdir on the path under some configurations, and this suite
    is not one of them.
    """
    from pylon.models import (
        AttackVector,
        Detection,
        EngineReport,
        ThreatAnalysis,
        ValidatedDetection,
    )

    vector = AttackVector(
        name="RBAC Role Assignment",
        priority="critical",
        mitre_technique="T1098.003",
        operation="MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
        log_table="AzureActivity",
        alert_condition="Any successful role assignment",
        rationale="Grants persistent access.",
    )
    detection = Detection(
        vector_name="RBAC Role Assignment",
        mitre_technique="T1098.003",
        kql='AzureActivity\n| where OperationNameValue =~ "X"',
        tuning_guidance="Scope to production subscriptions.",
        false_positive_notes="IaC pipelines.",
    )
    return EngineReport(
        service="Key Vault",
        platform="arm",
        analysis=ThreatAnalysis(
            service="Key Vault", platform="arm",
            executive_summary="Summary.", attack_vectors=[vector],
        ),
        detections=[
            ValidatedDetection(
                detection=detection, log_table="AzureActivity",
                valid=True, errors=[], warnings=[], retried=False,
            )
        ],
        generation_yield=100,
        critical_gaps=[],
    )


# ── every target a run can actually reach ────────────────────────────────────
# `PLATFORMS[*].services` used to be the list of things the tool could be aimed
# at, and three tests parametrized over it. The catalogue took that job (see the
# comment on `PLATFORMS`), the service tuples were emptied for `arm` and
# `dataplane`, and those three tests kept iterating the old source. Two of them
# went from covering the whole surface to covering ONE row, with no failure to
# say so: a parametrize over a shrinking list stays green all the way to empty.
#
# One helper, asked of the catalogue, so the next list that moves cannot quietly
# empty a test again.

def live_targets() -> list:
    """[(key, platform_or_resource, table)] for every target `design` offers."""
    from pylon.services import targets

    out = []
    for key, target in sorted(targets().items()):
        table = target.surfaces[0].table if target.surfaces else "AuditLogs"
        out.append((key, target, table))
    return out


def prompt_for(target, phase_id: str, playbook_target: str | None = None) -> str:
    """The prompt a real run builds for this target — down the same branch
    `engine._build_prompt` takes, so a test cannot exercise a path the tool does
    not use."""
    from pylon.prompts import build_resource_prompt, build_system_prompt

    if target.resource_type:
        return build_resource_prompt(
            target.resource_type, phase_id, target.surfaces, playbook_target
        )
    return build_system_prompt(
        "graph", "AuditLogs", phase_id, playbook_target,
        entra_category=target.entra_category,
    )
