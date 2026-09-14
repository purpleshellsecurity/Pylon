"""Rules the prompts must keep, checked as text rather than trusted.

Prompt regressions are silent: a rule deleted in an asset costs money and a
wrong detection before anyone notices, and no other test reads these files for
meaning. These assert the properties that were deliberately put there.
"""

import re

import pytest

from pylon import clients
from pylon.prompts import build_system_prompt
from pylon.validation import validate_kql

def _every_builder():
    """One prompt from each of the five builders.

    Editing the generic builder and believing the prompt had changed is how the
    old role text survived in four of them while every test passed -- the tests
    only exercised the path that was edited. These cover all five.
    """
    from pylon.catalog.overlay import LogSurface
    from pylon.prompts import build_resource_prompt

    surface = LogSurface(table="AzureActivity", diagnostic_category="Cat",
                         mode="resource-specific", covers=("read", "write"),
                         volume="medium", note="")
    return [
        ("generic/arm", build_system_prompt("arm", "Key Vault", "detection")),
        ("generic/graph", build_system_prompt("graph", "MicrosoftGraphActivityLogs", "detection")),
        ("combined", build_system_prompt("graph", "Entra", "detection")),
        ("azurediagnostics", build_system_prompt("dataplane", "AzureDiagnostics", "detection")),
        ("resource", build_resource_prompt("Microsoft.KeyVault/vaults", "detection", [surface])),
    ]


BUILDERS = _every_builder()


@pytest.mark.parametrize("name,prompt", BUILDERS, ids=[n for n, _ in BUILDERS])
def test_every_rule_says_what_to_do_when_it_cannot_be_followed(name, prompt):
    # "Do not hallucinate" names a failure without giving a procedure, and the
    # moment the model needs the rule is the moment it has nothing to use.
    block = prompt[prompt.index("<platform_rules>"):prompt.index("</platform_rules>")]
    assert "hallucinate" not in block.lower(), name
    for phrase in ("omit that detection and name the",
                   'write "unmapped"'):
        assert phrase in block, f"{name} missing exit route: {phrase}"


@pytest.mark.parametrize("name,prompt", BUILDERS, ids=[n for n, _ in BUILDERS])
def test_the_role_states_a_tradeoff_not_a_job_title(name, prompt):
    head = prompt[prompt.index("<role>"):prompt.index("</role>")]
    assert "Adversary Lab" not in head, name
    assert "narrower" in head and "routine automation" in head, name


@pytest.mark.parametrize("name,prompt", BUILDERS, ids=[n for n, _ in BUILDERS])
def test_rules_never_quote_a_structural_tag(name, prompt):
    # A rule that names <schema_reference> or <technique_reference> breaks the
    # tests that count those blocks, and points the model at a section some
    # phases do not include.
    block = prompt[prompt.index("<platform_rules>"):prompt.index("</platform_rules>")]
    for tag in ("<schema_reference>", "<technique_reference>", "<task>"):
        assert tag not in block, f"{name} quotes {tag} inside its rules"


def test_every_threat_asset_permits_an_empty_answer():
    # Told to omit what it cannot ground, but never told an empty list is
    # allowed, a model pads to fill the shape it was given.
    import pathlib
    assets = sorted(pathlib.Path(__file__).resolve().parents[1]
                    .glob("src/pylon/prompts/assets/*/threat.md"))
    assert assets, "no threat assets found"
    for f in assets:
        assert "Zero is a valid answer" in f.read_text(encoding="utf-8"), f.parent.name


def test_every_threat_asset_also_sets_a_floor():
    """The companion to the test above, and it exists because that one alone was
    read as an instruction to be brief.

    The assets said "returning fewer vectors than you could imagine is correct"
    and set no bar at all. A run against a Key Vault with 78 documented
    operations and nine mapped techniques came back with ONE attack vector, and
    every count downstream is capped by that number, so the whole tool read as
    empty. Permission to return nothing when nothing can be grounded is not
    permission to stop early when plenty can.

    Both properties have to hold at once, which is why they are two tests: drop
    the permission and the model pads with invented operations, drop the floor
    and it samples.
    """
    import pathlib
    assets = sorted(pathlib.Path(__file__).resolve().parents[1]
                    .glob("src/pylon/prompts/assets/*/threat.md"))
    assert assets, "no threat assets found"
    for f in assets:
        body = f.read_text(encoding="utf-8")
        assert "Cover the surface, do not sample it" in body, f.parent.name
        assert "never about brevity" in body, f.parent.name


class TestPlaceholdersNeverShip:
    """The detection templates are fill-in skeletons; copying the shape can
    copy the placeholder. Bracketed prose must fail validation, and KQL's own
    bracket uses must not."""

    @pytest.mark.parametrize("q", [
        'AzureActivity | where TimeGenerated > ago(1h) | where Op =~ "[exact value from Phase 1]"',
        'AzureActivity | where TimeGenerated > ago(1h) // Detection: [Name]',
        'AzureActivity | where TimeGenerated > ago(1h) // MITRE: [T####.### - Name]',
    ])
    def test_a_leftover_placeholder_is_an_error(self, q):
        r = validate_kql(q, "AzureActivity")
        assert not r.valid
        assert any("placeholder" in e for e in r.errors)

    @pytest.mark.parametrize("q", [
        'AzureActivity | where TimeGenerated > ago(1h) | extend a = dynamic([])',
        'AzureActivity | where TimeGenerated > ago(1h) | extend a = dynamic(["x","y"])',
        'AzureActivity | where TimeGenerated > ago(1h) | extend i = tostring(parse_json(Claims)["http://schemas.microsoft.com/x"])',
        'AzureActivity | where TimeGenerated > ago(1h) | extend s = split(ResourceId, "/")[3]',
    ])
    def test_kql_bracket_syntax_is_not_a_placeholder(self, q):
        assert not any("placeholder" in e for e in validate_kql(q, "AzureActivity").errors)


class TestSystemPromptCaching:
    """Anthropic caches only where a breakpoint is set; OpenAI caches an exact
    prefix automatically and rejects a structured block."""

    def test_anthropic_gets_a_cache_breakpoint(self, monkeypatch):
        monkeypatch.setenv("PYLON_PROVIDER", "anthropic")
        out = clients.cacheable("system text")
        assert isinstance(out, list)
        assert out[0]["cache_control"] == {"type": "ephemeral"}
        assert out[0]["text"] == "system text"

    @pytest.mark.parametrize("provider", ["openai", "azure-openai"])
    def test_openai_providers_get_a_plain_string(self, provider, monkeypatch):
        monkeypatch.setenv("PYLON_PROVIDER", provider)
        assert clients.cacheable("system text") == "system text"

    def test_the_default_provider_is_a_plain_string(self, monkeypatch):
        monkeypatch.delenv("PYLON_PROVIDER", raising=False)
        assert clients.cacheable("x") == "x"


class TestRoleSubjects:
    """The subject lands mid-sentence, so it must survive being interpolated."""

    def test_a_clause_is_refused(self):
        from pylon.prompts import _role
        with pytest.raises(ValueError, match="bare noun phrase"):
            _role("the Azure resource provider X, whose logs land in a table")

    def test_an_overlong_subject_is_refused(self):
        from pylon.prompts import _role
        with pytest.raises(ValueError, match="bare noun phrase"):
            _role("a" * 81)

    @pytest.mark.parametrize("subject", [
        "Azure ARM",
        "Microsoft Defender for Endpoint",
        "Entra ID directory changes and Graph API access",
        "the Azure resource type Microsoft.KeyVault/vaults",
    ])
    def test_real_subjects_pass(self, subject):
        from pylon.prompts import _role
        assert subject in _role(subject)

    def test_the_azurediagnostics_subject_never_doubles_its_own_words(self):
        # provider_label falls back to the words "this Azure resource provider",
        # which read correctly in the rules and doubled the phrase in the role.
        from pylon.prompts import build_system_prompt
        for prov in ("", "MICROSOFT.APIMANAGEMENT"):
            p = build_system_prompt("dataplane", "AzureDiagnostics", "detection",
                                    az_provider=prov)
            head = p[p.index("<role>"):p.index("</role>")]
            assert "provider this Azure resource provider" not in head
