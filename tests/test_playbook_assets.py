"""Invariants over the six Phase 3 IR playbook templates.

These are prompt assets: an LLM renders them into a playbook a responder
copy-pastes at 3am, so a defect in a template becomes a defect in every playbook
generated from it. Each assertion here corresponds to something that actually
shipped.
"""

import pathlib
import re

import pytest

_ASSETS = pathlib.Path(__file__).resolve().parent.parent / "src/pylon/prompts/assets"
_PLAYBOOKS = sorted(_ASSETS.glob("*/playbook.md"))


def test_there_are_playbooks_to_check():
    """A glob that matches nothing passes for ever."""
    assert len(_PLAYBOOKS) == 3, [p.parent.name for p in _PLAYBOOKS]


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_no_typescript_escape_survives_in_powershell(path):
    r"""`\$` is a TypeScript template-literal escape, not a PowerShell one.
    Measured: pwsh parses `\$_.Exception.Message` as a command name and fails
    with "is not recognized" — and it sat inside catch blocks, so the error
    handler broke exactly when containment had already failed. Four of six
    templates carried it."""
    assert "\\$" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_no_unordered_take(path):
    """`take` is explicitly unordered in KQL, so a burst yields arbitrary rows
    rather than the most recent ones. Every template ended a triage query with
    one."""
    assert not re.search(r"\|\s*take\s+\d", path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_no_let_shadows_the_column_it_filters_on(path):
    """`let CorrelationId = "..."` then `| where CorrelationId == CorrelationId`
    is always true — the name shadows the column — and with no time bound it
    returns the whole retention window."""
    text = path.read_text(encoding="utf-8")
    shadow = re.search(r"let\s+(\w+)\s*=.*?\|\s*where\s+\1\s*==\s*\1\b", text, re.DOTALL)
    assert not shadow, f"`{shadow.group(1)}` shadows the column it is compared against"


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_every_containment_try_block_does_something(path):
    """A containment step must never print success for a no-op. `signin`'s
    Option B had every executable line commented out and fell through to
    `Write-Host "✅ Completed"`, telling the responder the account was blocked
    when nothing had run."""
    text = path.read_text(encoding="utf-8")
    for block in re.findall(r"try\s*\{(.*?)\}\s*catch", text, re.DOTALL):
        live = [
            ln for ln in block.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
            and "Write-Host" not in ln
        ]
        assert live, f"a try block in {path.parent.name} has no executable statement"


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_graph_cmdlets_are_not_issued_on_an_azure_connection(path):
    """Get-Mg*/Update-Mg*/Revoke-Mg* need Connect-MgGraph. `arm` opened its
    Option C with Connect-AzAccount and then called three of them, none of which
    an Az context can authenticate."""
    text = path.read_text(encoding="utf-8")
    for block in re.findall(r"```powershell\s*\n(.*?)```", text, re.DOTALL):
        if re.search(r"\b(Get|Update|Revoke|Remove|Add)-Mg\w+", block):
            assert "Connect-MgGraph" in block, (
                f"{path.parent.name}: a block calls Graph cmdlets without Connect-MgGraph"
            )


# ── the checker, and the retry it drives ─────────────────────────────────────


def test_the_checker_catches_the_shadowed_let():
    from pylon.validation import check_playbook

    bad = '```kql\nlet CorrelationId = "x";\nAuditLogs\n| where CorrelationId == CorrelationId\n```'
    result = check_playbook(bad, "AuditLogs")
    assert result.failed and any("shadows" in e for e in result.errors)


def test_the_checker_catches_the_powershell_escape():
    r"""script_check's tiers do NOT catch this: `\$_.Exception.Message` parses,
    and tier 3 skips it because it has no hyphen and so looks like an external
    tool. Hence a targeted check."""
    from pylon.validation import check_playbook

    bad = '```powershell\nWrite-Host "x: \\$(\\$_.Exception.Message)"\n```'
    result = check_playbook(bad, "AuditLogs")
    assert result.failed and any("not an escape" in e for e in result.errors)


def test_a_clean_playbook_passes():
    """The gate has to mean something, so it must not fire on good input."""
    from pylon.validation import check_playbook

    good = (
        '```kql\nlet AlertTime = datetime(2026-01-01);\nAuditLogs\n'
        '| where TimeGenerated > AlertTime\n| top 10 by TimeGenerated desc\n```\n'
        '```powershell\nWrite-Host "x: $($_.Exception.Message)"\n```'
    )
    result = check_playbook(good, "AuditLogs")
    assert not result.failed, result.errors


def test_missing_pwsh_is_recorded_as_unchecked_not_as_a_pass():
    """Same discipline as every other gate here: could-not-check is not clean."""
    from pylon.validation import playbook_check, script_check

    original = script_check.shutil.which
    script_check.shutil.which = lambda _n: None
    try:
        # A KQL block too: a playbook with no queries is now its own error, and
        # this test is about the pwsh tier, not about that.
        result = playbook_check.check_playbook(
            '```kql\nAuditLogs\n| take 1\n```\n\n```powershell\nWrite-Host "x"\n```',
            "AuditLogs")
    finally:
        script_check.shutil.which = original
    assert not result.failed, result.errors
    assert result.unchecked and "pwsh" in result.unchecked[0]


def test_the_playbook_phase_retries_a_bad_fill():
    """The retry survives the move to assembly, but what it corrects changed.

    Phase 3 used to return a whole document and the retry asked for a better
    document. Now Pylon assembles the document and the model supplies three
    fields, so the only thing a retry can fix is those three -- and the retry
    must RE-RENDER rather than take the response text, or it throws the assembled
    playbook away. It did exactly that on the first wiring and the integration
    tests caught it: a 323-line playbook became an empty string.

    `containment_role` lands inside a PowerShell block, so a bad value there is a
    real fault in the finished document and the honest way to exercise this.
    """
    import asyncio
    from types import SimpleNamespace

    from pylon import engine
    from pylon.playbook import PlaybookFill

    context = ("The actor reached the object. The material must now be treated "
               "as disclosed.")
    why = ["The material is now disclosed", "The actor still holds the access"]
    bad = PlaybookFill(what_happened="The actor read the object.",
                       attack_context=context, why_it_matters=why,
                       # `\$` is not an escape in PowerShell; the checker rejects it.
                       containment_role=r"\$($_.Role)")
    good = PlaybookFill(what_happened="The actor read the object.",
                        attack_context=context, why_it_matters=why,
                        containment_role="Key Vault Secrets Officer")

    calls = []

    async def fake_arun(_agent, prompt, **_kw):
        calls.append(prompt)
        return SimpleNamespace(value=bad if len(calls) == 1 else good,
                               text="", usage_details=None)

    class _Stub:
        def __init__(self, *a, **k):
            pass

    saved = engine._arun, engine.Agent, engine.make_chat_client
    engine._arun, engine.Agent = fake_arun, _Stub
    engine.make_chat_client = lambda *a, **k: None
    try:
        from pylon.models import Detection, ValidatedDetection

        target = ValidatedDetection(
            detection=Detection(vector_name="v", mitre_technique="T1078.004",
                                kql="AZKVAuditLogs | take 1", tuning_guidance="",
                                false_positive_notes=""),
            log_table="AZKVAuditLogs", valid=True, errors=[], warnings=[],
            retried=False, operation="SecretGet")
        out = asyncio.run(
            engine.run_playbook_phase.__wrapped__(engine.EngineRequest(), target))
    finally:
        engine._arun, engine.Agent, engine.make_chat_client = saved

    assert len(calls) == 2, "a faulty fill must trigger exactly one retry"
    assert "PowerShell" in calls[1], "the retry must say what was wrong"
    assert "three fields" in calls[1], "the retry must still ask for three fields"
    assert "# IR Playbook:" in out, "the retry must RE-RENDER, not return the response"
    assert "Key Vault Secrets Officer" in out, "the corrected field must be used"
    assert "$($_.Role)" not in out


# ── the factored skeleton ────────────────────────────────────────────────────
# The six assets were ~70% identical with accidental differences: signin had no
# Quick Decision, no blast radius even though fleet scope is
# the central endpoint question, only graph_activity had prevention. So a fix had
# to be made six times and sometimes was not — `\$` survived in four files.


_REQUIRED_SECTIONS = (
    "## Fill these in first",     # 3.3 — one parameter block, not eight `let`s
    "## Attack Context",
    "## Quick Triage",
    "## Scope of Actor Activity",  # the unfiltered actor profile
    "## Investigation",
    "### Blast radius",           # promoted to every plane
    "## Cross-Log Pivots",        # 3.1 — resolves the template/runtime conflict
    "## Preserve Evidence",       # 2.1 — before containment destroys state
    "## Containment",
    "## Eradication",             # 2.2 — the AiTM re-entry hole
    "## Validation",
    "## Recovery Verification",
    "## Prevention",
    "## Escalate immediately if",  # 2.8
)


def _rendered(track: str) -> str:
    from pylon.prompts import load_asset, render_playbook

    return render_playbook(load_asset(f"{track}/playbook.md"))


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_every_plane_gets_every_section(path):
    """The point of the skeleton: a doctrine section is added once and every
    plane has it, rather than five planes quietly lacking what the sixth got."""
    text = _rendered(path.parent.name)
    missing = [h for h in _REQUIRED_SECTIONS if h not in text]
    assert not missing, f"{path.parent.name} is missing {missing}"


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_preserve_comes_before_containment(path):
    """Ordering is the whole point of 2.1 — revoking a grant deletes the record
    of what scopes it held, and isolating a device ends the sessions you would
    have enumerated."""
    text = _rendered(path.parent.name)
    assert text.index("## Preserve Evidence") < text.index("## Containment")


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_eradication_comes_between_containment_and_validation(path):
    text = _rendered(path.parent.name)
    assert text.index("## Containment") < text.index("## Eradication") < text.index("## Validation")


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_validation_states_a_dwell_time_and_a_positive_control(path):
    """"No results" proved nothing before this: a query run 60 seconds after
    containment is empty because the data has not landed, and a broken
    diagnostic setting is indistinguishable from success."""
    text = _rendered(path.parent.name)
    assert "before you believe an empty result" in text
    assert "your logging is broken, not your attacker" in text
    assert "TotalRowsInWindow" in text


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_containment_states_its_undo(path):
    """"Option A — Preferred (reversible)" asserted reversibility and never said
    how. Someone disables the SP that turns out to be the payroll connector."""
    text = _rendered(path.parent.name)
    assert "**Undo:**" in text or "**Undo.**" in text or "must state its undo" in text


# Planes whose schema supports a read/write split. Everywhere else it would be a
# fabricated axis: AzureActivity does not log control-plane reads, AuditLogs is a
# change log so every row is a write, a sign-in is neither a read nor a write, and
# the Device* tables have no read ActionType (FileCreated/Modified/Deleted/Renamed).
_READ_WRITE_PLANES = {"dataplane", "graph_activity"}

# Operation fields per plane. The scope query is the ONE query in the playbook that
# must not narrow to the detection's operation.
_OPERATION_FIELDS = (
    "OperationNameValue", "OperationName", "ActionType", "RequestUri", "ActivityName",
)


def _scope_block(plane: str) -> str:
    text = _rendered(plane)
    i = text.index("## Scope of Actor Activity")
    return text[i : text.index("## Investigation", i)]


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_scope_sits_between_triage_and_investigation(path):
    text = _rendered(path.parent.name)
    assert (
        text.index("## Quick Triage")
        < text.index("## Scope of Actor Activity")
        < text.index("## Investigation")
    )


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_the_scope_query_is_not_filtered_by_operation(path):
    """The whole point of the section. Every other query narrows to the operation
    that fired the alert; this one must not, because logging tampering, credential
    additions and lateral movement only surface when nothing filters them out."""
    import re

    block = _scope_block(path.parent.name)
    bad = re.findall(
        r"\|\s*where\s+(" + "|".join(_OPERATION_FIELDS) + r")\s*(?:==|=~|has\b|in~?\b)",
        block,
    )
    assert not bad, f"{path.parent.name} scope query filters on {bad}"


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_read_write_only_where_the_schema_has_one(path):
    """A read/write split on a plane that cannot express one renders as 100% write
    on every incident, which reads as a finding and is an artifact."""
    import re

    plane = path.parent.name
    has_split = bool(re.search(r"Reads\s*=\s*countif", _scope_block(plane)))
    assert has_split == (plane in _READ_WRITE_PLANES), (
        f"{plane}: read/write split present={has_split}, expected={plane in _READ_WRITE_PLANES}"
    )


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_the_attacker_controlled_caveat_renders_everywhere(path):
    """Source IP and user agent are attacker-set. They cluster; they never clear."""
    text = _rendered(path.parent.name)
    assert "attacker-controlled" in text
    assert "never as evidence" in text


def test_arm_states_that_control_plane_reads_are_not_logged():
    """Without this, "no reads" reads as "no reconnaissance happened" or "my logging
    is broken". Both are wrong: AzureActivity records writes by design.

    Not parametrized over the playbooks. It was, and then skipped the five that are
    not arm -- six runs to make one assertion about a hardcoded plane, and five skip
    lines in every report. A seventh playbook would have added another skip and
    checked nothing.
    """
    block = _scope_block("arm")
    assert "not logged natively" in block and "expected" in block
    assert "Reads" not in block, "arm must not offer a read filter"


# ── one row is not one operation ─────────────────────────────────────────────
#
# Three tables under `dataplane` count something other than what a reader assumes,
# and each was verified against its Azure Monitor table reference rather than
# recalled. The playbook is where the model is told; these are what keep it told.


def test_the_data_plane_assets_name_only_the_tables_on_offer():
    """The data-plane prompt described eight services long after the tool stopped
    offering six of them.

    It named SQLSecurityAuditEvents, CDBDataPlaneRequests, FunctionAppLogs,
    AppServiceAuditLogs, AZMSRunTimeAuditLogs and AKSAudit -- including AKSAudit's
    Kubernetes verbs, "get, list, create, delete" -- and it left out three of the
    five tables that ARE offered. Every data-plane run shipped that to the model:
    columns for tables it could not query, and no columns for tables it could.

    A prompt that describes a table the picker cannot reach is not extra help. It
    is an invitation to write a query against a table this workspace has no
    detection for, and the model took it.
    """
    offered = {"AZKVAuditLogs", "StorageBlobLogs", "StorageFileLogs",
               "StorageQueueLogs", "StorageTableLogs"}
    withdrawn = ("SQLSecurityAuditEvents", "CDBDataPlaneRequests", "FunctionAppLogs",
                 "AppServiceAuditLogs", "AZMSRunTimeAuditLogs", "AKSAudit",
                 "AKSAuditAdmin")

    for asset in sorted((_ASSETS / "dataplane").glob("*.md")):
        text = asset.read_text(encoding="utf-8")
        named = [t for t in withdrawn if t in text]
        assert not named, (
            f"{asset.name} still describes {named}, which no target can select. "
            "Withdraw the table from the picker and from the prompt together."
        )
        # The mapping table is what tells the model which tables exist at all.
        if asset.name == "context.md":
            missing = sorted(t for t in offered if t not in text)
            assert not missing, f"context.md omits offered tables: {missing}"


def test_storage_operation_count_is_not_offered_as_a_sum():
    """`OperationCount` reads like a count and is an index. The docs define it as
    starting "with an index of 0" over the operations within one request, so
    sum(OperationCount) is a number with no meaning that nobody would question.
    """
    # Moved out of the playbook's scope block when Pylon started WRITING that
    # query: the fact is for the phase where a model composes KQL, and leaving it
    # in a section no model reads is keeping text for a reader who left.
    from pylon.prompts import table_context

    for table in ("StorageBlobLogs", "StorageFileLogs", "StorageQueueLogs",
                  "StorageTableLogs"):
        block = table_context(table)
        assert "sum(OperationCount)" in block, table
        assert "INDEX" in block, "say WHY, or the rule is a rule to be argued with"


def test_key_vault_user_agent_is_not_declared_missing():
    """Key Vault's user agent is in `ClientInfo`, whose name does not say so. The
    playbook listed Key Vault among the services with no user agent column, so the
    model was told to drop a field that exists -- lost signal, quietly.
    """
    from pylon.prompts import table_context

    block = table_context("AZKVAuditLogs")
    assert "ClientInfo is the USER AGENT" in block, (
        "name the column AND say what it carries")
    assert "It has one." in block, (
        "Key Vault has a user agent; saying otherwise drops a field that exists"
    )


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_anti_forensics_does_not_come_back(path):
    """Superseded by the unfiltered scope query, which surfaces the same tampering
    without a separate operation list to keep current."""
    from pylon.prompts import load_asset

    assert "anti_forensics" not in load_asset(f"{path.parent.name}/playbook.md")
    assert "monitoring controls themselves" not in _rendered(path.parent.name)


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_no_unpaired_apostrophe_in_a_kql_block(path):
    """`'` delimits a KQL string, so an unpaired one inside a fence swallows every
    character up to the next quote. It cost a `let AllowedActors` declaration once
    and it desyncs the column guard's own string blanking, which is what turns a
    fabricated column into a silent pass. Paired literals (`datetime_diff('day',
    ...)`, `_GetWatchlist('ApprovedAutomation')`) are fine and stay."""
    import re

    text = _rendered(path.parent.name)
    bad = []
    for block in re.findall(r"```kql\n(.*?)```", text, re.DOTALL):
        for line in block.splitlines():
            if "'" in re.sub(r"'[^'\n]*'", "", line):
                bad.append(line.strip())
    assert not bad, f"{path.parent.name} has unpaired apostrophes: {bad}"


# Concepts a plane has no way to contain. The shared "state your undo" paragraph
# named a service principal on all six planes, endpoint included, where there is
# no such object to disable — the skeleton's own failure mode inverted: text that
# is true in one place rendering everywhere.
_ALIEN_CONCEPTS = {
}


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_no_plane_names_a_thing_it_cannot_contain(path):
    plane = path.parent.name
    text = _rendered(plane).lower()
    named = [c for c in _ALIEN_CONCEPTS.get(plane, ()) if c in text]
    assert not named, f"{plane} names {named}, which it has no way to contain"


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_every_plane_writes_its_own_undo_stakes(path):
    """The cautionary example is plane-specific by construction. Falling back to
    the generic default means nobody wrote the one that fits this plane, which is
    how the endpoint playbook came to warn about a payroll connector."""
    from pylon.prompts import load_asset, parse_slots

    slots = parse_slots(load_asset(f"{path.parent.name}/playbook.md"))
    assert slots.get("undo_stakes"), f"{path.parent.name} supplies no undo_stakes"


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_the_triage_window_comes_from_the_detection(path):
    """A rule firing on a 24h summarize got a 1h triage query and the responder
    saw nothing."""
    text = _rendered(path.parent.name)
    assert "TriageWindow" in text
    assert "WINDOW THE DETECTION AGGREGATES OVER" in text


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_the_allowlist_is_a_watchlist_in_both_phases(path):
    """Phase 2 shipped `dynamic([])`, Phase 3 shipped three differently-named
    arrays. Nobody hand-populates four lists at 3am."""
    from pylon.prompts.shared import QUERY_RULES

    text = _rendered(path.parent.name)
    assert "_GetWatchlist(" in text
    assert "fallback" in text
    assert any("_GetWatchlist(" in rules for rules in QUERY_RULES.values()), (
        "Phase 2 must read the same watchlist Phase 3 does"
    )


@pytest.mark.parametrize("path", _PLAYBOOKS, ids=lambda p: p.parent.name)
def test_normalized_entity_names_are_projected(path):
    """The alert carries ActorUpn/ActorName/SrcIp; a playbook showing only raw
    per-table columns makes the analyst translate between two vocabularies while
    the incident is live."""
    text = _rendered(path.parent.name)
    assert "ActorUpn" in text or "ActorName" in text
    assert "NORMALIZED entity names" in text


def test_a_plane_that_omits_a_slot_still_gets_the_section():
    """An omitted slot falls back to a documented generic — a plane is never
    silently missing a section, which is how the drift happened."""
    from pylon.prompts import render_playbook

    out = render_playbook("preamble\n<!-- SLOT: attack_context -->\nonly this\n")
    assert "## Eradication" in out and "## Preserve Evidence" in out


def test_an_unconverted_asset_passes_through_unchanged():
    """A plane not yet on the skeleton must keep working."""
    from pylon.prompts import render_playbook

    assert render_playbook("no slot markers here") == "no slot markers here"


def test_a_cross_log_pivot_is_judged_against_its_own_table():
    """From the first live run. The Cross-Log Pivots section queries AuditLogs on
    purpose, and `InitiatedBy` is a real AuditLogs column absent from
    AzureActivity — so a CORRECT pivot was reported as a fabricated column, burned
    a corrective retry, and warned the operator about KQL that was right.

    The old guard filtered errors containing "does not query"; this error says
    "does not exist", so it went straight through."""
    from pylon.validation.playbook_check import check_playbook

    pivot = (
        "```kql\n"
        'let ActorId = "x";\n'
        "AuditLogs | where tostring(parse_json(InitiatedBy).user.id) == ActorId\n"
        "| project TimeGenerated, InitiatedBy\n"
        "```"
    )
    assert not check_playbook(pivot, "AzureActivity").errors


def test_the_detections_own_table_still_wins():
    """A block that RUNS on the detection's table is judged against it, even when
    another table is named inside — otherwise the fix would disable the gate."""
    from pylon.validation.playbook_check import check_playbook

    # BOTH tables open a line, so the resolver has a real choice to get wrong.
    # Alphabetically AuditLogs sorts first, and `InitiatedBy` is valid there — so
    # dropping the "detection's table wins" rule makes this phantom column vanish
    # and the gate silently stops working.
    bad = (
        "```kql\n"
        "AzureActivity\n"
        "| where TimeGenerated > ago(1h)\n"
        "| join kind=inner (\n"
        "AuditLogs\n"
        '| where Result == "success"\n'
        ") on $left.CorrelationId == $right.CorrelationId\n"
        '| where InitiatedBy == "x"\n'
        "```"
    )
    assert check_playbook(bad, "AzureActivity").errors, (
        "a phantom column on the detection's OWN table must still be caught"
    )


def test_the_playbook_skeleton_passes_its_own_validator(monkeypatch):
    """A model that follows the Phase 3 prompt exactly must not be rejected by it.

    `PLAYBOOK_SKELETON` hands the model `let AlertActor = "[FROM ALERT: ActorUpn
    or ActorId]";` to emit, and `check_playbook` ran `validate_kql`'s fill-in rule
    over the result -- a rule written for Phase 2, where a detection ships as
    generated and a surviving slot cannot be deployed. So every playbook failed on
    the slots its own skeleton required, spent a corrective call being told to
    remove them, and the retry pressured the model to strip the fields a responder
    fills in at the console. 147 such errors across the 36 skeletons.
    """
    import re

    from pylon.validation import script_check
    from pylon.validation.playbook_check import check_playbook

    # The PowerShell tier, stood down. This asserts about ONE KQL rule, and the
    # 36 skeletons carry 62 PowerShell blocks between them -- each of which
    # `check_playbook` hands to `pwsh` to parse and resolve against installed
    # modules. No `pwsh` on the machine this was written on, so the tier skipped
    # itself and the test looked instant; ubuntu-latest ships PowerShell, and the
    # first CI run spent 3m08s here out of 3m36s total. `ran=False` is exactly
    # the state the assertion was verified under. The tier keeps its own tests.
    monkeypatch.setattr(script_check, "parse_check",
                        lambda body, lang: script_check.ParseResult(ran=False))

    # Asked of the catalogue, not of `PLATFORMS[*].services`. Those tuples were
    # emptied for `arm` and `dataplane` when the catalogue took over deciding what
    # a run can be aimed at, and this loop went from 36 skeletons to ONE without
    # failing -- a parametrize over a shrinking list is green all the way to empty.
    from conftest import live_targets, prompt_for

    offenders = []
    checked = 0
    for key, target, table in live_targets():
        prompt = prompt_for(target, "playbook", "T1078")
        task = re.search(r"<task>(.*?)</task>", prompt, re.S)
        result = check_playbook(task.group(1) if task else prompt, table)
        checked += 1
        offenders += [(key, e) for e in result.errors if "fill-in placeholders" in e]
    assert checked >= 10, f"only {checked} skeletons reached -- the list emptied again"
    assert offenders == [], (
        f"{len(offenders)} playbook skeleton(s) rejected by the fill-in rule: "
        f"{offenders[:2]}"
    )


def test_a_detection_still_cannot_ship_with_a_fill_in_slot():
    """The other half. Scoping the rule to playbooks must not switch it off for
    Phase 2, where the query is deployed exactly as generated."""
    from pylon.validation.validate_kql import validate_kql

    kql = ('AzureActivity | where TimeGenerated > ago(1d) '
           '| where Caller == "[FROM ALERT: ActorUpn]"')
    errors = validate_kql(kql, "AzureActivity").errors
    assert any("fill-in placeholders" in e for e in errors), errors


def test_a_playbook_may_hand_the_operation_over_as_a_slot():
    """The Validation query filters on the operation the detection caught, and the
    skeleton hands that over as a slot for the responder to fill at the console.

    `allow_placeholders` stood the structural fill-in check down for playbooks and
    the operation-VALUE check one rule further on kept judging the same slot as a
    name -- so the data-plane skeleton was rejected for carrying exactly what it
    told the model to emit, and the corrective retry pressured it to drop the
    field.
    """
    from pylon.validation.validate_kql import validate_kql

    kql = ('AZKVAuditLogs | where TimeGenerated > ago(1d) '
           '| where OperationName =~ "[the operation from Phase 2]"')
    assert validate_kql(kql, "AZKVAuditLogs", allow_placeholders=True).errors == []
    # And a real name that the table never writes is still caught.
    wrong = ('AZKVAuditLogs | where TimeGenerated > ago(1d) '
             '| where OperationName =~ "SecretTeleport"')
    assert any("operation filter" in e for e in
               validate_kql(wrong, "AZKVAuditLogs", allow_placeholders=True).errors)


def test_the_data_plane_skeleton_passes_its_own_checker():
    """Every blank the five tables agree on is written in, so what is left is
    alert-specific. The template must survive the gate it is checked by.

    Rendered, not raw. The asset is SLOT bodies; `render_playbook` assembles them
    into the document the model is actually shown, and the "Fill these in first"
    block that defines AlertTime and AlertActor lives in the skeleton rather than
    in any plane's asset. Checking the fragment reported the skeleton's own
    prelude pattern as undefined names.
    """
    from pylon.prompts import load_asset, render_playbook
    from pylon.validation.playbook_check import check_playbook

    asset = render_playbook(load_asset("dataplane/playbook.md"))
    for table in ("AZKVAuditLogs", "StorageBlobLogs"):
        # __SERVICE__ is substituted by `_render` before the model sees it, so a
        # check that leaves it in place is judging a token no run ever contains.
        assert check_playbook(asset.replace("__SERVICE__", table), table).errors == [], table


def test_an_unfenced_playbook_is_a_failure_not_a_pass():
    """Measured on a real SecretPurge run: fourteen queries, none fenced, zero
    errors. `blocks()` finds blocks by fence, found none, the validation loop
    never ran, and an empty error list read as a clean file. Nothing to validate
    is not the same as nothing wrong."""
    from pylon.validation import playbook_check

    bare = """## Triage

AZKVAuditLogs
| where TimeGenerated >= ago(24h)
| where OperationName == "SecretPurge"
| project TimeGenerated, CallerIpAddress
"""
    result = playbook_check.check_playbook(bare, "AZKVAuditLogs")
    assert result.failed
    assert any("fenced code blocks" in e for e in result.errors), result.errors


def test_a_playbook_with_no_queries_at_all_is_a_failure():
    """The other half: prose with no queries gives a responder nothing to run."""
    from pylon.validation import playbook_check

    result = playbook_check.check_playbook("## Triage\n\nLook at the vault.\n",
                                           "AZKVAuditLogs")
    assert result.failed
    assert any("no KQL query blocks" in e for e in result.errors), result.errors


def test_a_correctly_fenced_playbook_does_not_trip_the_fence_check():
    """The check must not fire on the thing it is asking for."""
    from pylon.validation import playbook_check

    good = '```kql\nAZKVAuditLogs\n| where TimeGenerated > ago(1h)\n| take 5\n```'
    result = playbook_check.check_playbook(good, "AZKVAuditLogs")
    assert not any("fence" in e for e in result.errors), result.errors
    assert not playbook_check.unfenced_kql(good), (
        "a fenced query must not be seen as unfenced")


def test_the_skeleton_demands_fences_and_keeps_the_technique():
    """The checker rejecting unfenced KQL only costs a retry unless the model is
    told the rule. The same run also re-mapped T1485 to "unmapped (host/endpoint)"
    against the catalogue that maps it to Key Vault purge."""
    from pylon.prompts.shared import PLAYBOOK_SKELETON

    head = PLAYBOOK_SKELETON.split("# IR Playbook:", 1)[0]
    assert "```kql" in head
    assert "```powershell" in head
    assert "Do not re-map it" in head


def test_bare_queries_are_fenced_rather_than_asked_for():
    """Two consecutive real runs returned fourteen unfenced queries each, through
    a header rule AND a corrective retry. A rule the model can ignore is not a
    rule. Fencing here makes it a property of the output, and the real checks
    then run on queries that were previously invisible to every validator."""
    from pylon.validation.playbook_check import blocks, fence_bare_kql

    bare = """## Triage

AZKVAuditLogs
| where TimeGenerated > ago(1h)
| where OperationName == "SecretPurge"

Some prose after the query.
"""
    fenced = fence_bare_kql(bare)
    assert len(blocks(fenced)) == 1
    assert "Some prose after the query." in fenced
    assert "## Triage" in fenced.split("```kql")[0], "prose above must stay outside"


def test_the_let_lines_above_a_query_come_inside_the_fence():
    """They belong to the query, and leaving them out hid the exact fault worth
    catching: a self-referencing `let` sat one line above the table name, so it
    fell outside the fence and no checker ever saw it."""
    from pylon.validation.playbook_check import blocks, fence_bare_kql

    bare = 'let lookback = 24h;\nlet ActorId = ActorId;\nSigninLogs\n| where UserId == ActorId\n'
    body = blocks(fence_bare_kql(bare))[0][1]
    assert "let lookback" in body
    assert "let ActorId = ActorId;" in body


def test_a_fenced_playbook_is_left_alone():
    """The fencer must be a no-op on correct input, or it corrupts good output."""
    from pylon.validation.playbook_check import fence_bare_kql

    good = '## Triage\n\n```kql\nAZKVAuditLogs\n| take 1\n```\n\nprose\n'
    assert fence_bare_kql(good) == good


def test_a_self_referencing_let_is_an_error():
    """`let X = X;` is a cycle: the query does not run. It appears when a model
    tries to carry a value from one block into the next, where lets do not
    reach -- seven pivot queries in one measured playbook."""
    from pylon.validation.playbook_check import check_playbook

    q = '```kql\nlet ActorId = ActorId;\nSigninLogs\n| where UserId == ActorId\n```'
    result = check_playbook(q, "SigninLogs")
    assert any("refers to itself" in e for e in result.errors), result.errors


def test_ago_of_an_undefined_name_is_an_error():
    """`ago(lookback)` where the block never defines `lookback`. A let in an
    EARLIER block is out of scope, so the query does not run."""
    from pylon.validation.playbook_check import check_playbook

    bad = '```kql\nSigninLogs\n| where TimeGenerated >= ago(lookback)\n```'
    assert any("never defines" in e for e in check_playbook(bad, "SigninLogs").errors)

    ok = '```kql\nlet lookback = 24h;\nSigninLogs\n| where TimeGenerated >= ago(lookback)\n```'
    assert not any("never defines" in e for e in check_playbook(ok, "SigninLogs").errors)

    literal = '```kql\nSigninLogs\n| where TimeGenerated >= ago(24h)\n```'
    assert not any("never defines" in e for e in check_playbook(literal, "SigninLogs").errors)
