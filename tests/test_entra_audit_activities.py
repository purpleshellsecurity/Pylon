"""The Entra audit activity vocabulary.

AuditLogs.OperationName was the one surface in the tool with NEITHER half of the
pattern everything else uses: nothing put the real vocabulary in front of the
model, and nothing checked what came back. ARM operations have both. Data-plane
operations have both. Techniques got both earlier today.

The evidence it mattered: an Entra run produced ten detections, seven of them
T1098.003, every OperationName recalled — and the eval printed "operation
warnings: 0" for that target, which reads as clean and meant the check had never
run. A zero that means "not checked" is worse than a number.
"""

import pytest

from pylon.entra_audit_activities import (
    activities_for,
    categories,
    category_for,
    describe,
    is_known,
    category_for,
    render_for_prompt,
)
from pylon.validation.operation import validate_operation

# --- the catalog ---------------------------------------------------------------


def test_the_vocabulary_actually_loaded():
    assert len(categories()) > 20
    assert sum(len(activities_for(s)) for s in categories()) > 500


def test_a_real_activity_is_known_and_a_plausible_invention_is_not():
    # The pair that shows the check has teeth. Both read as reasonable English;
    # only one is a string Entra writes.
    assert is_known("Add member to role")
    assert not is_known("Add User To Role")


def test_matching_ignores_case_and_padding():
    # The model may emit a differently-cased or space-padded value; that is not
    # a hallucination and must not be reported as one.
    assert is_known("  add MEMBER to role ")


def test_an_activity_reports_the_category_it_belongs_to():
    # Category narrows a table carrying every directory event in a tenant.
    # NOT LoggedByService: that column holds "Core Directory" on the same row.
    assert category_for("Add member to role") == "RoleManagement"
    assert category_for("nonsense that is not an activity") == ""


def test_descriptions_are_available_where_the_reference_gives_them():
    described = [
        a for s in categories() for a in activities_for(s) if describe(a)
    ]
    assert described, "no activity carries a description"


# --- HALF 1: grounding ---------------------------------------------------------


def test_the_prompt_block_carries_the_operations_attacks_actually_use():
    block = render_for_prompt()
    for activity in ("Add member to role", "Consent to application"):
        assert activity in block, activity


def test_nothing_is_excluded_by_a_judgement_about_what_is_security_relevant():
    """There WAS a ten-service allowlist here, picked by taste, with no basis —
    and one of the ten was a service that did not exist. It existed to control
    cost, which the threat-phase-only placement solved instead. So the whole
    reference goes in: a detection for an unusual service must not be impossible
    because of a list somebody typed."""
    block = render_for_prompt()
    for category in categories():
        if activities_for(category):
            assert category in block, f"{category} silently excluded"


def test_the_full_vocabulary_is_affordable_because_it_is_injected_once():
    # ~10,600 tokens against a run that already spends ~44,000 on input — but
    # only because it is the threat call alone. In all 16 calls it was ~170,000.
    assert len(render_for_prompt()) < 60000


def test_the_block_says_when_it_caps_a_service():
    # Silent truncation would read as a complete vocabulary, which is the exact
    # failure this block exists to fix.
    block = render_for_prompt(("GroupManagement",), per_category=3)
    assert "more in this category" in block


def test_the_block_tells_the_model_what_to_do_when_nothing_fits():
    # Without this, a model that cannot find its behaviour in the list invents
    # one — which is the state before any of this existed.
    block = render_for_prompt()
    assert "rather than inventing" in block


def test_the_entra_prompt_carries_it_and_other_platforms_do_not():
    from pylon.prompts import build_system_prompt

    entra = build_system_prompt("graph", "Directory Changes", "threat")
    assert "<operation_reference>" in entra
    assert "Add member to role" in entra

    for platform, service in (("arm", "Key Vault"), ("dataplane", "Blob Storage")):
        other = build_system_prompt(platform, service, "threat")
        assert "<operation_reference>" not in other, f"{platform}/{service}"


def test_only_the_threat_phase_carries_it():
    """Phase 1 chooses the operation; phase 2 is handed it on the attack vector.
    Injecting into both paid ~2,600 tokens per detection — sixteen times over on
    a 15-vector run — to ground a choice already made."""
    from pylon.prompts import build_system_prompt

    for phase, kwargs in (("detection", {}), ("playbook", {"playbook_target": "Role"})):
        prompt = build_system_prompt("graph", "Directory Changes", phase, **kwargs)
        assert "<operation_reference>" not in prompt, phase

    # And the check still covers phase 2's output, which is what makes dropping
    # the vocabulary there safe rather than merely cheaper.
    assert validate_operation("Add User To Role", "AuditLogs") != []


# --- HALF 2: checking ----------------------------------------------------------


@pytest.mark.parametrize("operation", ["Add member to role", "Consent to application"])
def test_a_real_operation_passes_validation(operation):
    assert validate_operation(operation, "AuditLogs") == []


@pytest.mark.parametrize("operation", ["Add User To Role", "Grant Admin Consent"])
def test_an_invented_operation_is_warned_about(operation):
    warnings = validate_operation(operation, "AuditLogs")
    assert warnings and "Entra audit activity reference" in warnings[0]


def test_the_check_is_reachable_at_all():
    """The bug this test exists for: the data-plane branch returns for EVERY
    table that is not AzureActivity, so an AuditLogs check placed after it was
    dead code — it looked wired up and ran never."""
    assert validate_operation("Definitely Not An Activity", "AuditLogs") != []


def test_it_stays_a_warning_and_never_an_error():
    # Entra ships new activities continuously and this snapshot is deliberate,
    # so a miss is a signal, not proof. Rejecting a detection on it would break
    # every genuinely-new operation the day it appears.
    from pylon.validation.operation import validate_operation as v

    result = v("Some Brand New Activity", "AuditLogs")
    assert isinstance(result, list)
    assert all(isinstance(w, str) for w in result)


def test_other_tables_are_unaffected():
    # The AuditLogs branch runs first now, so the ARM and data-plane paths have
    # to still behave exactly as before.
    assert validate_operation("MICROSOFT.KEYVAULT/VAULTS/DELETE", "AzureActivity") == []
    assert "not shaped like an ARM operation" in validate_operation(
        "delete the vault", "AzureActivity")[0]


def test_the_block_groups_by_the_column_that_actually_holds_these_names():
    """This test used to assert the bug.

    It required `LoggedByService == "RoleManagement"` in the block, and the block
    duly emitted it, so the grounding text taught the model a filter that can
    never match. Both columns exist, so the query parsed, validated, deployed and
    returned clean for ever. Measured on a live tenant, one row carried
    Category="ApplicationManagement" and LoggedByService="Core Directory".

    The reference's own column header is "Audit Category". A test that locks in
    the wrong column is worse than no test, because it makes the mistake look
    deliberate.
    """
    block = render_for_prompt()
    assert 'Category =~ "RoleManagement"' in block


def test_the_block_never_teaches_a_loggedbyservice_filter():
    """The one assertion that would have caught it. Every name in this block is a
    Category value, so ANY LoggedByService filter built from the block is dead."""
    block = render_for_prompt()
    for category in categories():
        assert f'LoggedByService == "{category}"' not in block
        assert f'LoggedByService =~ "{category}"' not in block


def test_the_block_tells_the_model_to_match_operationname_case_insensitively():
    """These are the names Microsoft DOCUMENTS. A tenant writes them in a
    different case -- the reference says "Delete Conditional Access policy" and
    the tenant logged "Delete conditional access policy" -- and == is
    case-sensitive in KQL. The table asset has carried this rule all along; the
    vocabulary block was contradicting it by calling the values EXACT."""
    block = render_for_prompt()
    assert "=~" in block
    assert "case-sensitive" in block
