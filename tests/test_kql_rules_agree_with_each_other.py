"""The KQL rules must be satisfiable, together, at the same time.

This is the test the repo did not have on 2026-09-13, and its absence shipped a
contradiction: the exclusion-scaffolding rule was stated as REQUIRED in four
copies of the prompt, and both forms of it were rejected as ERRORS by two
separate gates. There was no way to write a detection that obeyed the prompt and
passed the validator, so the model's only viable output was one that ignored the
instruction -- which is what it produced, twice, silently.

Nothing could have noticed, because the requirement lived in prompt text and the
checks lived in validator code and no test read both.

The fix in one sentence: every rule carries an example it must ACCEPT, and every
such example is run through EVERY rule's checker. A rule that rejects another
rule's mandated shape fails here, immediately, with both ids named.
"""

import pytest

from pylon.validation import kql_rules

RULES = kql_rules.rules()
IDS = [str(r["id"]) for r in RULES]


def test_there_are_rules_to_check():
    """A parametrize over a shrinking list is green all the way to empty."""
    assert len(RULES) >= 5, f"only {len(RULES)} rule(s) loaded"


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_every_rule_is_complete(rule):
    assert rule.get("id"), rule
    assert rule.get("says", "").strip(), f"{rule['id']} says nothing to the model"
    assert rule.get("severity") in kql_rules.SEVERITIES, rule
    assert rule.get("provenance") in ("published", "measured", "decided"), rule
    if rule.get("source"):
        assert rule["source"] in kql_rules.sources(), \
            f"{rule['id']} cites {rule['source']!r}, which is not in `sources`"


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_a_rule_with_a_checker_names_one_that_exists(rule):
    """A rule naming a checker that is not registered enforces nothing while
    looking exactly like a rule that does."""
    check = str(rule.get("check") or "")
    if not check:
        pytest.skip(f"{rule['id']} is guidance with no checker")
    assert check in kql_rules._CHECKS, \
        f"{rule['id']} names checker {check!r}, which is not registered"


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_a_checked_rule_carries_both_kinds_of_example(rule):
    """Without both, a checker can be trivially wrong in one direction and the
    suite stays green: one that never fires passes every `accepts`, and one that
    always fires passes every `rejects`."""
    if not rule.get("check"):
        pytest.skip(f"{rule['id']} is guidance with no checker")
    assert rule.get("accepts"), f"{rule['id']} has no example it must accept"
    assert rule.get("rejects"), f"{rule['id']} has no example it must reject"


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_each_rule_rejects_what_it_says_it_rejects(rule):
    check = str(rule.get("check") or "")
    if not check:
        pytest.skip(f"{rule['id']} is guidance with no checker")
    checker = kql_rules._CHECKS[check]
    for example in rule.get("rejects") or []:
        assert checker(example), \
            f"{rule['id']} should reject this and does not:\n{example}"


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_each_rule_accepts_what_it_says_it_accepts(rule):
    check = str(rule.get("check") or "")
    if not check:
        pytest.skip(f"{rule['id']} is guidance with no checker")
    checker = kql_rules._CHECKS[check]
    for example in rule.get("accepts") or []:
        assert not checker(example), \
            f"{rule['id']} should accept this and does not:\n{example}"


# ── The one that matters ──────────────────────────────────────────────────────


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_no_rule_rejects_another_rules_required_shape(rule):
    """THE contradiction check.

    An example one rule requires is run through every OTHER rule's checker. If
    rule A mandates a shape that rule B rejects, there is no query that can obey
    both, and this fails naming A and B rather than leaving a model to discover
    it by having its output rejected.
    """
    for example in rule.get("accepts") or []:
        broken = kql_rules.problems(example)
        assert not broken, (
            f"{rule['id']} requires this query:\n{example}\n"
            f"but these rules reject it: "
            + ", ".join(f"{rid} ({sev})" for sev, rid, _ in broken))


def test_the_existing_validator_agrees_with_the_new_rules():
    """The contradiction was BETWEEN the two piles, so checking the new pile
    against itself is not enough. Every accepted example is also run through the
    old validator's structural and performance checks."""
    from pylon.validation.validate_kql import _performance_issues, _structural_issues

    for rule in RULES:
        for example in rule.get("accepts") or []:
            errors, _warnings = _structural_issues(example)
            assert not errors, (
                f"{rule['id']} requires a query the existing validator rejects:\n"
                f"{example}\n{errors}")
            perf = _performance_issues(example)
            assert not perf, (
                f"{rule['id']} requires a query the existing performance checks "
                f"flag:\n{example}\n{perf}")


# ── What reaches the model ────────────────────────────────────────────────────


def test_every_rule_reaches_the_prompt():
    """One object, two consumers. A rule that is enforced and never stated is a
    detection rejected for a reason nobody was told; a rule stated and never
    enforced is the pile this file replaced."""
    rendered = kql_rules.render()
    for rule in RULES:
        head = " ".join(str(rule["says"]).split())[:40]
        assert head in rendered, f"{rule['id']} is not in the rendered prompt"


def test_unchecked_rules_are_countable():
    """Not "there are none" -- there are, and prose guidance is legitimate. The
    point is that the number is reachable rather than assumed."""
    unchecked = kql_rules.unchecked()
    assert all(kql_rules.by_id(r).get("severity") == "guidance" for r in unchecked), \
        f"a rule with no checker is not marked guidance: {unchecked}"


# ── Every prompt a run can build ──────────────────────────────────────────────


def test_every_prompt_builder_states_the_rules_it_enforces():
    """Placement is not the safeguard; this test is.

    There are several prompt builders and the repo has already been bitten once
    by editing one and believing the prompt had changed -- four kept the old
    text and every test still passed, because the tests only exercised the path
    that was edited. A rule enforced by the gate and absent from the prompt is a
    detection rejected for a reason nobody was told.
    """
    from conftest import live_targets, prompt_for
    from pylon.validation import kql_rules

    first = " ".join(str(kql_rules.rules()[0]["says"]).split())[:40]
    targets = live_targets()
    assert targets, "no targets to build prompts for"
    for key, target, table in targets:
        for phase in ("threat", "detection"):
            text = prompt_for(target, phase,
                              "a vector" if phase == "playbook" else None)
            assert first in text, f"{key} {phase} prompt does not state the KQL rules"


def test_a_rule_added_later_reaches_the_prompt_too():
    """`kql_contract()` is a function for this reason. As a module constant it
    would be evaluated at import, and a rule added to the catalogue afterwards
    would reach the validator and not the model -- the same asymmetry, rebuilt
    one layer down."""
    from pylon.prompts import shared

    assert callable(shared.kql_contract)


# ── Tuning notes are output too, and nothing used to check them ───────────────


def test_suppression_advice_is_rejected_only_on_a_privilege_grant():
    """The same sentence is right on one detection and wrong on another.

    Allowlisting the deploy principal on an App Service config write is how that
    rule becomes usable. Allowlisting the break-glass account on a permanent
    Global Administrator grant makes the highest-value identity in the tenant
    invisible to the one rule watching for its abuse. So this is scoped by
    technique, and a technique it does not list is left alone.
    """
    from pylon.validation.kql_rules import guidance_problems

    advice = "- Allowlist ActorUPN for break-glass or approved automation accounts."
    assert guidance_problems(advice, "T1098.003"), "a GA grant must reject this"
    assert not guidance_problems(advice, "T1651"), "a config write must accept it"
    assert not guidance_problems(advice, ""), "no technique means no verdict"


def test_narrowing_by_role_is_not_suppressing_by_actor():
    """The replacement advice must pass, or the rule bans tuning rather than
    bad tuning. Measured on a real regeneration: the model moved from
    "Allowlist ActorUPN" to "Allowlist RoleId for non-admin roles", which
    suppresses by WHICH ROLE was granted rather than by who granted it."""
    from pylon.validation.kql_rules import guidance_problems

    good = ("- Scope initially to critical roles: Global Administrator, "
            "Privileged Role Administrator\n"
            "- Allowlist RoleId for non-admin roles where permanent grants "
            "are policy-approved")
    assert not guidance_problems(good, "T1098.003"), good


def test_the_rule_names_the_techniques_it_applies_to_in_the_prompt():
    """A rule in force for six techniques and silent about which is a rule the
    model has to guess the scope of."""
    rendered = kql_rules.render("detection")
    assert "T1098.003" in rendered
    assert "Applies to:" in rendered


def test_a_tuning_rule_is_not_rendered_into_a_playbook_prompt():
    """A playbook has no tuning notes. Stating the rule there is noise the
    reader has to work out is irrelevant."""
    assert "T1098.003" not in kql_rules.render("playbook")


# ── A prompt must not instruct a column the contract calls empty ──────────────


def test_no_prompt_tells_the_model_to_read_an_always_empty_column():
    """The NORMALIZE OUTPUT rule said `TargetResource = ResourceId`, and the
    AzureActivity contract records ResourceId as never populated -- measured
    empty on all 35,000 rows. So the prompt required the exact thing the
    contract gate rejects, and a generated detection failed validation for
    obeying its own instructions.

    It had been true for as long as both existed. It surfaced only when the two
    rule sets were merged and the model happened to follow the literal example
    rather than reach for `_ResourceId` on its own -- which is the worst way for
    a contradiction to behave: intermittent, and blamed on the model.

    The same fault was fixed in the ARM PLAYBOOK asset earlier the same day and
    not looked for in the detection prompt. Hence a test over every prompt, not
    a second fix.
    """
    from pylon import contracts
    from pylon.prompts import build_system_prompt

    for plane, table in (("arm", "AzureActivity"), ("entra", "AuditLogs"),
                         ("dataplane", "AZKVAuditLogs"),
                         ("dataplane", "StorageBlobLogs")):
        empty = [str(c) for c in (contracts.for_table(table) or {}).get("never_populated") or []]
        prompt = build_system_prompt(plane, table, "detection", None)
        # The prompt names these columns legitimately, to say DO NOT USE them.
        # An instruction is an assignment or a comparison, not a mention.
        import re
        # A prompt names these columns legitimately, to say DO NOT USE them --
        # the ARM asset carries a labelled CORRECT/WRONG pair showing
        # `OperationName ==` as the wrong one. An instruction is an assignment
        # or comparison that is NOT sitting under such a marker.
        warned = ("WRONG", "NEVER", "never", "not populated", "do not", "Do NOT",
                  "always empty", "ALWAYS empty", "is EMPTY", "matches nothing")
        for column in empty:
            for m in re.finditer(
                    rf"=\s*{re.escape(column)}\b|\b{re.escape(column)}\s*[=!]=", prompt):
                lead = prompt[max(0, m.start() - 220):m.start()]
                if any(w in lead for w in warned):
                    continue
                assert False, (
                    f"{plane}/{table}: the prompt instructs `{m.group(0)}` with "
                    f"nothing warning against it, and the contract records "
                    f"{column} as never populated")
