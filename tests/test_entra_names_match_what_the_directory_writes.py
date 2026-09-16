"""Entra writes typographic punctuation; the reference page transcribes ASCII.

Measured on a live tenant. The directory emits

    'Update application – Certificates and secrets management '

with an EN DASH and a trailing space. The catalogue holds

    'Update application - Certificates and secrets management'

`=~` forgives case and nothing else, so a detection built from the catalogue
entry runs, validates, deploys and matches zero events for ever. Verified
against 30 days of a real workspace: the catalogue spelling matches 0 rows and
`has "Certificates and secrets management"` matches all 44.

57 of the 922 catalogued names contain a dash, so patching the two we have
evidence for would leave the rest to fail the same way. Two fixes: the lookup
normalises, and the contract tells a detection to stop using equality on these.
"""

from pylon import contracts
from pylon.entra_audit_activities import (activities_for, categories,
                                          category_for, is_known, normalise)

_EN_DASH = "Update application – Certificates and secrets management "
_ASCII = "Update application - Certificates and secrets management"


# --- the lookup ------------------------------------------------------------

def test_the_name_the_directory_writes_is_recognised():
    assert is_known(_EN_DASH), "the tenant's own spelling must resolve"
    assert category_for(_EN_DASH) == "ApplicationManagement"


def test_the_name_the_catalogue_holds_still_resolves():
    assert is_known(_ASCII)
    assert category_for(_ASCII) == category_for(_EN_DASH)


def test_case_and_inner_whitespace_fold_too():
    assert normalise("ADD  CONDITIONAL   ACCESS POLICY") == "add conditional access policy"
    assert is_known("ADD CONDITIONAL ACCESS POLICY")


def test_a_name_that_is_in_neither_source_stays_absent():
    """Normalising must not turn a real gap into a false match."""
    assert not is_known("Update PasswordProfilee")
    assert not is_known("Add member to roles")


def test_a_name_the_directory_writes_and_the_docs_omit_is_known_but_not_documented():
    """Microsoft's reference publishes 922 names. This tenant emitted three that
    appear nowhere on it, including a password reset. They are carried under
    their own key so the two claims stay separable: the directory writes this,
    and Microsoft does not say so."""
    from pylon.entra_audit_activities import is_documented

    for observed in ("Update PasswordProfile",
                     "Add app role assignment grant to user"):
        assert is_known(observed), f"{observed} was measured in a live directory"
        assert not is_documented(observed), (
            f"{observed} is on the reference page after all -- move it")
    assert is_documented("Add member to role"), "a documented name must stay so"


def test_normalisation_only_merges_names_that_were_already_the_same():
    """Folding is safe only while it keeps distinct activities distinct.

    Measured: 922 distinct names fold to 916 keys. All six merges are the
    catalogue listing one activity twice with different casing -- "Update
    Domain" and "Update domain" -- so nothing real is lost. The assertion is
    that every merge is case-only, which is a stronger and more useful claim
    than a tolerance on the count.
    """
    import collections

    every = {a for c in categories() for a in activities_for(c)}
    folded = collections.Counter(normalise(a) for a in every)
    for key, count in folded.items():
        if count == 1:
            continue
        originals = sorted(a for a in every if normalise(a) == key)
        lowered = {a.casefold() for a in originals}
        assert len(lowered) == 1, (
            f"normalise() merged genuinely different activities: {originals}")


# --- the contract ----------------------------------------------------------

def test_an_equality_match_on_a_dashed_name_is_flagged():
    """The query would run and match nothing. This is the only signal available
    before the query is put in front of a workspace."""
    kql = (f'AuditLogs\n| where TimeGenerated > ago(1d)\n'
           f'| where OperationName =~ "{_ASCII}"')
    problems = contracts.conforms(kql, "AuditLogs")
    assert problems, "an equality match on a dashed name must be caught"
    assert "dash" in problems[0]


def test_the_operator_that_works_is_accepted():
    kql = ('AuditLogs\n| where TimeGenerated > ago(1d)\n'
           '| where OperationName has "Certificates and secrets management"')
    assert contracts.conforms(kql, "AuditLogs") == []


def test_a_name_without_a_dash_may_still_use_equality():
    kql = ('AuditLogs\n| where TimeGenerated > ago(1d)\n'
           '| where OperationName =~ "Add member to role"')
    assert contracts.conforms(kql, "AuditLogs") == []


def test_the_rule_reaches_the_prompt():
    rendered = contracts.render("AuditLogs")
    assert rendered, "AuditLogs renders no contract"
    from pylon.prompts import table_rules
    assert rendered in table_rules("AuditLogs")
