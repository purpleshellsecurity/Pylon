"""Real events, captured once, graded forever without a tenant.

Everything learned about Azure's log shapes this week came from reading real
rows: that `Authorization.evidence.role` is the CALLER's role, that
`ResourceId` is empty on all 99 role-assignment rows, that the assignment GUID
arrives dashed on writes and undashed on 17 of 23 deletes. All of it lives as
prose in a prompt file, where nothing tests it and nothing notices when it goes
stale. A recorded row makes it executable.
"""

from pylon.record import fixture, redact

REAL_UPN = "someone@contoso.example"
REAL_SUB = "11111111-2222-3333-4444-555555555555"
OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
OWNER_FLAT = "8e3af657a8ff443ca75c2fe8c4bcb635"


def test_the_identifiers_a_tenant_would_recognise_are_replaced():
    seen = {}
    out = redact(f"{REAL_UPN} from 10.1.2.3 in /subscriptions/{REAL_SUB}/x", seen)
    for real in (REAL_UPN, REAL_SUB, "10.1.2.3"):
        assert real not in out, out


def test_a_replacement_keeps_the_shape_it_replaced():
    """This week's defects were all about shape -- a path compared to a bare
    GUID, a dashed id matched against an undashed one. A fixture that
    normalises shape away cannot reproduce them."""
    import re

    seen = {}
    out = redact(f"/subscriptions/{REAL_SUB}/rg", seen)
    guid = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", out)
    assert guid, out
    assert redact(REAL_UPN, {}).count("@") == 1


def test_the_same_real_id_becomes_the_same_fake_one():
    """Not cosmetic. A detection joining Start to Success on CorrelationId only
    works if the mapping is stable -- otherwise the fixture tests a join that
    can never succeed and every recorded detection reads as dead."""
    seen = {}
    first = redact(REAL_SUB, seen)
    assert redact(f"nested {REAL_SUB} again", seen).split()[1] == first


def test_a_builtin_role_guid_survives_in_both_spellings():
    """Azure writes the same built-in role id dashed in the request body and
    UNDASHED in Authorization.evidence. Redacting either destroys the fixture:
    the detection compares against exactly that constant."""
    seen = {}
    assert OWNER in redact(f"/roleDefinitions/{OWNER}", seen)
    assert OWNER_FLAT in redact(f'{{"roleDefinitionId":"{OWNER_FLAT}"}}', seen)


def test_a_principal_guid_is_still_replaced_beside_a_role_guid():
    """The keep-list is for Azure's own constants, not for anything GUID-shaped
    sitting next to one."""
    # Made up, deliberately. A real principal id from the tenant this was
    # developed against is exactly the thing `record` exists to strip, and a
    # test asserting that must not be the file that carries one.
    principal = "0123456789abcdef0123456789abcdef"
    out = redact(f'{{"roleDefinitionId":"{OWNER_FLAT}","principalId":"{principal}"}}', {})
    assert OWNER_FLAT in out and principal not in out


def test_nested_json_is_walked():
    """Half of what matters on an AzureActivity row is inside a JSON string."""
    out = redact({"Properties": {"caller": REAL_UPN, "n": 5}}, {})
    assert REAL_UPN not in str(out)
    assert out["Properties"]["n"] == 5, "numbers are not identifiers"


# ── the fixture itself ───────────────────────────────────────────────────────

def _fx():
    return fixture("x", "AzureActivity", "AzureActivity | take 1",
                   "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
                   [{"Caller": REAL_UPN, "CorrelationId": REAL_SUB}],
                   [{"Caller": REAL_UPN, "CorrelationId": REAL_SUB}])


def test_both_row_sets_are_labelled():
    labels = [e["label"] for e in _fx()["events"]]
    assert labels == ["tp", "tn"]


def test_one_actor_stays_one_actor_across_both_sets():
    """What lets a fixture catch a detection matching on the actor rather than
    on the operation."""
    tp, tn = _fx()["events"]
    assert tp["Caller"] == tn["Caller"]


def test_empty_columns_are_dropped_not_recorded_as_empty():
    fx = fixture("x", "T", "q", "op", [{"A": "v", "B": "", "C": None}], [])
    assert set(fx["events"][0]) == {"A", "label"}


def test_the_fixture_says_what_was_not_redacted():
    """Resource and resource-group NAMES survive. In a customer tenant that
    might be their company, and a fixture is read by someone deciding whether
    to trust it."""
    assert "NAMES ARE NOT REDACTED" in _fx()["note"]


# ── the grader could not run a recorded fixture at all ───────────────────────

def test_a_null_string_is_an_empty_string_in_a_datatable():
    """Kusto refuses `string(null)` as a datatable literal and accepts `""`.
    It accepts the typed null for dynamic, datetime and the numerics, which is
    why this looked fine.

    It never surfaced because the harness was only ever exercised with an
    injected row_counter, so no real engine had seen the script it builds. Every
    recorded fixture leaves most of a 37-column table empty, so every one of
    them came back as a bad request with each event errored -- the harness could
    not grade a single real row.
    """
    from pylon.golden_eval import _kql_literal

    assert _kql_literal(None, "string") == '""'
    assert _kql_literal(None, "dynamic") == "dynamic(null)"
    assert _kql_literal(None, "datetime") == "datetime(null)"
    assert _kql_literal(None, "int") == "int(null)"


def test_a_real_value_is_still_rendered_as_itself():
    from pylon.golden_eval import _kql_literal

    assert _kql_literal("x", "string") == '"x"'
    assert _kql_literal(5, "int") == "5"
