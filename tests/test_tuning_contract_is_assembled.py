"""Every field of the tuning contract comes from a catalogue, or is the one
sentence that deliberately does not.

The risk this file guards is the one that would be easiest to ship here: 25
targets x 9 fields is 225 cells, and filling them with plausible prose would
look complete and be unverifiable. Eight of the nine are assembled, so they can
be checked; the ninth is identical everywhere, so it cannot be a per-target
guess dressed as a finding.
"""

import pytest

from pylon import contracts, tuning

ROWS = tuning.contracts_all()
IDS = [r["target"] for r in ROWS]


def test_every_target_has_a_row():
    from pylon.services import targets

    assert len(ROWS) == len(targets()), "a target is missing from the tuning contract"
    assert len(ROWS) >= 20, f"only {len(ROWS)} rows"


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_the_target_is_named_the_way_a_user_would_type_it(row):
    """The registry's dict key is a lowercased lookup form and its `key`
    attribute is the display form. Printing the lookup form gave every Entra row
    a name that matches nothing in `design list`."""
    from pylon.services import targets

    assert row["target"] in {t.key for t in targets().values()}


def _all_field_lists(row):
    """The primary table's fields AND every other table's.

    The prose bug was fixed on the primary path and left on the other-tables
    path, because this test only read the primary. A target that writes to four
    tables has four of these lists and all four reach a reader.
    """
    yield row["key_fields"]
    for entry in row.get("other_tables") or []:
        yield entry["key_fields"]


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_every_key_field_is_an_expression_not_prose(row):
    """`key fields to alert on` is the one place an analyst is being told what to
    put in a query. A contract's honest "no single column carries this" belongs
    in a note, not here -- AuditLogs records the source address inside
    InitiatedBy and has no column for it."""
    for fields in _all_field_lists(row):
        for expression, _meaning in fields:
            assert "see " not in expression.lower(), expression
            assert "not a column" not in expression.lower(), expression
            assert "none" != expression.lower().split()[0], expression
            assert len(expression.split()) <= 3, f"reads as prose: {expression}"
            names = [e for e, _ in fields]
            assert names.count(expression) == 1, f"listed twice: {expression}"


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_a_baseline_query_carries_no_unresolved_placeholder(row):
    """A family contract is written once for several tables, so its reference
    query is a template. Substituting only {window} shipped four storage queries
    beginning with a literal `{`, which do not parse -- found by running all 25
    against a workspace, not by reading them."""
    assert row["baseline"], f"{row['target']} has no baseline query"
    assert "{" not in row["baseline"], row["baseline"]
    assert "}" not in row["baseline"], row["baseline"]


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_the_baseline_reads_the_table_the_row_names(row):
    first = row["baseline"].strip().splitlines()[0].strip()
    assert first == row["primary_table"], f"{row['target']}: {first}"


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_a_tuning_lever_names_a_column_the_contract_measured(row):
    """An analyst told to allowlist on a column that does not exist gets a rule
    that suppresses nothing and looks tuned."""
    c = contracts.for_table(row["primary_table"]) or {}
    measured = set(c.get("typing") or {})
    for value in (c.get("roles") or {}).values():
        # `scope` is a LIST in every contract and `contracts.roles` joins it
        # with commas, so treating each role value as one name loses
        # `_ResourceId` and `ServiceEndpoint` -- which are exactly the columns a
        # scope lever names.
        parts = value if isinstance(value, list) else str(value).split(",")
        measured |= {str(part).split("--")[0].strip() for part in parts}
    measured |= set(c.get("observed_values") or {})
    from pylon import correlation as co
    measured |= {f["field"] for f in co.actor_fields(row["primary_table"])}
    import re
    for lever in row["levers"]:
        expression = lever.split(" — ")[0]
        names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expression)
        assert any(n in measured for n in names), \
            f"{row['target']}: lever {expression!r} names nothing the contract measured"


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_noise_entries_carry_the_reason_they_were_excluded(row):
    """"This is noisy" asserted is an opinion; "this is noisy BECAUSE" is the
    catalogue's recorded judgement. Every entry has to carry the second."""
    for entry in row["noisy"]:
        assert entry["why"].strip(), f"{row['target']}: {entry['rule']} has no reason"
        # Provenance travels with it. An exclusion is a recorded human
        # judgement, never a measurement and never Microsoft's word, and a
        # reader has to be able to tell which kind of claim they are given.
        assert entry["source"] == "decided", entry


# ── The field that is deliberately identical ──────────────────────────────────


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_the_false_positive_field_is_the_same_everywhere(row):
    """Not a per-target guess. Whether an actor is AUTHORIZED is a fact about
    one organization -- who they designated to run an account, a service
    principal, a sync identity or a pipeline -- and no catalogue can hold it.
    Varying this sentence per target would present invented specifics as
    findings; one sentence everywhere is a question, and a question is honest.
    """
    assert row["false_positives"] == tuning.FALSE_POSITIVES
    assert "[Customer to populate" in row["false_positives"]


def test_the_false_positive_field_is_not_confused_with_noise():
    """Generic first-party noise IS groundable -- token issuance, sync job
    mechanics, portal reads -- and stays in `noisy`, sourced from the rejection
    taxonomy. The two must not collapse into each other."""
    entra = next(r for r in ROWS if r["target"] == "Entra")
    rules = {e["rule"] for e in entra["noisy"]}
    assert "R-token-issuance" in rules
    assert "R-provisioning" in rules
    assert tuning.FALSE_POSITIVES not in str(entra["noisy"])


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_severity_comes_from_attack_tiers_only(row):
    """Not from a judgement about what feels important. Every tier present must
    be one ATT&CK's tactics can produce."""
    assert set(row["severity"]) <= {"early", "mid", "late", "unmapped"}, row["severity"]


def test_no_contract_types_something_that_is_not_a_column():
    """A role entry in the TYPING block is invisible to `roles()` and nonsense
    in the prompt.

    Measured: the storage family contract carried `target: ObjectKey` and
    `scope: [AccountName, _ResourceId]` under `typing`, so `render()` told the
    model "`scope` is typed ['AccountName', '_ResourceId']" -- a Python list
    repr offered as a type -- while `roles()` could not see either, and every
    storage playbook and tuning row was missing the object acted on and the
    resource to scope by. Nothing noticed until the verifier learned to check
    typing against a live schema.

    Offline half of that check: a typed name must not be a ROLE name. The live
    half, which also catches a wrong type, is scripts/verify-contracts.py.
    """
    from pylon import contracts

    roles = {"who", "who_id", "who_upn", "who_app", "who_name", "who_sid",
             "what", "outcome", "outcome_text", "outcome_code", "outcome_cast",
             "target", "target_kind", "target_host", "scope", "from_where",
             "client", "correlate", "severity", "detail", "host", "function",
             "statement", "stream", "why_decided", "display", "opaque_id"}
    for table in sorted(contracts.tables()):
        typed = set((contracts.for_table(table) or {}).get("typing") or {})
        stray = sorted(n for n in typed if n in roles)
        assert not stray, (
            f"{table}: {stray} are ROLE names sitting in the typing block. "
            f"They belong in `roles`, where the renderers can read them.")


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_severity_counts_every_table_the_target_writes_to(row):
    """Microsoft.Web/sites has twelve techniques, all of them on AzureActivity,
    and the row computed severity from its most SPECIFIC table -- so it reported
    "no technique mapped to this target yet" for a target with twelve."""
    from pylon import knowledge

    expected: dict[str, int] = {}
    for table in row["tables"]:
        for tier, n in knowledge.mapped_tiers(
                table, category=row["category"],
                resource_type=row["resource_type"]).items():
            expected[tier] = expected.get(tier, 0) + n
    assert row["severity"] == expected


def test_app_service_reports_the_techniques_it_has():
    """The specific regression, named. Guards the shape as well as the number:
    a reader has to be told WHICH table carries them."""
    row = next(r for r in ROWS if r["target"] == "Microsoft.Web/sites")
    assert sum(row["severity"].values()) >= 10, row["severity"]
    assert "AzureActivity" in row["technique_tables"]
    assert "AzureActivity" in tuning.render(row)
