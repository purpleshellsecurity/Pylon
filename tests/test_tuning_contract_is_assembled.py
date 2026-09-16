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


# ── what the page says about an exclusion ────────────────────────────────────

def test_a_count_prefix_leads_the_line():
    """`knowledge.excluded` hands over one string whose first sentence is the
    count. The reader is scanning for how much of the target this covers, so it
    goes in front rather than being buried mid-sentence."""
    count, reason = tuning._reason(
        "42 of 82 activities. Request and approval bookkeeping around an act.")
    assert count == "42 of 82 activities"
    assert reason.startswith("Request and approval")


def test_a_first_sentence_that_merely_contains_of_is_not_a_count():
    """Key Vault's exclusions are per-operation and carry no count. "Recovery
    of a soft-deleted secret" was split off as though it were one, joining two
    sentences with an em dash."""
    count, reason = tuning._reason(
        "Recovery of a soft-deleted secret. The subsequent read is what matters.")
    assert count == ""
    assert reason.startswith("Recovery of a soft-deleted secret.")


def test_a_long_reason_ends_on_a_sentence():
    """`clip` at 210 characters ended a line with "another when it is approved
    or denied, another…" -- a clause that stops mid-thought, where the reader
    cannot tell whether the argument finished."""
    long = ". ".join(f"Sentence number {n} runs on for a while yet" for n in range(40))
    _count, reason = tuning._reason(long + ".")
    assert reason.endswith(". …")
    assert "runs on for a while yet. …" in reason
    # Cut between sentences, never inside a word.
    assert not reason.replace(". …", "").endswith(("Sentenc", "numbe", "whil"))


def test_a_reason_that_fits_is_printed_whole():
    whole = ("The restoring direction of an act that is itself mapped. "
             "Re-enabling an account, restoring a deleted object.")
    assert tuning._reason(whole)[1] == whole
    assert "…" not in tuning._reason(whole)[1]


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_the_exclusions_say_what_they_are_before_naming_a_rule_id(row):
    """The heading was "Common noisy activities" and every row led with
    `R-workflow`, which is a catalogue key and tells a reader nothing."""
    text = tuning.render(row)
    if not row["noisy"]:
        return
    assert "**Deliberately not detected**" in text
    assert "no detection fires on" in text
    line = next(ln for ln in text.splitlines()
                if ln.startswith("- ") and row["noisy"][0]["rule"] in ln)
    assert line.endswith(f"[`{row['noisy'][0]['rule']}`]"), line
    assert not line.startswith(f"- `{row['noisy'][0]['rule']}`"), line


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_severity_names_only_the_stages_this_target_has(row):
    """It printed the definition of `late` AND `early` whether or not either was
    present, with the tenant's counts embedded in the vocabulary lesson."""
    text = tuning.render(row)
    assert "**How severe** —" in text
    tiers = row["severity"]
    if not tiers:
        assert "no technique is mapped to this target yet" in text
        return
    severity = next(ln for ln in text.splitlines() if ln.startswith("**How severe**"))
    for stage, present in (("late in an attack", "late"), ("mid-chain", "mid"),
                           ("early — discovery", "early")):
        assert (stage in severity) is bool(tiers.get(present)), (stage, tiers)


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_the_severity_verb_agrees_with_its_count(row):
    severity = next((ln for ln in tuning.render(row).splitlines()
                     if ln.startswith("**How severe**")), "")
    for wrong in ("1 of them sit ", "1 sit ", "2 sits ", "2 of them sits "):
        assert wrong not in severity, (wrong, severity)


# ── descriptive by construction, not by one hand-written paragraph ───────────

@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_every_exclusion_shows_a_name_or_is_one(row):
    """The guarantee. A row either names the operation it excludes in its own
    id -- which is the per-operation shape -- or it covers many operations and
    prints examples of them.

    That is what stops one well-explained rule and twelve opaque ones: the
    names come out of the catalogue, so a rule added tomorrow gets them with no
    prose written for it.
    """
    for n in row["noisy"]:
        rule_is_a_name = not n["rule"].startswith("R-")
        assert rule_is_a_name or n["examples"], (row["target"], n["rule"])


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_a_rule_row_prints_the_names_it_covers(row):
    text = tuning.render(row)
    for n in row["noisy"][:6]:
        if not n["examples"]:
            continue
        shown = [name for name, _ in tuning._examples(n["examples"],
                                                      row.get("detected") or [])]
        assert shown, (row["target"], n["rule"])
        for name in shown:
            assert f"not detected: `{name}`" in text, name


def test_a_counterpart_is_only_claimed_when_the_names_really_match():
    """A wrong pair asserts a relationship the catalogue never recorded."""
    detected = ["Add member to role in PIM completed (permanent)"]
    assert tuning._counterpart(
        "Add member to role in PIM requested (permanent)", detected) == detected[0]
    # Shares "Add " and nothing else that matters.
    assert tuning._counterpart("Add role definition", detected) == ""
    assert tuning._counterpart("Delete secret", detected) == ""
    assert tuning._counterpart("anything", []) == ""


def test_the_examples_do_not_pair_twice_to_the_same_operation():
    """Two `canceled` variants pair to one completed operation, and printing it
    twice spends four lines saying one thing."""
    names = ["Add member to role in PIM canceled (permanent)",
             "Add member to role in PIM canceled (renew)",
             "Zzz unrelated activity name here"]
    detected = ["Add member to role in PIM completed (permanent)"]
    pairs = tuning._examples(names, detected)
    counterparts = [c for _n, c in pairs if c]
    assert len(counterparts) == len(set(counterparts))


def test_the_pairs_come_before_the_unpaired_ones():
    names = ["Zzz something with no match at all",
             "Add member to role in PIM requested (permanent)"]
    detected = ["Add member to role in PIM completed (permanent)"]
    assert tuning._examples(names, detected)[0][1] == detected[0]


@pytest.mark.parametrize("row", ROWS, ids=IDS)
def test_what_is_detected_is_stated_beside_what_is_not(row):
    """A list of exclusions with no statement of what IS detected reads as
    "almost nothing is watched here". For RoleManagement it is 33 of 82."""
    text = tuning.render(row)
    if not row["detected"]:
        assert "**What is detected**" not in text
        return
    assert "**What is detected**" in text
    assert str(len(row["detected"])) in text
    assert f"- `{row['detected'][0]}`" in text


def test_the_detected_list_is_not_a_second_copy_of_the_excluded_one():
    """They are read off the same catalogue block and must not overlap: an
    operation cannot be both mapped and excluded."""
    for row in ROWS:
        excluded = {n["rule"] for n in row["noisy"] if not n["rule"].startswith("R-")}
        overlap = excluded & set(row["detected"])
        assert not overlap, (row["target"], sorted(overlap))


def test_a_name_that_extends_another_is_not_its_counterpart():
    """"Delete application collection" against "Delete application" cleared
    both bars -- 18 shared characters, 0.87 similarity -- and printed as though
    deleting a collection were the undetected half of deleting an application.
    They are different objects.

    A lifecycle differs by SUBSTITUTION: requested/completed,
    onboarded/offboarded. It never differs by appending a noun.
    """
    assert tuning._counterpart("Delete application collection",
                               ["Delete application"]) == ""
    assert tuning._counterpart("Update application collection",
                               ["Update application"]) == ""
    # The substitutions still pair.
    assert tuning._counterpart(
        "Add member to role in PIM requested (permanent)",
        ["Add member to role in PIM completed (permanent)"]) \
        == "Add member to role in PIM completed (permanent)"


def test_no_printed_pair_is_an_extension_of_its_counterpart():
    """The rule, over the whole catalogue rather than the one case found."""
    for row in ROWS:
        for n in row["noisy"][:6]:
            for name, instead in tuning._examples(n["examples"], row["detected"]):
                if not instead:
                    continue
                assert not name.startswith(instead), (row["target"], name)
                assert not instead.startswith(name), (row["target"], name)
