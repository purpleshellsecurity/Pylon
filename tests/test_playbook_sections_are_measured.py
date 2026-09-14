"""The playbook sections that are ASSEMBLED from the contract, not asked for.

Every claim these sections make is a claim some contract already makes. The
defect this file exists to catch is the one this repo keeps producing: a fact
that lives in one place and does not reach the place that needs it. Here that
would be a triage question naming a column the contract never measured, or a
monitoring note offering a column the contract records as always empty, or --
the one that already happened three times in one afternoon -- three sections
disagreeing about whether a table names an actor at all.
"""

import pytest

from pylon import contracts, knowledge
from pylon.playbook import (
    _actor_reference,
    assessment_questions,
    attack_diagram,
    escalation_matrix,
    monitoring,
    prevention,
)
from pylon.prompts import _TABLE_RULES_KEY

# AzureDiagnostics answers per SERVICE, never at the table level: its roles live
# in the per-provider sections, so asking it a table-level question is asking the
# wrong question. It is exercised through SHARED below instead.
WIRED = sorted(set(_TABLE_RULES_KEY) - {"AzureDiagnostics"})


@pytest.mark.parametrize("table", WIRED)
def test_every_wired_table_can_answer_at_least_three_triage_questions(table):
    """If a table's roles are too thin to ask three questions of, the contract is
    the thing to fix, not the renderer. Measured when this was written: three on
    the two App Service tables and the Function App host log, four or five
    everywhere else."""
    rows = [r for r in assessment_questions(table).splitlines()[2:] if r.strip()]
    assert len(rows) >= 3, f"{table} produced {len(rows)} triage question(s)"


@pytest.mark.parametrize("table", WIRED)
def test_a_triage_question_never_names_a_column_the_contract_did_not_measure(table):
    """The whole point of rendering these is that the columns are measured. A
    question pointing at a column nobody counted is the documentation-grounded
    failure this replaced."""
    import re

    c = contracts.for_table(table) or {}
    known = set(c.get("typing") or {})
    known |= set(map(str, c.get("never_populated") or []))
    known |= {str(v).split("--")[0].strip()
              for v in (c.get("roles") or {}).values()}
    known |= set((c.get("observed_values") or {}))
    # `columns` is a COUNT at the top level of a contract and a LIST inside a
    # per-service section. Same key, two types, on purpose.
    for section in (c.get("services") or {}).values():
        known |= {str(x) for x in (section.get("columns") or [])}
        known |= {str(v).split("--")[0].strip()
                  for v in (section.get("roles") or {}).values()}
    # Columns reachable through the correlation map count as measured too: the
    # map is where a claim-bag principal is recorded.
    from pylon import correlation as co
    known |= {f["field"] for f in co.actor_fields(table)}
    ip = co.ip_field(table)
    if ip:
        known.add(ip["field"])

    for line in assessment_questions(table).splitlines()[2:]:
        for ref in re.findall(r"`([^`]+)`", line):
            bare = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", ref)
            assert any(b in known for b in bare), \
                f"{table}: triage question names {ref!r}, which no contract measured"


@pytest.mark.parametrize("table", WIRED)
def test_one_answer_to_whether_the_table_names_an_actor(table):
    """The triage question, the diagram and the monitoring baseline must agree.

    They did not. Key Vault's contract says the principal is "NOT a column",
    which is true and does not mean the table is actor-less -- the correlation
    map carries the expression that reads the claim bag. Three renderers each
    decided for themselves and Key Vault came out actor-less in all three: no
    baseline line, an unusable triage answer, and a diagram opening on "source
    address" for a table that names the caller on every row.
    """
    actor = _actor_reference(table)
    diagram = attack_diagram(table, "SomeOperation")
    assert ("   actor" in diagram) == bool(actor), table
    baselines = [n for n in monitoring(table) if n.startswith("Baseline `")]
    if actor:
        assert any(actor in n for n in baselines), \
            f"{table}: names an actor but no baseline mentions it"
        assert actor in assessment_questions(table), \
            f"{table}: names an actor but the triage question does not use it"


@pytest.mark.parametrize("table", WIRED)
def test_monitoring_never_offers_a_column_the_contract_calls_empty(table):
    """An empty column is offered as a WARNING or not at all. Recommending a
    baseline on one produces a rule that runs forever and matches nothing."""
    unusable = contracts.unusable(table)
    for note in monitoring(table):
        if note.startswith(("Measured empty", "Never build a rule", "These columns")):
            continue
        for column in unusable:
            assert f"`{column}`" not in note, \
                f"{table}: monitoring offers {column}, which the contract calls unusable"


def test_the_escalation_tier_comes_from_attack_not_from_an_opinion():
    """A late-chain technique gets an IMMEDIATE top row; a discovery technique
    does not, and gains a monitoring row saying why."""
    late = escalation_matrix("AZKVAuditLogs", "T1485 Data Destruction")
    early = escalation_matrix("AzureActivity", "T1526 Cloud Service Discovery")
    assert "🔴 IMMEDIATE ESCALATION" in late.splitlines()[2]
    assert "🟡 STANDARD INVESTIGATION" in early.splitlines()[2]
    assert "discovery phase" in early
    assert "discovery phase" not in late


def test_a_policy_row_always_says_what_to_configure():
    """A row with an empty How column is not a recommendation. Controls with no
    Azure guidance are dropped rather than rendered blank."""
    text = prevention("AZKVAuditLogs", "T1485 Data Destruction",
                      "Key Vault Secrets Officer", "VaultDelete")
    rows = [r for r in text.splitlines() if r.startswith("| ") and "---" not in r]
    for row in rows[1:]:
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert all(cells), f"policy row has an empty cell: {row}"


def test_mitre_countermeasures_reach_the_index_and_the_document():
    """The harvest is only useful if it lands in the index AND is rendered. It
    was added to `refresh.py` and read by `knowledge.about`; a test that checked
    only the first would have passed with nothing reaching a playbook."""
    published = (knowledge._techniques().get("T1485") or {}).get("mitigations") or []
    assert "Data Backup" in published
    text = prevention("AZKVAuditLogs", "T1485 Data Destruction", "", "VaultDelete")
    assert "Data Backup" in text
    assert "ATT&CK's published countermeasures" in text


def test_a_technique_with_no_published_countermeasure_renders_no_policy_table():
    """ATT&CK publishes none for most discovery techniques, on the stated
    grounds that preventing enumeration breaks the service. Padding the table
    with invented controls would present a judgement as published fact."""
    assert not (knowledge._techniques().get("T1526") or {}).get("mitigations")
    text = prevention("AzureActivity", "T1526 Cloud Service Discovery", "", "")
    assert "**Policies to enable**" not in text


@pytest.mark.parametrize("service", ["MICROSOFT.AUTOMATION/AuditEvent",
                                    "MICROSOFT.AUTOMATION/JobLogs",
                                    "MICROSOFT.SQL/SQLSecurityAuditEvents"])
def test_each_shared_service_can_answer_its_own_triage_questions(service):
    rows = [r for r in assessment_questions("AzureDiagnostics", service).splitlines()[2:]
            if r.strip()]
    assert len(rows) >= 3, f"{service} produced {len(rows)} triage question(s)"


SHARED = [("MICROSOFT.AUTOMATION/AuditEvent", "clientInfo_ObjectId_g"),
          ("MICROSOFT.AUTOMATION/JobLogs", "Caller_s"),
          ("MICROSOFT.SQL/SQLSecurityAuditEvents", "server_principal_name_s")]


@pytest.mark.parametrize("service,actor", SHARED)
def test_the_shared_table_answers_per_service_not_per_table(service, actor):
    """AzureDiagnostics is every service's table, so "who did this" has one
    answer per provider and category. A single table-level answer would be
    wrong for at least two of these three."""
    assert _actor_reference("AzureDiagnostics", service) == actor
    assert actor in assessment_questions("AzureDiagnostics", service)


def test_the_shared_table_says_when_the_address_is_scrubbed():
    """Automation redacts the caller address to the literal "{scrubbed}". A
    responder who is not told will go looking for a field that is there and
    holds nothing."""
    notes = monitoring("AzureDiagnostics", "MICROSOFT.AUTOMATION/AuditEvent")
    assert any("redacted" in n for n in notes), notes


# ── The check that would have caught every column bug in this file's history ──
#
# The data-plane asset spelled four of its columns by hand -- CallerIpAddress,
# OperationName, RequesterUpn via the storage default, and CorrelationId -- and
# every one of them was right for the tables the asset was written from and a
# hard error on the three added later. Measured against a live workspace: five
# of AppServiceAuditLogs' own queries, five of FunctionAppLogs', four of
# AppServiceIPSecAuditLogs'. All three were shipping.
#
# The contract knew the right column for each, in every case, the whole time.
# Nothing asked it. This test asks it, offline, for every table on the asset.

def _rendered(table: str, section: str = "") -> str:
    from types import SimpleNamespace

    from pylon.playbook import PlaybookFill, document_template, render

    fill = PlaybookFill(
        what_happened="The actor reached the object.",
        attack_context="The actor reached the object. The material is disclosed.",
        why_it_matters=["The material is disclosed", "The access is still held"],
        true_positive_indicators=["No prior history", "Followed by an export"],
        containment_role="Reader")
    target = SimpleNamespace(
        operation="Op", priority="high",
        detection=SimpleNamespace(vector_name="V", mitre_technique="T1485 Data Destruction",
                                  false_positive_notes="fp"))
    platform = {"AzureActivity": "arm", "AuditLogs": "entra"}.get(table, "dataplane")
    template = document_template(platform, table, "V", operation="Op",
                                 technique="T1485 Data Destruction", az_provider=section)
    return render(template, target, table, fill, section)


def _primary_blocks(doc: str, table: str) -> list[str]:
    """The KQL blocks that read the playbook's OWN table.

    A cross-log pivot reads another table on purpose and must not be checked
    against this one's contract -- AzureActivity.Caller is not a Key Vault
    column and is not meant to be.
    """
    import re

    out = []
    for block in re.findall(r"```kql\n(.*?)```", doc, re.S):
        body = re.sub(r'^\s*let\s+\w+\s*=.*$', "", block, flags=re.M).strip()
        if body.startswith(table):
            out.append(block)
    return out


@pytest.mark.parametrize("table", WIRED)
def test_no_query_names_a_column_its_own_table_does_not_have(table):
    doc = _rendered(table)
    problems = []
    for block in _primary_blocks(doc, table):
        problems += contracts.conforms(block, table)
    assert not problems, f"{table}: {problems[:3]}"


@pytest.mark.parametrize("service", ["MICROSOFT.AUTOMATION/AuditEvent",
                                     "MICROSOFT.AUTOMATION/JobLogs",
                                     "MICROSOFT.AUTOMATION/JobStreams",
                                     "MICROSOFT.SQL/SQLSecurityAuditEvents"])
def test_every_shared_table_query_scopes_itself_to_one_service(service):
    """The contract's defining warning: one filter on AzureDiagnostics returns
    every service in the tenant that writes there. A query that does not narrow
    by provider AND category is reading other people's events."""
    doc = _rendered("AzureDiagnostics", service)
    blocks = _primary_blocks(doc, "AzureDiagnostics")
    assert blocks, "no query read the shared table at all"
    provider, category = service.split("/")
    for block in blocks:
        # The positive control is unscoped ON PURPOSE. Its question is "is this
        # table receiving anything at all since containment" -- if logging was
        # turned off, every scoped query returns nothing and looks like success.
        # Narrowing it to one service would defeat the only check in the
        # document that can tell "contained" from "blind".
        if "TotalRowsInWindow" in block:
            continue
        assert f'ResourceProvider == "{provider}"' in block, block
        assert f'Category == "{category}"' in block, block


@pytest.mark.parametrize("table", WIRED)
def test_an_actor_column_is_gated_where_the_contract_gates_it(table):
    """A column that only names somebody under a condition is rendered under
    that condition. The storage family names a principal on 38 rows of 196 and
    the playbook projected it flat on all of them, which reads as "nobody did
    this" rather than "this row cannot say"."""
    gate = (contracts.for_table(table) or {}).get("attribution", {}).get("gate")
    if not gate:
        pytest.skip(f"{table} has no attribution gate")
    from pylon.playbook import normalisation
    assert gate in normalisation(table)["__NORMALISE_FULL__"]
