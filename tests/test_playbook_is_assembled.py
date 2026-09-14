"""The document is assembled, not requested.

Three runs of one vector produced three structurally different playbooks. None
used the fourteen sections. The cause was not a weak rule: the whole document was
a REQUEST, and a model handed a nearly-complete template to reproduce rewrites it.

Measured on the rendered data-plane template, the 21 bracketed blanks sort into
nine the responder fills from the alert row, six Pylon already holds, and four
that genuinely need a model. So Pylon renders the document and asks for four
fields. What the playbook LOOKS like stops being a thing that can vary.
"""

import re

import pytest

from pylon.models import Detection, ValidatedDetection
from pylon.playbook import (
    PlaybookFill,
    document_template,
    facts,
    operation_lists,
    render,
    unfilled,
)

TABLES = ("AZKVAuditLogs", "AzureActivity", "AuditLogs", "StorageBlobLogs")

FILL = PlaybookFill(
    what_happened="The actor permanently destroyed a soft-deleted secret.",
    attack_context="The actor purged a soft-deleted secret. It has no recovery "
                   "path, so every application still reading it is failing now.",
    why_it_matters=["The secret cannot be recovered by any means",
                    "Every consumer is failing until a replacement is issued"],
    true_positive_indicators=[
        "The purge followed a soft-delete by the same principal within minutes",
        "The principal has never issued a Key Vault data-plane call before",
    ],
    containment_role="Key Vault Secrets Officer",
)


# A real operation per table. One vocabulary does not serve four planes, and a
# fixture that pretends otherwise fails on the vocabulary check for a reason that
# has nothing to do with what is being tested.
_OPERATION = {
    "AZKVAuditLogs": "SecretPurge",
    "AzureActivity": "MICROSOFT.KEYVAULT/VAULTS/DELETE",
    "AuditLogs": "Add member to role",
    "StorageBlobLogs": "DeleteBlob",
}


def _target(table: str) -> ValidatedDetection:
    return ValidatedDetection(
        detection=Detection(vector_name="Destructive operation",
                            mitre_technique="T1485", kql=f"{table} | take 1",
                            tuning_guidance="t",
                            false_positive_notes="rotation automation"),
        log_table=table, valid=True, errors=[], warnings=[], retried=False,
        operation=_OPERATION[table], rationale="x", priority="high")


@pytest.mark.parametrize("table", TABLES)
def test_every_plane_renders_all_sixteen_sections(table):
    """The structure is the same on every plane and in every run, because no run
    is in a position to change it."""
    doc = render(document_template("dataplane", table, "X"), _target(table), table, FILL)
    headings = [h.strip() for h in re.findall(r"^## (.+)$", doc, re.M)]
    assert headings[0] == "Playbook Metadata"
    assert headings[-1] == "Escalate immediately if"
    # Evidence before containment is the procedure, not a preference.
    assert headings.index("Preserve Evidence") < headings.index("Containment")
    assert headings.index("Containment") < headings.index("Eradication")
    # Fifteen since Current State was added between the cross-log pivots and
    # evidence preservation. Everything above it reads history; it reads the
    # present, and it has to run before containment changes the present.
    assert "Current State" in headings
    assert headings.index("Current State") < headings.index("Preserve Evidence")
    # Sixteen since the attack diagram got a heading. It had rendered as a bare
    # fence under the metadata for as long as it existed, and round nine
    # reported the section absent from five playbooks that contained it --
    # a section nothing can navigate to is one nobody finds.
    assert "Attack Sequence" in headings
    assert headings.index("Attack Sequence") < headings.index("Attack Context")
    assert len(headings) == 16, headings


@pytest.mark.parametrize("table", TABLES)
def test_nothing_is_left_that_nobody_can_fill(table):
    """A blank with no stated source is one the responder cannot fill either."""
    doc = render(document_template("dataplane", table, "X"), _target(table), table, FILL)
    assert unfilled(doc) == []


@pytest.mark.parametrize("table", TABLES)
def test_the_responder_blanks_survive(table):
    """Filling these would be inventing alert data. They must stay brackets."""
    doc = render(document_template("dataplane", table, "X"), _target(table), table, FILL)
    assert "[FROM ALERT:" in doc


def test_the_facts_pylon_holds_are_never_asked_for():
    """One run re-mapped T1485 to "unmapped (host/endpoint)" against the
    catalogue that maps it to Key Vault purge. A fact Pylon holds and asks for
    anyway is a fact that can come back wrong."""
    got = facts(_target("AZKVAuditLogs"), "AZKVAuditLogs")
    assert got["[technique ID and name]"] == "T1485"
    assert got["[the operation from Phase 2]"] == "SecretPurge"
    assert got["[common false positives]"] == "rotation automation"
    assert got["[from Phase 2]"] == "high"
    assert set(got).isdisjoint(set(PlaybookFill.model_fields))


def test_the_operation_lists_come_from_the_catalogue():
    """"The read operations for this table" was a blank the model filled from
    recall, which makes it a list of plausible operation names."""
    from pylon import data_plane_operations as dp

    reads, writes = operation_lists("AZKVAuditLogs")
    assert '"SecretGet"' in reads and '"SecretList"' in reads
    assert '"SecretPurge"' in writes and '"SecretSet"' in writes
    assert '"SecretGet"' not in writes
    for quoted in re.findall(r'"([^"]+)"', reads + ", " + writes):
        assert dp.reference("AZKVAuditLogs", quoted), quoted


@pytest.mark.parametrize("table", TABLES)
def test_the_document_carries_no_instructions_to_the_model(table):
    """The skeleton serves two readers and only one of them should see "produce
    the sections below". One skeleton, marked regions, stripped for the
    document -- rather than a prompt copy and a document copy that drift."""
    doc = render(document_template("dataplane", table, "X"), _target(table), table, FILL)
    for phrase in ("Produce exactly the structure", "supplied with this prompt",
                   "will be rejected", "<!-- GUIDE", "Do not re-map it"):
        assert phrase not in doc, phrase


def test_the_fill_prompt_keeps_the_grounding_and_drops_the_document():
    from pylon.playbook import fill_prompt
    from pylon.prompts import build_system_prompt

    full = build_system_prompt("dataplane", "AZKVAuditLogs", "playbook",
                               playbook_target="x")
    small = fill_prompt(full)
    for kept in ("<role>", "<platform_rules>", "<schema_reference>"):
        assert kept in small, kept
    assert "Produce exactly the structure below" not in small
    assert len(small) < len(full)


def test_the_field_counts_are_checked_not_suggested():
    """A count in a prompt is a suggestion; a count on a field is a check."""
    base = dict(what_happened="It happened.", attack_context="A. B.",
                why_it_matters=["one", "two"],
                true_positive_indicators=["one", "two"],
                containment_role="Reader")
    PlaybookFill(**base)
    with pytest.raises(ValueError):
        PlaybookFill(**{**base, "why_it_matters": ["only one"]})
    with pytest.raises(ValueError):
        PlaybookFill(**{**base, "why_it_matters": ["a", "b", "c", "d", "e"]})
    with pytest.raises(ValueError):
        PlaybookFill(**{**base, "containment_role": "a b c d e f g h i j"})
    with pytest.raises(ValueError):
        PlaybookFill(**{**base, "attack_context": "A. B. C. D. E."})
    with pytest.raises(ValueError):
        PlaybookFill(**{**base, "true_positive_indicators": ["only one"]})
    with pytest.raises(ValueError):
        PlaybookFill(**{**base, "true_positive_indicators": ["a b " * 20, "b"]})


def test_one_blank_means_one_thing_on_every_plane():
    """Three assets spelled the false-positive blank three ways and the role two,
    so a filler had to know each plane's wording. The assets are readers of one
    vocabulary now."""
    from pathlib import Path

    from pylon import prompts

    root = Path(prompts.__file__).parent / "assets"
    seen = set()
    for asset in sorted(root.glob("*/playbook.md")):
        seen |= set(re.findall(r"\[([^\]\[\n]{3,110})\]", asset.read_text()))
    for gone in ("most likely benign triggers",
                 "IAM automation, provisioning tools, approved admins",
                 "application service accounts, backup jobs, CI/CD",
                 "the data-plane role", "the role from Phase 2",
                 "Impact bullet 1"):
        assert gone not in seen, f"{gone!r} is a second spelling of a shared blank"


def test_a_run_says_which_build_produced_it():
    """Four playbook runs in a row were read as evidence about code that was not
    installed. The changes were pushed, the tool was not reinstalled, and nothing
    in the output said so — so each run cost a round to establish only that.

    The path matters as much as the number: a repo checkout and a `uv tool
    install` can report the same version while running different code.
    """
    from pylon.cli import _version_line

    line = _version_line()
    assert line.startswith("pylon ")
    assert "running from" in line
    assert "unknown" not in line.splitlines()[0], (
        "the package must be installed for the version to mean anything")


@pytest.mark.parametrize("table", TABLES)
def test_no_query_reads_another_table_s_columns(table):
    """The data-plane asset used to carry BOTH normalisation lines with "keep one
    and delete the other". That was a choice the model made; under assembly it is
    Pylon's, and nobody was making it -- so a Key Vault playbook shipped reading
    RequesterUpn and StatusCode, which are Storage columns. Every query in it
    would have errored, and the checker passed it, because validate_kql does not
    flag a missing column on the right of an `extend`.
    """
    doc = render(document_template("dataplane", table, "X"), _target(table), table, FILL)
    foreign = {
        "AZKVAuditLogs": ("RequesterUpn", "RequesterObjectId", "UserAgentHeader",
                          'StatusCode != "200"'),
        "StorageBlobLogs": ("Identity.claim", "HttpStatusCode", "ClientInfo"),
    }.get(table, ())
    for column in foreign:
        assert column not in doc, f"{table} playbook reads {column}"


def test_the_normalisation_is_written_for_the_table():
    from pylon.playbook import normalisation

    kv = normalisation("AZKVAuditLogs")
    assert "tostring(Identity.claim.upn)" in kv["__NORMALISE_ACTOR__"]
    assert "HttpStatusCode >= 300" in kv["__NORMALISE_ACTOR_FAIL__"]
    blob = normalisation("StorageBlobLogs")
    assert "RequesterUpn" in blob["__NORMALISE_ACTOR__"]
    assert '"200"' in blob["__NORMALISE_ACTOR_FAIL__"]
    # No token may survive into a document.
    for table in TABLES:
        doc = render(document_template("dataplane", table, "X"),
                     _target(table), table, FILL)
        assert "__NORMALISE" not in doc


@pytest.mark.parametrize("table", ("AZKVAuditLogs", "StorageBlobLogs"))
def test_cross_log_pivots_carry_real_queries(table):
    """The section shipped with no queries and a leftover instruction telling the
    responder the pivots were "supplied with this prompt" — something they cannot
    see. They come from the correlation map now."""
    doc = render(document_template("dataplane", table, "X"), _target(table), table, FILL)
    section = doc.split("## Cross-Log Pivots", 1)[1].split("\n---", 1)[0]
    assert "supplied with this prompt" not in section
    assert "```kql" in section, "the pivots section has no queries"
    assert "SigninLogs" in section


@pytest.mark.parametrize("table", TABLES)
def test_a_name_defined_below_its_use_does_not_count(table):
    """The positive control is the FIRST query a responder runs, and it read
    ContainmentTime from the block BELOW it — so it did not run at all, and a
    zero would have read as a broken logging pipeline rather than a broken query.

    The check scoped names to the whole document, which passed it. Ordering is
    the fix: a `let` above resolves, a `let` below does not.
    """
    from pylon.validation.playbook_check import check_playbook

    doc = render(document_template("dataplane", table, "X"), _target(table), table, FILL)
    assert check_playbook(doc, table).errors == []

    below = ('```kql\n%s\n| where TimeGenerated > T\n| count\n```\n\n'
             '```kql\nlet T = datetime([X]);\n%s | take 1\n```' % (table, table))
    assert any("any block above" in e
               for e in check_playbook(below, table).errors), "ordering is not checked"


@pytest.mark.parametrize("table", TABLES)
def test_the_positive_control_defines_its_own_time(table):
    """It is run on its own, before anything else. Self-contained or useless."""
    doc = render(document_template("dataplane", table, "X"), _target(table), table, FILL)
    control = doc.split("**Positive control", 1)[1].split("```", 2)[1]
    assert "let ContainmentTime" in control
