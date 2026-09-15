"""Two round-nine findings about sections that were present but unusable.

The attack diagram rendered as a bare code fence between the metadata block and
the first `---`, with no heading. Round nine reported it ABSENT from five
playbooks it was present in, because nothing scanning the document's structure
could see it -- which, for a section, is the same as not being there.

The current-state block asked two generic questions for every service. A blob
playbook whose Attack Context said the actor was checking "for publicly exposed
containers" never asked whether a container was public.
"""
import re

import pytest

from pylon.playbook import attack_diagram, current_state, document_template


def test_the_attack_diagram_carries_its_own_heading():
    out = attack_diagram("StorageBlobLogs", "GetBlob", "T1619")
    assert out.startswith("## "), out[:80]
    assert "```" in out, "the diagram itself is gone"


def test_the_diagram_heading_is_findable_in_a_built_document():
    doc = document_template("azure", "StorageBlobLogs", "Blob Storage",
                            operation="GetBlob", technique="T1619")
    headings = re.findall(r"(?m)^## .+", doc)
    assert any("Attack Sequence" in h for h in headings), headings


def test_an_empty_diagram_leaves_no_orphan_heading():
    """The heading travels WITH the content rather than living in the skeleton,
    because the slot's default is the empty string -- a heading written into the
    skeleton would stand alone over nothing."""
    from pylon.prompts import PLAYBOOK_SKELETON, PLAYBOOK_SLOT_DEFAULTS

    assert PLAYBOOK_SLOT_DEFAULTS["attack_diagram"] == ""
    before = PLAYBOOK_SKELETON[:PLAYBOOK_SKELETON.index("{attack_diagram}")]
    assert not before.rstrip().endswith("## Attack Sequence"), (
        "the heading is in the skeleton, so it renders over an empty diagram")


def test_every_table_still_gets_the_two_generic_questions():
    for table in ("AZKVAuditLogs", "StorageBlobLogs", "AuditLogs", ""):
        out = current_state(table)
        assert "az resource show --ids" in out, table
        assert "az role assignment list --assignee" in out, table


def test_blob_is_asked_whether_a_container_is_public():
    out = current_state("StorageBlobLogs")
    assert "container-rm list" in out, out
    assert "publicAccess" in out
    assert "allowBlobPublicAccess" in out


def test_a_table_with_no_entry_gets_only_the_generic_pair():
    assert current_state("AZKVAuditLogs") == current_state("")


def test_the_blob_commands_keep_their_shell_line_continuations():
    """Written as a raw string: a trailing backslash is a SHELL continuation,
    and in a normal Python string it is eaten as a Python one, collapsing the
    command onto one line."""
    out = current_state("StorageBlobLogs")
    assert " \\\n" in out, "line continuations were consumed"


@pytest.mark.parametrize("table", ["StorageBlobLogs", "AZKVAuditLogs"])
def test_current_state_names_no_placeholder_the_document_cannot_fill(table):
    """Every [FROM ALERT: x] must be a field the rest of the playbook fills."""
    out = current_state(table)
    known = {"TargetResource", "ActorUpn or ActorId", "AccountName"}
    for name in re.findall(r"\[FROM ALERT: ([^\]]+)\]", out):
        assert name in known, f"{name!r} is not a field the playbook fills"
