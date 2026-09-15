"""`design list` gives you the options; `design list <target>` explains one.

It printed the explanation for all fourteen at once to begin with -- about 130
lines to answer "what can I run", with the answer scrolled off the top before the
question was read. That is a reference page. A list is one line per option.

Azure names one thing three ways and none of the three can be guessed from the
others: the resource type you own, the table it writes to, and the string you
filter on. `OperationName` exists on AzureActivity and holds a DISPLAY name --
the harvested string is in `OperationNameValue`. `==` is case-sensitive in KQL
and a tenant spells an AuditLogs activity differently than the reference does.
Both mistakes produce a query that parses, runs, and matches nothing.

So the listing prints all three per table, and neither fact is retyped here: it
reads the same `operation_column` and `operation_match` the KQL validator does.
"""

import io
import re
from contextlib import redirect_stdout

import pytest

from pylon.cli import _design_list, build_parser
from pylon.services import (ENTRA_KEY, operation_column, operation_match,
                            operation_vocabulary, resolve_target, targets)

_TARGETS = list(targets().values())
_IDS = [t.key for t in _TARGETS]


def _listing(*argv: str) -> str:
    """Through the parser, so the flags the listing prints are the real ones."""
    args = build_parser().parse_args(["design", "list", *argv])
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert _design_list(args) == 0
    return buf.getvalue()


def _detail(key: str) -> str:
    return _listing(key)


def _block_for(text: str, key: str) -> str:
    start = text.index(f"\n{key}\n") if f"\n{key}\n" in text else text.index(f"{key}\n")
    rest = text[start:]
    nxt = re.search(r"\n\n", rest[1:])
    return rest[: nxt.end()] if nxt else rest


def test_stdout_is_the_accepted_values_and_nothing_else():
    """It is the answer to "what may I type", so it is the values themselves --
    greppable and pipeable, `pylon design list | fzf` being the obvious use. It
    carried a tables column and a footer before this, which made it something you
    read rather than something you pick from."""
    lines = _listing().splitlines()
    # Compared as a SET. This asserted list equality, which pinned the
    # catalogue's own ordering as a side effect of checking the contents -- and
    # the contents are what the name of this test is about. `Entra` is the whole
    # directory and eleven `Entra Something` rows are slices of it; sorted
    # plainly the parent landed last, reading as a stray line, so the ordering
    # changed. `test_cleanroom_findings` asserts the new order deliberately.
    assert set(lines) == {t.key for t in _TARGETS}
    assert len(lines) == len(_TARGETS), "a value is printed twice"
    for line in lines:
        assert resolve_target(line), f"{line!r} is printed and is not accepted"


def test_the_hint_goes_to_stderr_so_a_pipe_gets_only_values():
    import contextlib

    args = build_parser().parse_args(["design", "list"])
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), contextlib.redirect_stderr(err):
        assert _design_list(args) == 0
    assert "design detections" not in out.getvalue()
    assert "design detections" in err.getvalue()


@pytest.mark.parametrize("target", _TARGETS, ids=_IDS)
def test_every_target_prints_the_command_that_runs_it(target):
    assert f"pylon design detections {target.key}" in _detail(target.key), (
        "a reader should copy the line, not assemble it"
    )


@pytest.mark.parametrize("target", _TARGETS, ids=_IDS)
def test_every_target_names_the_tables_it_queries(target):
    block = _detail(target.key)
    for table in target.tables or ("AuditLogs",):
        assert table in block


@pytest.mark.parametrize("target", _TARGETS, ids=_IDS)
def test_a_refused_surface_is_named_and_not_silently_dropped(target):
    """Microsoft.Web/sites runs control plane only because six App Service tables
    have no operation vocabulary. Printing the surfaces and staying quiet about
    the rest is how "App Service covered" gets believed."""
    block = _detail(target.key)
    for refusal in target.refused:
        assert refusal in block


def test_azure_activity_is_filtered_on_the_value_column_not_the_display_name():
    block = _detail("Microsoft.KeyVault/vaults")
    assert "OperationNameValue" in block
    assert operation_column("AzureActivity") == "OperationNameValue"


def test_auditlogs_is_shown_with_the_case_insensitive_operator():
    block = _detail(ENTRA_KEY)
    operator, why = operation_match("AuditLogs")
    assert operator == "=~"
    assert "=~" in block and why in block


def test_a_resource_on_both_planes_shows_both_tables_in_one_target():
    """Key Vault and Key Vault Secrets were one vault listed twice, split by
    plane. One resource type, both tables, one run."""
    block = _detail("Microsoft.KeyVault/vaults")
    assert "AzureActivity" in block and "AZKVAuditLogs" in block
    assert "Key Vault" in block


def test_the_samples_are_real_operations_from_the_catalogue():
    for key, table in (("Microsoft.KeyVault/vaults", "AZKVAuditLogs"),
                       ("Microsoft.Storage/storageAccounts/blobServices",
                        "StorageBlobLogs"),
                       (ENTRA_KEY, "AuditLogs")):
        target = resolve_target(key)
        vocab = set(operation_vocabulary(target.resource_type, table))
        block = _detail(key)
        shown = re.findall(r'^\s+"(.+)"$', block, re.M)
        assert shown, f"{key} shows no example operation"
        assert vocab & set(shown), f"{key} shows no name from its own vocabulary"


def test_a_target_the_tool_cannot_ground_is_refused_here_too():
    """`design list <thing>` and `design detections <thing>` answer the same
    question about whether a target exists, so they must not disagree."""
    args = build_parser().parse_args(["design", "list", "Microsoft.DataFactory/factories"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert _design_list(args) == 2


def test_a_spaced_target_survives_an_unquoted_shell():
    """`Entra RoleManagement` has a space in it, so argparse gets two tokens
    unless the user quotes. Joining makes both spellings mean the same thing."""
    args = build_parser().parse_args(["design", "list", "Entra", "RoleManagement"])
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert _design_list(args) == 0
    assert "Entra RoleManagement" in buf.getvalue()


def test_a_category_slice_reports_its_own_vocabulary_not_the_directory():
    """It showed 922 for `Entra RoleManagement`, which describes a run other than
    the one about to happen."""
    block = _detail("Entra RoleManagement")
    assert "82 known operation(s)" in block
    assert "922" not in block
