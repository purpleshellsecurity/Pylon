"""A `//` inside a string literal is not a comment, and one module decides that.

Five modules each needed "the query with its comments gone", and four of them
wrote `re.sub(r"//[^\n]*", "", kql)`. That is wrong on every KQL query carrying
a URL -- a blob endpoint, a vault host, an OAuth issuer -- because stripping
from the `//` also deletes the string's closing quote and everything after it on
that line.

The fifth, `live_schema`, had already found this and written a paragraph about
it, which is the tell: the knowledge existed and did not reach the other four.
So `kqltext` is now the only place that tokenises a query, and this file holds
the others to it.

WHAT THIS CANNOT DO
-------------------
It forbids the naive pattern; it cannot make a new module use `kqltext` at all.
A module that never strips comments is invisible here.
"""

import pathlib
import re

import pytest

from pylon import contracts, kqltext, verification
from pylon.validation.validate_kql import validate_kql

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "pylon"

URL_LINE = (
    '| where Uri has "https://acct.blob.core.windows.net/" '
    'and OperationName == "PutBlobb"\n'
)


def test_no_module_strips_comments_by_hand():
    """The pattern itself is the defect. `kqltext` is where it is allowed."""
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "kqltext.py":
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r'r"//\[\^', line) or re.search(r"r'//\[\^", line):
                offenders.append(f"{path.relative_to(SRC)}:{i}")
    assert offenders == [], (
        "these treat any `//` as a comment, so a URL in a string eats its line: "
        + ", ".join(offenders))


def test_the_scheme_slashes_survive():
    kept = kqltext.strip_comments(URL_LINE)
    assert '"https://acct.blob.core.windows.net/"' in kept, kept
    assert 'OperationName == "PutBlobb"' in kept, kept


def test_a_real_comment_still_goes():
    out = kqltext.strip_comments('| where A == "b" // and never this\n| project A\n')
    assert "never this" not in out, out
    assert '"b"' in out and "project A" in out, out


def test_blanking_keeps_the_clause_shape():
    """The column-case scan reads identifier POSITIONS, so a value must leave an
    empty string behind rather than vanish -- and a `|` inside a value must not
    read as a pipe."""
    out = kqltext.blank('| where Op == "a|b" // note')
    assert out.count("|") == 1, out
    assert '""' in out, out


def test_the_validator_still_sees_a_typo_beside_a_url():
    """The shipping direction: a wrong operation name on the same line as a
    blob endpoint used to validate clean."""
    query = 'StorageBlobLogs\n| where AuthenticationType == "OAuth"\n' + URL_LINE
    assert any("PutBlobb" in e for e in validate_kql(query, "StorageBlobLogs").errors)


@pytest.mark.parametrize("blank", [contracts._code, verification._blank],
                         ids=["contracts", "verification"])
def test_the_other_readers_keep_what_follows_a_url(blank):
    """`contracts` reads column names out of its result and `verification` reads
    whether the query narrows. Both lost the rest of any line holding a URL --
    and in `contracts` the unbalanced quote left behind made the following
    string blank swallow to the next quote, wherever that was."""
    out = blank("AzureDiagnostics\n" + URL_LINE + "| project TimeGenerated, Uri\n")
    assert "OperationName" in out, out
    assert "project TimeGenerated" in out, out
