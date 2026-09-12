"""Every operation the technique catalog names must be one Entra actually logs.

`entra_audit_activities` is the vocabulary — 1,171 activities across 48 services,
harvested from Microsoft's reference — and `table-techniques.yaml` is what grounds
generation. They were two copies of one truth with nothing comparing them, which
is this codebase's recurring scar, and three of eighteen AuditLogs operations had
drifted into names that do not exist:

    T1528      "Add app role assignment grant to user"
    T1556.006  "Update authentication methods policy"
    T1484.002  "Set domain authentication type"

Every one is a near-miss of a real activity, which is why nothing caught them: the
string looks entirely plausible, the KQL is valid, the column is real, and the
detection simply never matches. Found by firing the T1528 attack in a live tenant
and reading what Entra actually wrote — "Add app role assignment to service
principal", which the vocabulary already knew and the catalog did not.
"""

import pathlib

import pytest
import yaml

from pylon import entra_audit_activities as vocabulary

_CATALOG = (
    pathlib.Path(__file__).resolve().parents[1]
    / "src" / "pylon" / "catalog" / "table-techniques.yaml"
)


def _auditlogs_claims():
    data = yaml.safe_load(_CATALOG.read_text(encoding="utf-8"))
    for name, body in data["tables"].items():
        if name != "AuditLogs":
            continue
        for claim in body.get("techniques") or []:
            for op in claim.get("operations") or []:
                yield claim.get("id"), op


def test_the_vocabulary_is_actually_loaded():
    """Guards the guard. An empty vocabulary would make every assertion below
    vacuously pass — the same shape as `grep -L` over zero files."""
    assert len(vocabulary.categories()) > 20
    assert sum(len(vocabulary.activities_for(c)) for c in vocabulary.categories()) > 500


@pytest.mark.parametrize(
    "technique,operation", list(_auditlogs_claims()), ids=lambda v: str(v)[:40]
)
def test_every_catalog_operation_is_a_real_entra_activity(technique, operation):
    assert vocabulary.is_known(operation), (
        f"{technique} names {operation!r}, which Entra never logs. A detection "
        f"grounded on it filters on a value that never appears: valid KQL, real "
        f"column, and no possibility of matching."
    )


def test_the_operation_measured_in_a_live_tenant_is_present():
    """Not a hypothetical. The T1528 emulation script granted an app role
    assignment and Entra logged exactly this; the catalog named something else, so
    the detection could not fire."""
    ops = {op for _, op in _auditlogs_claims()}
    assert "Add app role assignment to service principal" in ops


def test_no_activity_name_carries_markdown_escaping():
    """The vocabulary is parsed out of a documentation table, so it can inherit
    the DOCUMENT's punctuation rather than the log's.

    Fifty names did. Learn escapes underscores when it renders a table cell, so
    `Group_AddMember` reached the catalog as `Group\\_AddMember` -- a string
    Entra never writes, in fifty operation names, silently. Same failure as the
    Cosmos DB names and LeaseBlob: valid KQL, real column, and no possibility of
    matching.

    A backslash in an Entra activity name is always this bug. None of the 1,171
    real names contains one.
    """
    offenders = [
        (category, activity)
        for category in vocabulary.categories()
        for activity in vocabulary.activities_for(category)
        if "\\" in activity
    ]
    assert offenders == [], (
        f"activity names carrying a backslash: {offenders}. The harvester must "
        f"unescape the source, or read the markdown Microsoft authors rather "
        f"than the page Learn renders."
    )
