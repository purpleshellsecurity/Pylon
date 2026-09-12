"""Where two sources describe the same thing, a disagreement must be visible.

Operation names live in two places. `service_files/*.json` is harvested from
Microsoft and covers 81 tables. `data-plane-operations.yaml` is hand-written and
covers the five tables a target can fire on. Nothing compared them, so a disagreement was not a failure -- it was
invisible, and it stayed invisible for as long as nobody thought to look.

It was found by looking. Cosmos DB shares ONE operation name across the two
sources: the harvest says Read, Query, Upsert; the hand-written file says
ReadDocument, QueryDocuments, WriteDocument. Five of six hand-written names
appear nowhere in Microsoft's own list, and every Cosmos detection this tool has
produced filters on one of them.

This file does not decide who is right. It refuses to let the question go
unasked. A name in one source and not the other is either drift, a genuinely
different vocabulary, or a harvest that needs fixing -- and all three of those
are things a person should see rather than a silence.
"""

import json
import pathlib

import pytest
import yaml

_CATALOG = pathlib.Path(__file__).resolve().parents[1] / "src" / "pylon" / "catalog"

# Tables where the two sources are known to disagree, with the reason. Adding a
# line here is a decision someone made and can be argued with; the empty case is
# the goal, not the starting point.
# Resolved 2026-09: StorageBlobLogs carried a hand-written name, LeaseBlob, that
# the harvest had never heard of. Microsoft's own list settles it -- the Blob
# service logs AcquireBlobLease, RenewBlobLease, ReleaseBlobLease, BreakBlobLease,
# ChangeBlobLease and GetBlobLeaseInfo, and no LeaseBlob. The hand-written name
# was wrong, the same shape as the Cosmos DB names above, and it is gone.
KNOWN_DISAGREEMENTS: dict[str, str] = {}

# A hand-written list being SMALLER than the harvest is not a disagreement. It is
# a curated subset, which is the point of having a judged layer at all. Only a
# name the harvest has never heard of is a problem, because that is the one that
# ships a filter matching nothing.


def _harvested() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in (_CATALOG / "service_files").glob("*.json"):
        for table, meta in (json.loads(f.read_text(encoding="utf-8")).get("tables") or {}).items():
            ops = meta.get("operations")
            if not ops:
                continue
            flat = ([o for v in ops.values() for o in v]
                    if isinstance(ops, dict) else list(ops))
            out.setdefault(table, set()).update(flat)
    return out


def _hand_written() -> dict[str, set[str]]:
    doc = yaml.safe_load((_CATALOG / "data-plane-operations.yaml").read_text(encoding="utf-8"))
    return {t: set(b["operations"]) for t, b in doc["tables"].items()}


def test_both_sources_actually_load():
    """Guards every assertion below. Two empty dicts agree perfectly."""
    assert len(_harvested()) > 50
    assert len(_hand_written()) >= 5


SHARED = sorted(set(_harvested()) & set(_hand_written()))


def test_the_two_sources_overlap_at_all():
    assert SHARED, "no table is described by both sources, so nothing is compared"


@pytest.mark.parametrize("table", SHARED)
def test_a_disagreement_is_recorded_rather_than_silent(table):
    """A hand-written name absent from Microsoft's own list is the exact shape of
    a detection that can never fire: valid KQL, real column, real table, and a
    filter on a string the log does not write."""
    unknown = sorted(_hand_written()[table] - _harvested()[table])
    if not unknown:
        return
    assert table in KNOWN_DISAGREEMENTS, (
        f"{table}: {len(unknown)} hand-written operations appear in no harvested "
        f"source: {unknown[:6]}. Either the harvest is incomplete or these names "
        f"are wrong. Record the disagreement in KNOWN_DISAGREEMENTS with a reason, "
        f"or fix one of the two sources."
    )


def test_every_recorded_disagreement_still_exists():
    """The list must shrink as things are settled. An entry for a table that now
    agrees is a stale excuse, and stale excuses are how a list like this stops
    meaning anything."""
    harvested, hand = _harvested(), _hand_written()
    stale = [t for t in KNOWN_DISAGREEMENTS
             if t in hand and t in harvested and not (hand[t] - harvested[t])]
    assert stale == [], f"these now agree and the entry should be deleted: {stale}"


def test_every_hand_written_table_has_a_harvest_to_check_it_against():
    """It used to be four, and all four were withdrawn together: AKSAudit,
    AKSAuditAdmin, AZMSRunTimeAuditLogs and SQLSecurityAuditEvents were
    hand-written vocabularies with nothing to compare them to, for tables no
    target can fire on. Every remaining table has two sources, so every name in
    the judged layer is one a script can check against Microsoft's own list."""
    only_hand = sorted(set(_hand_written()) - set(_harvested()))
    assert only_hand == [], (
        f"these have no harvest to check against: {only_hand}. Either the harvest "
        f"is missing the table, or the vocabulary is unverifiable and should not "
        f"back a target."
    )
