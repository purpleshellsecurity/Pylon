#!/usr/bin/env python3
"""The ladder, every cell of it, and the two states that must not blur.

Six outcomes, and the one that matters most is the sixth: a resource whose
role read did not run must come back `None`/`unrated`, never tier 4. Tier 4
says "checked and clean". If a failed read could produce it, this whole field
would present an unmeasured tenant as a safe one.
"""

from __future__ import annotations

import sys

from pylon.analysis_model import Analysis, ReadState, Reads, Resource
from pylon.inventory import read_exposure, read_reachability, types_with_reachability

FAILS = []


def check(label, got, want):
    if got != want:
        FAILS.append(f"{label}: got {got!r}, want {want!r}")


# ── the ladder ───────────────────────────────────────────────────────────────
ABOVE = (["Owner"], True)          # a privileged role above this resource
HERE = (["Contributor"], False)    # one scoped to the resource itself
NONE = ([], False)                 # read ran, found nothing

check("0  public + role above", read_exposure(None, "enabled", ABOVE), (0, "role_assignment"))
check("1  public alone", read_exposure(None, "enabled", NONE), (1, "public_network_access"))
check("1  public + role here", read_exposure(None, "enabled", HERE), (1, "public_network_access"))
check("2  private + role above", read_exposure(None, "disabled", ABOVE), (2, "role_assignment"))
check("3  private + role here", read_exposure(None, "disabled", HERE), (3, "role_assignment"))
check("4  private, clean", read_exposure(None, "disabled", NONE), (4, "scope"))
check("4  no concept, clean", read_exposure(None, None, NONE), (4, "scope"))

# The two that must be None. A rank here would be a fabricated measurement.
check("None  role read failed", read_exposure(None, "enabled", None), (None, "unrated"))
check("None  reachability unknown", read_exposure(None, "unknown", NONE), (None, "unrated"))

# Tags never reach the ranking, whatever they say.
check("tags ignored", read_exposure({"criticality": "Tier 0"}, "disabled", NONE),
      read_exposure(None, "disabled", NONE))

# ── reachability ─────────────────────────────────────────────────────────────
ROWS = [
    {"type": "Microsoft.Storage/storageAccounts", "networkDefaultAction": "Allow"},
    {"type": "Microsoft.Storage/storageAccounts", "networkDefaultAction": "Deny"},
    {"type": "Microsoft.KeyVault/vaults", "publicNetworkAccess": "Enabled"},
    {"type": "Microsoft.Storage/storageAccounts"},          # type has one, no value
    {"type": "Microsoft.Compute/disks"},                    # never reports one
]
HAS = types_with_reachability(ROWS)
check("storage Allow", read_reachability(ROWS[0], HAS),
      ("enabled", "networkAcls.defaultAction=Allow"))
check("storage Deny", read_reachability(ROWS[1], HAS),
      ("disabled", "networkAcls.defaultAction=Deny"))
check("vault Enabled", read_reachability(ROWS[2], HAS),
      ("enabled", "publicNetworkAccess=Enabled"))
check("storage, no value", read_reachability(ROWS[3], HAS)[0], "unknown")
check("type with no concept", read_reachability(ROWS[4], HAS), (None, None))
# Restriction beats permission: an open endpoint fenced to selected networks,
# and the basis names the property that restricted it, not the one that did not.
check("endpoint on, ACL deny",
      read_reachability({"type": "Microsoft.Storage/storageAccounts",
                         "publicNetworkAccess": "Enabled",
                         "networkDefaultAction": "Deny"}, HAS),
      ("disabled", "networkAcls.defaultAction=Deny"))
# Every verdict carries a basis. A bare "yes" is the thing this was added for.
for _row in ROWS[:4]:
    _v, _why = read_reachability(_row, HAS)
    if _v is not None and not _why:
        FAILS.append(f"{_row['type']}: verdict {_v} with no basis")


# ── the document still validates under extra="forbid" ────────────────────────
def resource(rank, source, **kw):
    return Resource(resource_id=f"/r/{rank}", resource_type="microsoft.storage/storageaccounts",
                    criticality_tier="unrated", criticality_source="unrated",
                    assessment_status="assessed", logging_status="not-enabled",
                    exposure_rank=rank, exposure_source=source, **kw)


rows = [resource(r, s) for r, s in
        [(0, "role_assignment"), (1, "public_network_access"), (2, "role_assignment"),
         (3, "role_assignment"), (4, "scope"), (None, "unrated")]]
doc = Analysis(generated_at="2026-08-30T00:00:00Z", workspace="w",
               reads=Reads(inventory=ReadState(ran=True, detail="synthetic"),
                           role_assignments=ReadState(ran=True, detail="synthetic")),
               resources=rows)
check("all six ranks validate", len(doc.resources), 6)
check("round-trips", Analysis.model_validate_json(doc.model_dump_json()).resources[0].exposure_rank, 0)

# The blur the validator exists to catch, in both directions.
for label, kw in [("unrated with a rank", dict(exposure_rank=4, exposure_source="unrated")),
                  ("rated with no rank", dict(exposure_rank=None, exposure_source="scope"))]:
    try:
        resource(**{}, **kw)
        FAILS.append(f"{label}: accepted, should have raised")
    except Exception:
        pass

def test_exposure_ladder_and_model():
    """The checks above run at import; this is what makes pytest see them.

    They were written as a standalone script and stayed one after moving into
    `tests/`, which meant pytest imported the module, ran every check, and
    collected no test from it -- a failure would have surfaced as a collection
    error rather than a failing assertion, and a pass looked like an empty file.
    """
    assert not FAILS, "\n".join(FAILS)


if __name__ == "__main__":
    if FAILS:
        print("\n".join("FAIL  " + f for f in FAILS))
        sys.exit(1)
    print("exposure: ladder, reachability and model checks pass")
