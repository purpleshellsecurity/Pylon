"""ATT&CK itself, so a technique id is checked rather than repeated.

Sentinel's rule templates state the techniques they detect, and that claim is
the basis for every technique-level verdict here. It is Microsoft's claim, not
MITRE's, and it goes wrong in ways that are invisible without checking:

  * ids from the WRONG MATRIX. A template in this tenant claims T0853, which
    is ICS ATT&CK, not Enterprise. Reported unchecked it becomes an Enterprise
    gap that no Enterprise reader can act on.
  * REVOKED ids, replaced by MITRE and still referenced by content.
  * DEPRECATED ids, retired but not replaced.
  * ids that resolve to nothing at all.

`mitre_index.json` is distilled from MITRE's published STIX bundles -- 60MB
across three matrices, reduced to the fields needed here -- so a scan grounds
against it without a download. Refresh it with `refresh.py` when ATT&CK
publishes a version.
"""

from __future__ import annotations

import json
import os

# Beside the other catalogues, not beside this module. It moved there when the
# package gained a `catalog/` directory, and the move is what exposed the
# failure below.
_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "catalog", "mitre_index.json")

try:
    with open(_PATH, encoding="utf-8") as _f:
        _DATA = json.load(_f)
except (OSError, ValueError) as _exc:
    # An empty index is not a tenant with no techniques, and the difference has
    # to reach the page. When this module moved into the package the index was
    # left behind at the repo root; the load failed, `platforms.universe`
    # returned nothing, and the report rendered "0 live Enterprise techniques
    # apply to them" as a measurement. Nothing said the catalogue was missing.
    #
    # It still does not raise -- report renderers import this and an install
    # missing one data file should not be an unhandled traceback -- but the
    # reason is kept and every read state that quotes `version_note` now says
    # so out loud.
    _DATA = {"attack_versions": {}, "techniques": {}}
    LOAD_ERROR: str | None = f"{type(_exc).__name__}: {_exc}"
else:
    LOAD_ERROR = None

TECHNIQUES: dict[str, dict] = _DATA.get("techniques", {})
ATTACK_VERSIONS: dict[str, str] = _DATA.get("attack_versions", {})


def ground(technique_id: str) -> dict:
    """What ATT&CK says about this id.

    `usable` is false wherever a consumer should not present the id as a live
    Enterprise technique -- unknown, revoked, deprecated, or another matrix --
    and `note` says which, because the four need different handling.
    """
    rec = TECHNIQUES.get(technique_id)
    if rec is None:
        return {"name": "", "matrix": None, "usable": False,
                "note": f"{technique_id} is not an ATT&CK technique id"}
    notes = []
    if rec["revoked"]:
        # The replacement is what makes a revocation actionable, so it is
        # stated rather than left for the reader to look up.
        replacement = rec.get("revoked_by")
        notes.append(f"revoked by MITRE, replaced by {replacement}" if replacement
                     else "revoked by MITRE with no stated replacement")
    if rec["deprecated"]:
        notes.append("deprecated by MITRE")
    if rec["matrix"] != "enterprise":
        notes.append(f"belongs to {rec['matrix']} ATT&CK, not enterprise")
    return {"name": rec["name"], "matrix": rec["matrix"],
            "tactics": rec["tactics"], "sub_technique": rec["sub_technique"],
            "revoked_by": rec.get("revoked_by"),
            "usable": not notes, "note": "; ".join(notes)}


# A revocation chain is normally one hop, but MITRE has revoked a replacement
# in turn. Bounded so a cycle in the index cannot spin here.
_MAX_HOPS = 5


def current(technique_id: str) -> tuple[str, str]:
    """(the id to use today, why it changed) -- following MITRE's revocations.

    `ground()` reports that an id is unusable; this is what to do about it. The
    two answers are different and only one of them is actionable: told that
    T1562.008 is revoked, a caller can do nothing but drop the vector, which
    deletes every anti-forensics detection it had. Told that it is now
    T1685.002, the caller relabels and keeps the detection.

    Only a REVOCATION is followed. Deprecation and a wrong-matrix id both mean
    "MITRE no longer offers this here" with nothing to move to, so those come
    back unchanged and the caller decides. An id that is already current, or
    one ATT&CK has never heard of, likewise comes back as it arrived -- this
    resolves, it does not validate. `ground()` is still the check.
    """
    seen = {technique_id}
    at = technique_id
    for _hop in range(_MAX_HOPS):
        rec = TECHNIQUES.get(at)
        if rec is None or not rec["revoked"]:
            break
        nxt = rec.get("revoked_by")
        # A revocation with no stated replacement is a dead end, and so is a
        # cycle. Both stop here rather than guessing.
        if not nxt or nxt in seen:
            break
        seen.add(nxt)
        at = nxt
    if at == technique_id:
        return technique_id, ""
    return at, f"{technique_id} was revoked by MITRE and is now {at}"


def version_note() -> str:
    if LOAD_ERROR:
        return (f"ATT&CK INDEX FAILED TO LOAD from {_PATH} ({LOAD_ERROR}); "
                "every technique count below is zero because of that, not "
                "because the tenant is clean")
    if not ATTACK_VERSIONS:
        return "no ATT&CK index available; technique ids are unchecked"
    return "grounded against ATT&CK " + ", ".join(
        f"{k} v{v}" for k, v in sorted(ATTACK_VERSIONS.items()))
