"""Turn real events into offline fixtures, so a detection can be graded forever.

WHY THIS EXISTS. Everything learned about Azure's log shapes this week came
from reading real rows: that `Authorization.evidence.role` is the CALLER's role
and not the granted one, that `ResourceId` is empty on all 99 role-assignment
rows while `_ResourceId` is populated, that the assignment GUID arrives dashed
on writes and undashed on 17 of 23 deletes, that `requestbody` is a JSON string
inside the already-parsed `Properties`. None of that is in Microsoft's
documentation. All of it currently survives as English sentences in a prompt
file, where nothing can test it and nothing notices when it goes stale.

A recorded row makes those facts executable. The rows are captured once, the
tenant is stripped out of them, and every future detection is graded against
them offline -- no workspace, no credentials, no retention window, in CI.

WHAT IS NOT REDACTED. Identifiers are: GUIDs, user principal names, IPv4 and
IPv6. NAMES are not -- a resource group called PYLON-TRIGGER-RG stays that, and
in a customer tenant it might be their company. Redacting names generically
would mangle the operation names, table names and role names that are the whole
content of a fixture, so the honest position is that this strips identifiers and
a human reviews names before a fixture is published.

WHAT IT DOES NOT SOLVE. You can only record what has happened. On the tenant
this was written against, six of Key Vault's 54 operations had any events at
all, because nobody in a lab reads a secret or rotates a key. Recording covers
the third of the corpus that is already gradable; the rest needs the action
performed once, and then recording covers it too.

LABELS, AND WHY THEY CAN BE AUTOMATIC. A fixture needs true positives and true
negatives. The obvious default is right for the failures that actually happen:

    tp   rows of the operation this detection targets. It must match these.
    tn   rows of a DIFFERENT operation on the same table. It must not.

That is not a substitute for human judgement about whether a particular grant
should alert. It is a direct test of the class of defect found over and over:
a filter comparing the wrong shape, a role GUID that names another role, a
detection that dropped its filter and matches everything. Every one of those
shows up as a false positive against another operation's rows, or a false
negative against its own.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Shapes that identify a tenant, and what each becomes. Order matters: the more
# specific pattern has to run first or the general one eats it.
#
# REDACTION PRESERVES SHAPE. A GUID stays a GUID of the same length and dashing,
# a UPN stays an at-sign with a domain, an IP stays four octets. This week's
# bugs were all about shape -- a path compared to a bare GUID, a dashed id
# matched against an undashed one -- so a fixture that normalises shape away
# would be a fixture that cannot reproduce them.
_GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                   r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_GUID_FLAT = re.compile(r"\b[0-9a-fA-F]{32}\b")
_UPN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){3,7}[0-9a-fA-F]{0,4}\b")

# Built-in role GUIDs are Azure's, identical in every tenant, and the whole
# point of several detections. Redacting them would destroy the fixture.
def _keep() -> frozenset[str]:
    try:
        from .roles import ROLES

        return frozenset(ROLES)
    except Exception:  # noqa: BLE001 - a catalogue gap must not stop a recording
        return frozenset()


def _dash(flat: str) -> str:
    """A 32-character hex string in the 8-4-4-4-12 form, lowercased."""
    f = flat.lower()
    return f"{f[:8]}-{f[8:12]}-{f[12:16]}-{f[16:20]}-{f[20:]}"


def _stable(value: str, kind: str, seen: dict[str, str]) -> str:
    """A placeholder for `value`, the same every time within one recording.

    Stability is not cosmetic. A detection that joins Start to Success on
    CorrelationId, or a delete back to the write that created it, only works if
    the same real id maps to the same fake one -- otherwise the fixture tests a
    join that can never succeed and every recorded detection reads as dead.
    """
    if value in seen:
        return seen[value]
    digest = hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()
    if kind == "guid":
        out = f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"
    elif kind == "guid_flat":
        out = digest[:32]
    elif kind == "upn":
        out = f"user{digest[:6]}@example.invalid"
    elif kind == "ipv4":
        # TEST-NET-3 (RFC 5737), reserved for documentation.
        out = "203.0.113." + str(int(digest[:2], 16) % 254 + 1)
    else:
        out = f"2001:db8::{digest[:4]}"
    seen[value] = out
    return out


def redact(value: Any, seen: dict[str, str]) -> Any:
    """`value` with tenant identifiers replaced, shape intact.

    Walks strings only. A recorded row's numbers, timestamps and operation names
    are not secrets and are the thing being tested.
    """
    if isinstance(value, dict):
        return {k: redact(v, seen) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, seen) for v in value]
    if not isinstance(value, str):
        return value

    keep = _keep()
    out = _GUID.sub(
        lambda m: m.group(0) if m.group(0).lower() in keep
        else _stable(m.group(0), "guid", seen), value)
    # Azure writes the same built-in role id both ways: dashed in the request
    # body's roleDefinitionId path, UNDASHED in Authorization.evidence. Checking
    # only the dashed form redacted the flat one, which destroys the fixture --
    # a Key Vault or role detection compares against exactly that constant.
    out = _GUID_FLAT.sub(
        lambda m: m.group(0) if _dash(m.group(0)) in keep
        else _stable(m.group(0), "guid_flat", seen), out)
    out = _UPN.sub(lambda m: _stable(m.group(0), "upn", seen), out)
    out = _IPV4.sub(lambda m: _stable(m.group(0), "ipv4", seen), out)
    out = _IPV6.sub(lambda m: _stable(m.group(0), "ipv6", seen), out)
    return out


def fixture(name: str, table: str, kql: str, operation: str,
            positives: list[dict], negatives: list[dict],
            measured: dict | None = None, anchored: bool = False) -> dict:
    """One golden-set fixture, ready for `golden_eval`.

    Redaction shares one mapping across BOTH row sets, so an actor appearing in
    a true positive and a true negative is the same actor in the fixture too.
    That is what lets a fixture catch a detection which matches on the actor
    rather than on the operation.
    """
    seen: dict[str, str] = {}
    events = []
    for label, rows in (("tp", positives), ("tn", negatives)):
        for row in rows:
            clean = {k: redact(v, seen) for k, v in row.items()
                     if v is not None and v != ""}
            clean["label"] = label
            events.append(clean)
    return {
        "name": name,
        "table": table,
        "operation": operation,
        # What a LIVE measurement already said about this detection, carried so
        # the offline grader does not start from zero. A verdict was computed,
        # written into report.json, read by this very function's caller, and
        # then dropped -- so `grade` met a detection an earlier stage had
        # measured as matching nothing and offered a benign explanation for it.
        # None means it was never measured, which is not the same as measured
        # clean.
        "measured": measured or None,
        # Whether the positives are rows the detection MATCHED, or a
        # representative sample of the operation. The difference decides what a
        # failure means: an anchored fixture that stops firing is a regression,
        # a sampled one that never fires may simply hold nothing the query wants.
        "anchored": anchored,
        "query": kql,
        # Said out loud in the file, because a fixture is read by someone
        # deciding whether to trust it.
        "note": (f"Recorded from a real workspace. `tp` rows are {operation}; "
                 "`tn` rows are other operations on the same table. GUIDs, UPNs "
                 "and IP addresses are replaced with stable placeholders of the "
                 "same shape -- the same real id maps to the same fake one, so "
                 "joins still resolve. NAMES ARE NOT REDACTED: resource groups, "
                 "resources and workspaces keep the names they had. Review "
                 "before committing a fixture recorded from a tenant that is "
                 "not yours to publish."),
        "events": events,
    }
