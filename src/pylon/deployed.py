"""Which table this tenant actually writes to, and whether we know.

A detection names one table. Get it wrong and the detection is syntactically
perfect, passes every validator, ships, and returns nothing for ever -- the
quietest failure this tool can produce, because a rule that never fires looks
exactly like a tenant where nothing happened.

The way to get it wrong is the legacy/resource-specific split. The same Key
Vault audit event lands in `AzureDiagnostics` or in `AZKVAuditLogs` depending on
one field on one diagnostic setting, and the catalogue that routes a detection
knows only what Azure OFFERS, never what this tenant CHOSE.

THE EVIDENCE IS DATA, NOT EXISTENCE
-----------------------------------
The first version of this asked the control-plane table list -- does the
workspace HAVE this table -- on the premise that a resource-specific table only
comes into being when a setting in that mode creates it.

That premise is false, and the first run against a real tenant said so in eight
seconds: 844 tables existed, 34 held data. `AKSAudit`, `AZMSRunTimeAuditLogs`
and `CDBDataPlaneRequests` all came back present in a tenant running no AKS, no
Service Bus and no Cosmos DB. Installing a Content Hub solution provisions its
table SCHEMAS, so "exists" means a solution was installed, not that anything
was ever written. (`SurfaceHubDns` was absent, which is the tell: the set is
solution-shaped, not all-of-Azure.)

Shipped as it was, `basis` would have answered "deployed" for nearly every table
it was asked about -- reporting "confirmed present in the scanned workspace" for
a table the tenant has never written a row to. False confidence, in the one
feature built to prevent exactly that.

So confirmation comes from `Analysis.tables` instead: the tables holding data in
the scan window. Data arrived, therefore that mode is in use. It is the same
shape of claim, anchored to something that cannot be true by accident.

    the table has data       that mode is in use. Proof.
    the table has no data    proves NOTHING. An idle resource and one logging
                             the other way are identical from here.
    no scan document         we never looked.

The cost of the correction is real and is the honest price: a resource that is
correctly configured but quiet in the window now reads as unconfirmed. That is
what we actually know about it.

Absence is never grounds for picking the other table. It is grounds for saying
the choice was not confirmed. Writing a detection for a service not deployed yet
is a legitimate thing to do -- it is most of what this tool is for -- and it
must keep working. It just must not come out looking like a measurement.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

# How a detection's table was chosen. The same three answers `ReadState` gives,
# and for the same reason: "could not look" must never render as "looked".
#   deployed   the workspace has DATA in this table, so the mode is confirmed
#   catalogue  we had the list, this table is not in it -- an assumption
#   unchecked  no list was available, so nothing was compared
TableBasis = Literal["deployed", "catalogue", "unchecked"]


def from_analysis(path: str | Path = "analysis.json") -> tuple[frozenset[str] | None, str]:
    """(tables holding data in this workspace, why) from a scan document.

    Reads `tables`, the table-activity leg, NOT `provisioned_tables`. The latter is
    the control-plane list of provisioned schemas and is not evidence of use --
    see the module docstring for the tenant that proved it.

    `None` means no evidence is available: absent file, unreadable, or a scan
    whose table-activity read did not run. All three are the same answer to the
    only question asked here, and none may be mistaken for "this workspace has
    no data".
    """
    src = Path(path)
    if not src.is_file():
        return None, f"no scan document at {src} — run `pylon analyze` to confirm tables"
    try:
        document = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as unreadable:
        return None, f"could not read {src}: {unreadable}"

    rows = document.get("tables")
    if rows is None:
        # The document is valid and says the read did not happen. `_legs_agree`
        # guarantees these two agree, so the detail is the honest reason.
        detail = ((document.get("reads") or {}).get("table_activity") or {}).get("detail")
        return None, detail or "the scan did not read table activity"

    names = {r["table_name"] for r in rows if r.get("table_name")}
    window = document.get("window_days", 30)
    return frozenset(names), (
        f"{len(names)} table(s) holding data in the scanned workspace "
        f"over {window}d")


def basis(table: str, deployed: frozenset[str] | None) -> TableBasis:
    """How much this table name is worth."""
    if deployed is None:
        return "unchecked"
    return "deployed" if table in deployed else "catalogue"


def prefer(chosen: str, candidates: list[str],
           deployed: frozenset[str] | None) -> str:
    """`chosen`, unless a sibling candidate is the one this tenant actually has.

    Conservative on purpose. With no evidence the routing choice stands
    untouched -- this does not get to overrule the catalogue on a guess. It only
    intervenes where there is proof: the pick is not in the workspace and
    something else on the candidate list is.

    When NOTHING on the list is deployed, the pick also stands. That is the
    write-ahead-of-deployment case, and the right response is to say the table
    was not confirmed, not to substitute a different unconfirmed one.
    """
    if not deployed or chosen in deployed:
        return chosen
    for candidate in candidates:
        if candidate in deployed:
            return candidate
    return chosen


def note(table: str, how: TableBasis, why: str = "") -> str:
    """One line for a human, saying how much to trust the table name.

    Rendered next to the detection rather than buried, because the person
    deciding whether to deploy it is the only one who can check an assumption.
    """
    if how == "deployed":
        return f"{table}: confirmed — the scanned workspace holds data in it"
    if how == "catalogue":
        return (f"{table}: NOT confirmed — no data in it in the scanned workspace. "
                f"Assumed from the catalogue, which knows what Azure offers, not "
                f"what this tenant configured. If the resource logs in Azure "
                f"diagnostics mode the data is in AzureDiagnostics instead, and "
                f"this detection will never fire.")
    return (f"{table}: unchecked — {why or 'no scan document was available'}. "
            f"Run `pylon analyze` to confirm the table exists before deploying.")
