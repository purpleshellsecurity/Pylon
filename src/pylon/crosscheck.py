"""What is ARRIVING, read back against what the configuration claims.

This is deliberately NOT the source of findings. A resource that is dark
writes no rows, so its absence from a workspace is not evidence about the
resource -- that is why every verdict in this scan is read from
configuration, and why this module cannot replace that.

What it can do is catch the opposite error. Configuration is read through
specific APIs, and data can arrive by paths those APIs do not expose. This
tenant produced two: `az monitor diagnostic-settings subscription list`
returned one of five settings, and Defender XDR streams device tables through
a connection the dataConnectors API never lists. Both looked like clean
`not-enabled` verdicts. A table holding fresh data under a scope this scan
called dark is not proof the scan is right -- it is proof the scan is blind
somewhere, and it should say so rather than report the gap.

The blind-spot half of that has to be MEASURED, not assumed. It once was
assumed: a table in `UNREPORTED_SOURCES` holding data was reported as a source
with no configuration behind it, without ever asking whether a connector
claimed it. On the tenant this was written against that was wrong three ways
over -- an `Office365` connector was in the ARM list, `MicrosoftCloudAppSecurity`
beside it, and `MicrosoftThreatProtection` was reporting 694 health events
through SentinelHealth, the very leg built to see what ARM cannot. The page
declared a blind spot the scan did not have.

So a source counts as unreported only when NOTHING in either connector leg
claims it. `connector_kinds` takes that union, and an empty union means the
legs did not run -- not that every source is unreported.
"""

from __future__ import annotations

import json

from . import apiversions
from . import azcli

# A verdict of `not-enabled` on any of these scopes should be contradicted if
# the matching table is live. Keyed by the table a working path would fill.
CONTRADICTS: dict[str, str] = {
    "AzureActivity": "subscription",
    "SigninLogs": "tenant",
    "AuditLogs": "tenant",
    "AADNonInteractiveUserSignInLogs": "tenant",
    "AADServicePrincipalSignInLogs": "tenant",
}

# Tables whose presence means a source is connected. Whether the configuration
# reports it is decided per run against the connector legs, never here.
UNREPORTED_SOURCES: dict[str, str] = {
    "DeviceEvents": "Defender XDR / MDE",
    "DeviceProcessEvents": "Defender XDR / MDE",
    "DeviceNetworkEvents": "Defender XDR / MDE",
    "DeviceFileEvents": "Defender XDR / MDE",
    "OfficeActivity": "Office 365",
    "SecurityAlert": "a security product feeding alerts",
}

# Connector kinds that account for each table above. Deliberately generous:
# every kind here SUPPRESSES a blind-spot claim, so a name too many costs a
# disclosure the tenant did not need, while a name too few puts a false one on
# the page. `SecurityAlert` is fed by any alert-producing product, so it lists
# all of them rather than pretending the feed can be pinned to one.
CLAIMED_BY: dict[str, tuple[str, ...]] = {
    "DeviceEvents": ("MicrosoftThreatProtection",
                     "MicrosoftDefenderAdvancedThreatProtection"),
    "DeviceProcessEvents": ("MicrosoftThreatProtection",
                            "MicrosoftDefenderAdvancedThreatProtection"),
    "DeviceNetworkEvents": ("MicrosoftThreatProtection",
                            "MicrosoftDefenderAdvancedThreatProtection"),
    "DeviceFileEvents": ("MicrosoftThreatProtection",
                         "MicrosoftDefenderAdvancedThreatProtection"),
    "OfficeActivity": ("Office365",),
    "SecurityAlert": ("MicrosoftCloudAppSecurity", "MicrosoftThreatProtection",
                      "MicrosoftDefenderAdvancedThreatProtection",
                      "AzureAdvancedThreatProtection", "AzureSecurityCenter",
                      "OfficeATP", "OfficeIRM", "Dynamics365",
                      "IoT", "MicrosoftDefenderForIoT"),
}


def connector_kinds(workspace_arm_id: str | None, health: dict | None) -> set[str]:
    """Every connector kind either leg can see, as a union.

    Neither leg is complete. The dataConnectors API returns only connectors
    created as ARM resources; SentinelHealth returns only the ones Microsoft
    reports health for, and only while health monitoring is switched on. A
    kind in either one is configuration this scan can point at.
    """
    kinds: set[str] = set()
    if workspace_arm_id:
        p = azcli.run(
            ["rest", "--method", "get", "--url",
             f"https://management.azure.com{workspace_arm_id}/providers"
             f"/Microsoft.SecurityInsights/dataConnectors"
             f"?api-version={apiversions.SENTINEL}",
             "-o", "json"],
            timeout=azcli.CONTROL_TIMEOUT,
        )
        if p.returncode == 0:
            try:
                payload = json.loads(p.stdout or "{}")
            except ValueError:
                payload = {}
            kinds |= {c.get("kind") for c in payload.get("value", []) if c.get("kind")}
    # Keyed by connector INSTANCE ("Office365-Exchange"), with the kind inside.
    for slot in ((health or {}).get("connectors") or {}).values():
        if slot.get("kind"):
            kinds.add(slot["kind"])
    return kinds


def live_tables(workspace_guid: str, days: int = 30) -> tuple[dict[str, int], str | None]:
    """{table: row count} for everything with data in the window."""
    query = (f"union withsource=T * | where TimeGenerated > ago({days}d) "
             "| summarize n=count() by T")
    p = azcli.query(workspace_guid, query)
    if p.returncode != 0:
        return {}, (p.stderr or "").strip()[:200]
    return {r["T"]: int(r["n"]) for r in json.loads(p.stdout)}, None


def check(verdicts: list[dict], workspace_guid: str, days: int = 30,
          kinds: set[str] | None = None) -> dict:
    """Contradictions and blind spots, as a read state -- never as findings.

    `kinds` is the union both connector legs saw, from `connector_kinds`. It is
    None when neither leg ran, which is NOT the same as an empty set: no
    knowledge of connectors cannot be read as no connectors, so the blind-spot
    list is withheld rather than filled with every table that happens to hold
    data.
    """
    tables, err = live_tables(workspace_guid, days)
    if err:
        return {"ran": False, "detail": f"could not query the workspace: {err}",
                "contradictions": [], "unreported": []}

    dark_scopes = {v["scope"] for v in verdicts
                   if v.get("logging_status") == "not-enabled"}

    contradictions = [
        {"table": t, "scope": scope, "rows": tables[t]}
        for t, scope in CONTRADICTS.items()
        if t in tables and scope in dark_scopes
    ]
    # A source is only unreported when nothing in either leg claims it. With
    # `kinds` unknown, no such statement can be made at all.
    if kinds is None:
        unreported: list[str] = []
    else:
        unreported = sorted({
            source for t, source in UNREPORTED_SOURCES.items()
            if t in tables and not (set(CLAIMED_BY.get(t, ())) & kinds)
        })

    bits = [f"{len(tables)} table(s) with data in {days}d"]
    if contradictions:
        bits.append("CONTRADICTED: " + ", ".join(
            f"{c['scope']} read as not-enabled but {c['table']} has {c['rows']} rows"
            for c in contradictions))
    if unreported:
        bits.append("arriving via paths the configuration APIs do not report: "
                    + ", ".join(unreported))
    return {"ran": True, "detail": "; ".join(bits),
            "contradictions": contradictions, "unreported": unreported,
            "tables": tables}
