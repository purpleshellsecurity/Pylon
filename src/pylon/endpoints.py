"""Endpoint telemetry: which machines report, and what they send.

`Analysis.endpoint_os` is a count per platform, which is all the model asks
for. It is not enough to act on: a fleet where every sensor is healthy and one
where half have stopped reporting produce the same count.

So the census is computed for the document and the detail is kept beside it --
per device, whether it is onboarded and whether its sensor is alive; per
stream, whether that class of telemetry is actually arriving. Both are read
from the workspace, because an endpoint's telemetry is the one part of this
scan with no configuration API to consult: there is no diagnostic setting to
inspect, only data present or absent.

`AzureResourceId` is the field that matters most. It ties a device back to an
ARM resource without matching on hostname, which is how this scan can say that
an endpoint IS a virtual machine in the inventory rather than guessing from a
name that happens to look similar.
"""

from __future__ import annotations

import json

from . import azcli

# Defender XDR streams five families of advanced-hunting tables, not one.
# Reading only the endpoint family and calling the section "XDR" reports a
# fifth of the product. A family with no data is NOT necessarily a fault --
# Defender for Office 365, for Identity and for Cloud Apps are separate
# licences, and an unlicensed product legitimately sends nothing. The scan
# cannot see licensing, so absence is reported as absence and never as a gap.
FAMILIES: dict[str, list[str]] = {
    "Endpoint": [
        "DeviceEvents", "DeviceProcessEvents", "DeviceNetworkEvents",
        "DeviceFileEvents", "DeviceRegistryEvents", "DeviceImageLoadEvents",
        "DeviceLogonEvents", "DeviceNetworkInfo", "DeviceFileCertificateInfo",
        "DeviceInfo",
    ],
    "Email": [
        "EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo",
        "EmailPostDeliveryEvents", "UrlClickEvents",
    ],
    "Identity": [
        "IdentityLogonEvents", "IdentityQueryEvents",
        "IdentityDirectoryEvents", "IdentityInfo",
    ],
    "Cloud apps": ["CloudAppEvents"],
    "Alerts": ["AlertInfo", "AlertEvidence"],
}

STREAMS = [t for tables in FAMILIES.values() for t in tables]
FAMILY_OF = {t: fam for fam, tables in FAMILIES.items() for t in tables}


def _query(workspace_guid: str, kql: str) -> tuple[list[dict], str | None]:
    p = azcli.query(workspace_guid, kql)
    if p.returncode != 0:
        return [], (p.stderr or "").strip()[:200]
    return json.loads(p.stdout or "[]"), None


def probe(workspace_guid: str, days: int = 30) -> tuple[dict | None, dict, dict]:
    """(census for the model, detail for the report, read state)."""
    devices, err = _query(workspace_guid, (
        "DeviceInfo | summarize arg_max(TimeGenerated, OSPlatform, OSVersionInfo, "
        "DeviceName, DeviceType, OnboardingStatus, SensorHealthState, "
        "ExposureLevel, AzureResourceId, MitigationStatus, ClientVersion) "
        "by DeviceId"))
    if err:
        return None, {}, {"ran": False,
                          "detail": f"DeviceInfo unreadable, so no census: {err}"}
    if not devices:
        # Distinct from an empty fleet: absent DeviceInfo means no endpoint
        # product is feeding this workspace at all.
        return None, {}, {"ran": False,
                          "detail": "DeviceInfo holds no rows, so no endpoint "
                                    "census is possible. That is not the same "
                                    "claim as a fleet with no devices in it."}

    # One machine can carry several DeviceIds after a re-registration, and
    # counting ids would overstate the fleet.
    by_name: dict[str, dict] = {}
    for d in devices:
        name = d.get("DeviceName") or d.get("DeviceId")
        keep = by_name.get(name)
        if keep is None or (d.get("TimeGenerated") or "") > (keep.get("TimeGenerated") or ""):
            by_name[name] = d

    census: dict[str, int] = {}
    for d in by_name.values():
        platform = d.get("OSPlatform") or "unknown"
        census[platform] = census.get(platform, 0) + 1

    # Volume over the last day, but the LATEST log over the whole window: a
    # table that went quiet yesterday shows zero recent rows and still says
    # when it last wrote, which a single window cannot express.
    # `isfuzzy` so a table this workspace does not define is skipped rather
    # than failing the whole query -- which is the normal case for an
    # unlicensed Defender product.
    rows, _ = _query(workspace_guid, (
        f"union isfuzzy=true withsource=T {', '.join(STREAMS)} "
        f"| where TimeGenerated > ago({days}d) "
        "| summarize rows_24h=countif(TimeGenerated > ago(1d)), "
        "rows_window=count(), devices=dcount(DeviceName), "
        "latest=max(TimeGenerated) by T"))
    streams = {r["T"]: {"rows_24h": int(r["rows_24h"]),
                        "rows_window": int(r["rows_window"]),
                        "devices": int(r["devices"]),
                        "family": FAMILY_OF.get(r["T"], "Other"),
                        "latest": r["latest"]} for r in rows}
    silent = [s for s in STREAMS if s not in streams]

    detail = {
        "devices": [{
            "name": d.get("DeviceName"),
            "os": d.get("OSPlatform"),
            "os_version": d.get("OSVersionInfo"),
            "type": d.get("DeviceType"),
            "onboarded": d.get("OnboardingStatus") == "Onboarded",
            "onboarding_status": d.get("OnboardingStatus"),
            "sensor": d.get("SensorHealthState"),
            "exposure": d.get("ExposureLevel"),
            "client_version": d.get("ClientVersion"),
            # The join back to the inventory, without matching on a hostname.
            "azure_resource_id": d.get("AzureResourceId") or None,
            "mitigation": d.get("MitigationStatus"),
        } for d in sorted(by_name.values(), key=lambda x: x.get("DeviceName") or "")],
        "streams": streams,
        "silent_streams": silent,
        # Which XDR families are arriving at all. A family with nothing is
        # most often an unlicensed product, not a broken pipeline.
        "families": {fam: {"present": sorted(t for t in tables if t in streams),
                           "absent": sorted(t for t in tables if t not in streams)}
                     for fam, tables in FAMILIES.items()},
    }

    quiet = sorted(t for t, v in streams.items() if not v["rows_24h"])
    healthy = sum(1 for d in detail["devices"] if d["sensor"] == "Active")
    read = {"ran": True,
            "detail": (f"{len(by_name)} device(s) reporting, {healthy} with an "
                       f"active sensor; {len(streams)} of {len(STREAMS)} telemetry "
                       f"stream(s) arriving in {days}d"
                       + (f"; silent: {', '.join(silent)}" if silent else "")
                       + (f"; no rows in 24h: {', '.join(quiet)}" if quiet else ""))}
    return census, detail, read


def matched_to_inventory(detail: dict, resources: list) -> dict:
    """Which inventoried machines have an endpoint sensor, and which do not.

    Matched on `AzureResourceId` rather than hostname: a device named like a VM
    is not evidence it is that VM.
    """
    covered = {(d["azure_resource_id"] or "").lower()
               for d in detail.get("devices", []) if d["azure_resource_id"]}
    machines = [r for r in resources
                if r.resource_type in ("microsoft.compute/virtualmachines",
                                       "microsoft.hybridcompute/machines")]
    return {
        "with_sensor": [r.resource_id for r in machines
                        if r.resource_id.lower() in covered],
        "without_sensor": [r.resource_id for r in machines
                           if r.resource_id.lower() not in covered],
        # A device that reports no AzureResourceId is real but not an inventoried
        # Azure resource -- a laptop, an on-prem server, something else.
        "not_in_inventory": [d["name"] for d in detail.get("devices", [])
                             if not d["azure_resource_id"]],
    }
