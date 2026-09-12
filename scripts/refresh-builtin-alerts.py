#!/usr/bin/env python3
"""Vendor Microsoft's own built-in detections, so pylon stops writing duplicates.

The problem this exists for: `--gap-scan` decides a technique is uncovered by
reading the workspace's ENABLED ANALYTICS RULES. Microsoft's own products ship
detections too, and pylon cannot see them — so on a tenant paying for Defender
for Key Vault it will happily generate a rule for secret-dumping that duplicates
`KV_ListGetAnomaly`, and report the gap as real.

Two published catalogs, and they do NOT describe coverage at the same
granularity. That difference is carried through rather than flattened:

  Defender for Cloud   16 per-resource pages, each alert carrying MITRE
                       TACTICS ("Credential Access") and no technique id.
  Defender for Identity  one page, each alert carrying MITRE TECHNIQUE ids.

So a Defender for Cloud match is resource+tactic level and can only ever say
"this may overlap — here are the alerts, read them". Claiming a technique-level
match from a tactic would be inventing precision the source does not have, and
the whole point of this file is to stop overclaiming coverage.

Network, no credentials. Whether a catalogued alert actually EXISTS in a tenant
is a separate question answered by reading the plan tiers; a catalog entry means
Microsoft ships it, never that the customer has it switched on.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.request import ProxyHandler, build_opener, getproxies

DFC = "https://learn.microsoft.com/en-us/azure/defender-for-cloud/{slug}?accept=text/markdown"
MDI = "https://learn.microsoft.com/en-us/defender-for-identity/alerts-xdr?accept=text/markdown"

# The per-resource pages, and the Microsoft.Security pricing plan each belongs
# to. The plan name is what `Microsoft.Security/pricings` returns, and it is the
# join between "Microsoft ships this" and "the customer pays for it".
DFC_PAGES = {
    "alerts-windows-machines": "VirtualMachines",
    "alerts-linux-machines": "VirtualMachines",
    "alerts-dns": "Dns",
    "alerts-azure-vm-extensions": "VirtualMachines",
    "alerts-azure-app-service": "AppServices",
    "alerts-containers": "Containers",
    "alerts-sql-database-and-azure-synapse-analytics": "SqlServers",
    "alerts-open-source-relational-databases": "OpenSourceRelationalDatabases",
    "alerts-resource-manager": "Arm",
    "alerts-azure-storage": "StorageAccounts",
    "alerts-azure-cosmos-db": "CosmosDbs",
    "alerts-azure-network-layer": "VirtualMachines",
    "alerts-azure-key-vault": "KeyVaults",
    "alerts-azure-ddos-protection": "VirtualMachines",
    "alerts-defender-for-apis": "Api",
    "alerts-ai-workloads": "AI",
}

CATALOG = Path("src/pylon/catalog/builtin-alerts.json")
# A harvest that silently produced almost nothing would replace real coverage
# knowledge with none, and pylon would go back to calling every technique a gap.
MINIMUM_ALERTS = 200

# Both spellings appear: most pages bold the name, alerts-ai-workloads does not.
_HEADING = re.compile(r"^###\s+(?:\*\*)?(.+?)(?:\*\*)?\s*$")
_ALERT_ID = re.compile(r"^\((.+?)\)\s*$")
_TACTICS = re.compile(r"^\*\*\[?MITRE tactics\]?[^:]*\*\*:\s*(.+?)\s*$")
_SEVERITY = re.compile(r"^\*\*Severity\*\*:\s*(.+?)\s*$")
_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?")


def fetch(url: str, opener) -> str:
    with opener.open(url, timeout=60) as response:
        return response.read().decode("utf-8", "replace")


def parse_dfc(markdown: str) -> list[dict]:
    """Alerts from one Defender for Cloud resource page.

    Each is a `### **Name**` followed by an `(AlertId)` line, a description, and
    a MITRE TACTICS line. No technique ids appear on these pages at all.
    """
    alerts: list[dict] = []
    current: dict | None = None
    for raw in markdown.splitlines():
        line = raw.strip()
        heading = _HEADING.match(line)
        if heading:
            if current:
                alerts.append(current)
            current = {"name": heading.group(1).replace("\\", ""), "tactics": [],
                       "alert_id": "", "severity": ""}
            continue
        if current is None:
            continue
        ident = _ALERT_ID.match(line)
        if ident and not current["alert_id"] and " " not in ident.group(1):
            current["alert_id"] = ident.group(1).replace("\\", "")
            continue
        tactics = _TACTICS.match(line)
        if tactics:
            current["tactics"] = [
                t.strip() for t in re.split(r",|/", tactics.group(1)) if t.strip()
            ]
            continue
        severity = _SEVERITY.match(line)
        if severity:
            current["severity"] = severity.group(1)
    if current:
        alerts.append(current)
    return [a for a in alerts if a["name"] and a["name"] != "Description"]


def parse_mdi(markdown: str) -> list[dict]:
    """Alerts from the Defender for Identity page — table rows WITH technique ids."""
    alerts = []
    for row in re.finditer(
        r"^\|\s*(.+?)<br>\*\*Description\*\*:(.*?)\|\s*(\w+)\s*\|(.*?)\|\s*([\w\\_]+)\s*\|",
        markdown,
        re.MULTILINE,
    ):
        name, _desc, severity, techs, internal = row.groups()
        ids = sorted(set(_TECHNIQUE.findall(techs)))
        if not name.strip():
            continue
        alerts.append({
            "name": name.strip().replace("\\", ""),
            "alert_id": internal.replace("\\", ""),
            "severity": severity,
            "techniques": ids,
            "tactics": [],
        })
    return alerts


def main() -> int:
    opener = build_opener(ProxyHandler(getproxies()))
    opener.addheaders = [("User-Agent", "pylon-refresh-builtin-alerts")]

    catalog: dict[str, dict] = {}
    total = 0

    for slug, plan in DFC_PAGES.items():
        try:
            markdown = fetch(DFC.format(slug=slug), opener)
        except Exception as exc:  # noqa: BLE001 - one bad page must not stop the run
            print(f"  ! {slug}: {exc}", file=sys.stderr)
            continue
        alerts = parse_dfc(markdown)
        entry = catalog.setdefault(
            plan, {"product": "Microsoft Defender for Cloud", "plan": plan,
                   "granularity": "tactic", "alerts": [], "unenumerated_pages": []}
        )
        if not alerts:
            # Some pages describe their coverage in prose and never list the
            # individual alerts — alerts-containers and alerts-azure-app-service
            # do exactly this, and the App Service page says outright that some
            # alerts "might be undocumented". Recording that is the whole point:
            # an empty list here means COULD NOT FIND OUT, and reading it as "no
            # coverage" would make pylon call a defended resource an open gap.
            entry["unenumerated_pages"].append(slug)
            print(f"  ? {slug} -> {plan}: page does not enumerate alerts "
                  f"(recorded as not-enumerable, NOT as uncovered)", file=sys.stderr)
            continue
        entry["alerts"].extend(alerts)
        total += len(alerts)
        print(f"  {slug} -> {plan}: {len(alerts)}")

    try:
        alerts = parse_mdi(fetch(MDI, opener))
        if alerts:
            catalog["DefenderForIdentity"] = {
                "product": "Microsoft Defender for Identity",
                "plan": "DefenderForIdentity",
                "granularity": "technique",
                "alerts": alerts,
            }
            total += len(alerts)
            print(f"  defender-for-identity: {len(alerts)}")
    except Exception as exc:  # noqa: BLE001
        print(f"  ! defender-for-identity: {exc}", file=sys.stderr)

    if total < MINIMUM_ALERTS:
        print(
            f"only {total} alerts parsed (expected at least {MINIMUM_ALERTS}) — "
            "refusing to write. A thin catalog would silently return pylon to "
            "calling every technique an uncovered gap.",
            file=sys.stderr,
        )
        return 1

    CATALOG.parent.mkdir(parents=True, exist_ok=True)
    CATALOG.write_text(
        json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"\nwrote {CATALOG}: {len(catalog)} products/plans, {total} built-in alerts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
