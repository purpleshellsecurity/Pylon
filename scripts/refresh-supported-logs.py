#!/usr/bin/env python3
"""Record which of a service's tables are RESOURCE LOGS, and their categories.

The problem this solves, found by running --gap-scan against a real tenant: the
report told someone that Azure documents 35 "resource logs" for
Microsoft.Compute/virtualMachines and listed `Perf`, `Heartbeat`, `WireData`
among them. A virtual machine has NO resource logs. Those tables reach a
workspace because an agent and a data collection rule put them there, which is a
completely different thing to switch on — there is no diagnostic setting to
enable, so the advice attached to the finding was wrong too.

The service files were harvested from each service's MONITORING docs, which list
every table Azure Monitor associates with a type and do not distinguish the two.
Nothing in the data said which was which, so nothing downstream could either.

The authority is Azure Monitor's generated supported-logs reference, one page
per resource type at a deterministic URL:

    .../azure-monitor/reference/supported-logs/microsoft-<provider>-<type>-logs

It lists ONLY diagnostic-setting CATEGORIES. A 404 means the type has none at
all — Microsoft.Compute/virtualMachines is the worked example: its page exists
and offers exactly two Update Manager categories, so not one of the 35 tables in
its service file is a resource log.

What the page does NOT reliably give is the table each category lands in. The
"Log table" column names the DEFAULT destination, which for most services is the
shared `AzureDiagnostics` table: Key Vault's two categories both point there,
even though with `logAnalyticsDestinationType: Dedicated` they arrive in
AZKVAuditLogs and AZKVPolicyEvaluationDetailsLogs. Only services whose docs name
the dedicated table (Storage, Application Insights, Container Apps) can be joined
on table name at all.

So the CATEGORY is what gets recorded and what a report should say. It is also
the thing a reader acts on — you enable a category, not a table.

Learn serves these as markdown with `?accept=text/markdown`, so this parses a
documented table rather than scraping rendered HTML.

Writes back into each `src/pylon/catalog/service_files/*.json`:

    resource_log_categories   every diagnostic category the type offers, in
                              document order. [] means the page 404s: no
                              resource logs exist for this type.
    tables.<Table>.diagnostic_category
                              set only where the page named that exact table,
                              so it is never a guess. Absent means the docs
                              routed the category to AzureDiagnostics and the
                              dedicated name cannot be derived from this page.

Usage:
    python scripts/refresh-supported-logs.py            # every service file
    python scripts/refresh-supported-logs.py --check    # report, write nothing
    python scripts/refresh-supported-logs.py --only microsoft.keyvault/vaults

No Azure credentials: this reads public docs.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
from pathlib import Path
from urllib.request import ProxyHandler, build_opener, getproxies

BASE = "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs"
FILES = Path("src/pylon/catalog/service_files")

# | Category | Costs to export | Log table | ... |
# The log-table cell is a markdown link followed by <br> and a description; some
# rows (ContainerAppHTTPLogs, OTelResources) have a category and an EMPTY table
# cell, which is still a real category and still needs recording.
_ROW = re.compile(r"^\|\s*([A-Za-z0-9_.\-/ ]+?)\s*\|[^|]*\|\s*(.*?)\s*\|")
_LINK = re.compile(r"\[([A-Za-z0-9_]+)\]")


def slug(resource_type: str) -> str:
    """microsoft-storage-storageaccounts-blobservices, from the ARM type."""
    return resource_type.lower().replace("/", "-").replace(".", "-")


def fetch(resource_type: str, opener) -> str | None:
    """The page's markdown, or None on 404 — which means no resource logs."""
    url = f"{BASE}/{slug(resource_type)}-logs?accept=text/markdown"
    try:
        with opener.open(url, timeout=60) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def parse(markdown: str) -> tuple[list[str], dict[str, str]]:
    """(every category in document order, {table: categories} where named).

    Two returns because they answer different questions. The category list is
    complete and authoritative — it is what a diagnostic setting turns on. The
    table map is partial by nature: it holds only the rows whose "Log table"
    column names a table other than the shared `AzureDiagnostics`, because
    that is the only case where the dedicated destination can be read off this
    page rather than guessed at.
    """
    categories: list[str] = []
    by_table: dict[str, list[str]] = {}
    for line in markdown.splitlines():
        if not line.startswith("|"):
            continue
        match = _ROW.match(line)
        if not match:
            continue
        category, table_cell = match.group(1).strip(), match.group(2)
        if category in {"Category", "---"} or set(category) <= {"-", " "}:
            continue  # header or separator
        if category not in categories:
            categories.append(category)
        link = _LINK.search(table_cell)
        # A row can name no table at all (ContainerAppHTTPLogs, OTelResources)
        # and is still a real category — hence the category list above.
        if link and link.group(1) != "AzureDiagnostics":
            by_table.setdefault(link.group(1), []).append(category)
    return categories, {t: ", ".join(c) for t, c in by_table.items()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="report, write nothing")
    ap.add_argument("--only", help="one resource type")
    args = ap.parse_args()

    if not FILES.is_dir():
        print(f"{FILES} not found — run from the repo root.", file=sys.stderr)
        return 2

    opener = build_opener(ProxyHandler(getproxies()))
    opener.addheaders = [("User-Agent", "pylon-refresh-supported-logs")]

    changed = no_logs = failed = 0
    rows: list[tuple[str, int, int]] = []

    for path in sorted(FILES.glob("*.json")):
        if path.name.startswith("_"):
            continue
        svc = json.loads(path.read_text(encoding="utf-8"))
        rtype = svc.get("resource_type")
        if not rtype or (args.only and rtype.lower() != args.only.lower()):
            continue

        try:
            markdown = fetch(rtype, opener)
        except Exception as exc:  # noqa: BLE001 - one bad page must not stop the run
            print(f"  ! {rtype}: {exc}", file=sys.stderr)
            failed += 1
            continue

        categories, by_table = parse(markdown) if markdown is not None else ([], {})
        if markdown is None:
            no_logs += 1

        # [] is a claim: the page 404s, so this type has no diagnostic categories
        # at all. Distinct from the key being absent, which means unchecked.
        svc["resource_log_categories"] = categories

        tables = svc.get("tables") or {}
        named = 0
        for name, spec in tables.items():
            if not isinstance(spec, dict):
                continue
            category = by_table.get(name)
            if category:
                spec["diagnostic_category"] = category
                named += 1
            else:
                # Not named on the page. Either it is not a resource log, or the
                # docs routed its category to AzureDiagnostics and the dedicated
                # name is not derivable here. Both mean: do not claim one.
                spec.pop("diagnostic_category", None)

        rows.append((rtype, len(categories), named, len(tables)))
        if not args.check:
            path.write_text(json.dumps(svc, indent=1) + "\n", encoding="utf-8")
            changed += 1

    width = max((len(r[0]) for r in rows), default=0)
    for rtype, cats, named, tables in sorted(rows, key=lambda r: (-r[1], r[0])):
        note = "" if cats else "   NO RESOURCE LOGS"
        print(f"  {rtype:<{width}}  categories {cats:>3}   "
              f"tables named {named:>2}/{tables:<3}{note}")

    print("-" * (width + 42))
    verb = "checked" if args.check else "written"
    print(f"{len(rows)} service files {verb}; {no_logs} have no supported-logs page; "
          f"{failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
