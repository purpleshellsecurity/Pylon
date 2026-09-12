#!/usr/bin/env python3
"""Vendor Microsoft's per-table CATEGORY index from the docs repository.

The gap scan reports the fresh tables its technique index has no entry for as a
flat list — "16 not indexed ... they are not zero, they are unknown". True, and
unusable: on the tenant this was built against that list held `Event` at 963 MB
beside `Heartbeat`, `Perf` and `AzureMetrics`, with nothing to tell them apart.

This vendors the categories so that list can be RANKED. What it is emphatically
not is a filter, and the measurement below is why.

**The Security category is not the set of tables you can detect on.** Checked
against the tables this tenant's own enabled rules query:

    StorageBlobLogs   Azure Resources                       <- a deployed rule queries it
    AZKVAuditLogs     Audit, Azure Resources                <- the Key Vault surface
    LAQueryLogs       Audit                                 <- T1654 in the gap list
    AKSAudit          Audit, Azure Resources, Containers    <- eight deployed rules
    SentinelHealth    Security                              <- 255 MB of health telemetry

Filtering the gap denominator on `Security` would have cut four tables this
tenant actively detects on, and kept one that records whether Sentinel's own
connectors ran. `Security ∪ Audit` recovers three of the four and still misses
StorageBlobLogs — data-plane access logs are filed under Azure Resources with
hundreds of purely operational resource logs — and still keeps SentinelHealth.

There is no category combination that separates a detection surface from
operational noise, because that distinction is a judgement about what an attacker
does, which is what `catalog/table-techniques.yaml` holds and states a basis for.
So the categories are carried as a HINT for which unindexed table to look at
first, never as a claim about what a table can support.

The authority is the docs repository rather than the rendered page: one markdown
file, generated, listing every table under each category heading.
<https://github.com/MicrosoftDocs/azure-monitor-docs>

No credentials. Network only.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCE = (
    "https://raw.githubusercontent.com/MicrosoftDocs/azure-monitor-docs/main/"
    "articles/azure-monitor/reference/tables-category.md"
)
OUT = Path(__file__).resolve().parent.parent / "src" / "pylon" / "catalog" / "table-categories.json"

_HEADING = re.compile(r"^#{2,3}\s+(.+?)\s*$")
_ENTRY = re.compile(r"^-\s*\[([A-Za-z0-9_]+)\]")


def parse(markdown: str) -> dict[str, list[str]]:
    """{table: [category, ...]}, in the page's own order.

    A table appears under every category that claims it — AzureActivity is in
    Audit, Azure Resources AND Security — so this is a list per table and not a
    single label. Collapsing it to one would be inventing a primary category the
    page does not state.
    """
    out: dict[str, list[str]] = {}
    current = ""
    for line in markdown.splitlines():
        heading = _HEADING.match(line)
        if heading:
            current = heading.group(1).strip()
            continue
        entry = _ENTRY.match(line.strip())
        if entry and current:
            out.setdefault(entry.group(1), [])
            if current not in out[entry.group(1)]:
                out[entry.group(1)].append(current)
    return out


def main() -> int:
    with urllib.request.urlopen(SOURCE, timeout=60) as response:
        markdown = response.read().decode("utf-8")

    tables = parse(markdown)
    if len(tables) < 500:
        # A partial read is not a smaller docs page; it is a failed fetch, and
        # vendoring it would quietly shrink every hint downstream.
        print(f"refusing to write: only {len(tables)} tables parsed, expected 500+",
              file=sys.stderr)
        return 1

    categories = sorted({c for cats in tables.values() for c in cats})
    OUT.write_text(json.dumps({
        "meta": {
            "source": SOURCE,
            "harvested": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "tables": len(tables),
            "categories": categories,
        },
        "tables": dict(sorted(tables.items())),
    }, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(Path.cwd())}: {len(tables)} tables, "
          f"{len(categories)} categories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
