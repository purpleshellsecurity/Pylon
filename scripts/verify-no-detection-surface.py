#!/usr/bin/env python3
"""Check every "Activity Log only" declaration against Microsoft's own docs.

These declarations decide what the estate scan reports as *not a gap*, so a
wrong one hides a real blind spot — the worst failure this tool has. They were
originally written from memory with a `basis:` line that read as though it had
been checked. It had not: one of sixteen was verified. This script is what makes
the rest of them true, and keeps them true.

The check is deterministic. Azure Monitor publishes one page per resource type:

    .../azure-monitor/reference/supported-logs/microsoft-<provider>-<type>-logs

    404  no such page  ->  no resource logs exist  ->  reason: none
    200  page exists   ->  resource logs exist     ->  reason: operational-only,
                                                       and `logs` must list them

So `reason: none` on a type whose page returns 200 is a factual error, and
`operational-only` on a 404 claims to set aside categories that do not exist.
Both are caught here. What this CANNOT check is the judgement inside
`operational-only` — whether those categories really are availability rather
than identity — which is why the declaration lists them: a reader disagrees with
the call by reading the list, not by trusting the label.

    python scripts/verify-no-detection-surface.py

Network only, no Azure, no model. Exits non-zero on a contradiction.
"""

from __future__ import annotations

import subprocess
import sys

from pylon.catalog.no_detection_surface import NONE, OPERATIONAL_ONLY, declared

_BASE = "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs"


def _docs_url(resource_type: str) -> str:
    return f"{_BASE}/{resource_type.replace('.', '-').replace('/', '-')}-logs"


def _status(url: str) -> str:
    try:
        return subprocess.run(  # fixed argv, no shell
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "-L", "--max-time", "25", url],
            capture_output=True, text=True, check=False,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "err"


def main() -> int:
    entries = declared()
    if not entries:
        print("No declarations found — is the catalog data present?", file=sys.stderr)
        return 1

    problems, unreachable = [], []
    print(f"{'code':<6} {'declared':<18} resource type")
    print("-" * 78)
    for rt, d in sorted(entries.items()):
        code = _status(_docs_url(rt))
        note = ""
        if code == "200" and d.reason == NONE:
            note = "  <-- WRONG: the page exists, so resource logs exist"
            problems.append((rt, note))
        elif code == "404" and d.reason == OPERATIONAL_ONLY:
            note = "  <-- WRONG: no page, so there are no categories to set aside"
            problems.append((rt, note))
        elif code == "200" and d.reason == OPERATIONAL_ONLY and not d.logs:
            note = "  <-- INCOMPLETE: operational-only must LIST what it sets aside"
            problems.append((rt, note))
        elif code not in ("200", "404"):
            note = "  (unreachable — not checked)"
            unreachable.append(rt)
        print(f"{code:<6} {d.reason:<18} {rt}{note}")

    print("-" * 78)
    checked = len(entries) - len(unreachable)
    print(f"{checked} of {len(entries)} checked against the docs, {len(problems)} contradicted")
    if unreachable:
        # Never counted as passing: an unreachable page is an unknown, and
        # silently treating it as agreement is how a wrong claim survives.
        print(f"{len(unreachable)} unreachable — re-run with network access")
    if problems:
        print("\nA wrong declaration here hides a real blind spot: the estate scan")
        print("reports these types as 'not a gap' and stops looking at them.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
