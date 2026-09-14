#!/usr/bin/env python3
"""Add activity names a real directory writes that Microsoft's reference omits.

The vendored catalogue is harvested from the published audit-activities page and
holds 922 names. Measured against a quiet lab directory over 30 days: of the 42
activities it actually emitted, three appear nowhere on that page.

    Update PasswordProfile
    Add app role assignment grant to user
    Create application - Certificates and secrets management

None is obscure. The first is a password reset. The reference is a document
Microsoft maintains by hand and the directory is the system of record, and the
two disagree.

So there are two sources and they are kept apart. `refresh-entra-audit-
activities.py` writes what Microsoft documents. This adds what a workspace was
seen to write, under its own key, so a reader can always tell which is which and
a later refresh of the documented half never silently drops the observed one.

    python scripts/observe-entra-activities.py --workspace <name|id|guid> [--days 30]

Read-only against the workspace. Writes the same catalogue file. Names come from
the log, never from a keyboard: the point is that a transcription error here
produces a filter that matches nothing, which is the failure this whole path
exists to prevent.
"""

from __future__ import annotations

import argparse
import gzip
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "src" / "pylon" / "catalog" / "entra-audit-activities.json.gz"
OBSERVED_KEY = "observed"

QUERY = """
AuditLogs
| where TimeGenerated > ago({days}d)
| summarize events = count(), lastSeen = max(TimeGenerated)
    by OperationName, Category, LoggedByService
| order by events desc
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", required=True,
                    help="name, resource id, or workspace guid")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would be added and write nothing")
    args = ap.parse_args()

    sys.path.insert(0, str(ROOT / "src"))
    from pylon import entra_audit_activities as entra
    from pylon import validate

    _tenant, _arm, guid = validate.resolve(args.workspace)
    proc = subprocess.run(
        ["az", "monitor", "log-analytics", "query", "-w", guid,
         "--analytics-query", QUERY.format(days=args.days), "-o", "json"],
        capture_output=True, text=True, timeout=300)
    if proc.returncode:
        print(f"query failed: {proc.stderr.strip()[:300]}", file=sys.stderr)
        return 1
    rows = json.loads(proc.stdout or "[]")
    if not rows:
        print(f"no AuditLogs rows in the last {args.days}d — nothing to observe")
        return 0

    data = json.loads(gzip.decompress(CATALOG.read_bytes()))
    documented = {entra.normalise(a)
                  for block in (data.get("activities") or {}).values()
                  for a in block}
    already = {entra.normalise(a) for a in (data.get(OBSERVED_KEY) or {})}

    # The name is stored EXACTLY as the directory wrote it, trailing space and
    # typographic dash included. `normalise` is what matching folds; the stored
    # form is what a person compares against the portal.
    new: dict[str, dict] = {}
    for row in rows:
        name = row.get("OperationName") or ""
        key = entra.normalise(name)
        if not key or key in documented or key in already or key in {
                entra.normalise(n) for n in new}:
            continue
        new[name] = {"category": row.get("Category") or "",
                     "loggedByService": row.get("LoggedByService") or "",
                     "events": int(row.get("events") or 0)}

    print(f"{len(rows)} distinct activities emitted in {args.days}d; "
          f"{len(documented)} documented")
    if not new:
        print("every one of them is already catalogued")
        return 0
    print(f"\n{len(new)} emitted and NOT documented:")
    for name, detail in sorted(new.items()):
        print(f"  {detail['events']:>5} events  {name!r}")
        print(f"            category={detail['category']!r}")
    if args.dry_run:
        print("\n--dry-run: nothing written")
        return 0

    observed = dict(data.get(OBSERVED_KEY) or {})
    observed.update(new)
    data[OBSERVED_KEY] = observed
    data.setdefault("meta", {})["observed_note"] = (
        "Names under `observed` were seen in a real directory's AuditLogs and "
        "are absent from Microsoft's published reference. They are evidence "
        "from one tenant, not documentation.")
    CATALOG.write_bytes(gzip.compress(
        json.dumps(data, indent=1, sort_keys=True).encode("utf-8")))
    print(f"\nwrote {CATALOG.relative_to(ROOT)} — {len(observed)} observed names")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
