#!/usr/bin/env python3
"""Compare the techniques a run assigned against the ones the index names.

C7 of the release checklist, as a check rather than an eyeball. The failure it
looks for is invisible to everything else: `verify_mitre_ids` confirms a
technique ID exists in the ATT&CK bundle, never that it fits the behaviour, so a
real-but-wrong ID passes validation, passes the KQL checker, and ships.

Two live examples this exists because of:

  Two Exchange inbox-rule detections came back T1098.003 (Additional Cloud
  Roles). An inbox rule is not a cloud role.

  After that was fixed, the same run swapped T1485 (Data Destruction) in for
  T1070.008 (Clear Mailbox Data) and T1566.003 in for T1534 (Internal
  Spearphishing) -- reaching past the specific sub-technique for a broader one.

Usage:

    python scripts/check-techniques.py reports/release
    python scripts/check-techniques.py /tmp/tq            # one run's output dir

Reads only the generated .kql headers and the vendored index. No model, no
tenant, no network. Exits non-zero when a detection's technique contradicts the
index for the operation it fires on.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from pylon.catalog.table_techniques import candidates, indexed_tables

_TECHNIQUE = re.compile(r"^//\s*MITRE ATT&CK:\s*(T\d{4}(?:\.\d{3})?)", re.MULTILINE)
_TABLE = re.compile(r"^//\s*Table:\s*(\S+)", re.MULTILINE)


def _operations_in(kql: str, table: str) -> set[str]:
    """Indexed operation literals this query actually filters on.

    Matched against the query text rather than parsed: an operation appearing
    anywhere in the query is enough to say the detection is about it, and that
    keeps this robust to however the model chose to write the filter.
    """
    found = set()
    for claim in candidates(table):
        for op in claim.raw_operations:
            if re.search(rf'["\'\b]{re.escape(op)}["\'\b]', kql):
                found.add(op)
    return found


def check(root: Path) -> int:
    files = sorted(root.rglob("detections/*.kql"))
    if not files:
        print(f"No detections found under {root} — check the path.", file=sys.stderr)
        return 1

    problems, checked, unscoped = [], 0, 0
    for path in files:
        text = path.read_text(encoding="utf-8")
        tech_match, table_match = _TECHNIQUE.search(text), _TABLE.search(text)
        if not tech_match or not table_match:
            continue
        technique, table = tech_match.group(1), table_match.group(1)
        if table not in indexed_tables():
            unscoped += 1
            continue

        operations = _operations_in(text, table)
        if not operations:
            # Fires on an operation the index does not list. Choosing another
            # verified ID is legitimate here — this is the one allowed case.
            unscoped += 1
            continue

        checked += 1
        allowed = {
            c.technique for c in candidates(table)
            if operations & set(c.raw_operations)
        }
        if technique not in allowed:
            problems.append((path.name, technique, sorted(allowed), sorted(operations)))

    print(f"{len(files)} detections · {checked} fire on an indexed operation · "
          f"{unscoped} not scoped by the index (no claim made)")

    if not problems:
        print("\nPASS — every technique matches what the index names for its operation.")
        return 0

    print(f"\nFAIL — {len(problems)} technique(s) contradict the index:\n")
    for name, got, allowed, ops in problems:
        print(f"  {name}")
        print(f"      fires on: {', '.join(ops)}")
        print(f"      assigned: {got}")
        print(f"      index says: {' or '.join(allowed)}")
    print("\nA broader parent standing in for a specific sub-technique is the known")
    print("failure mode. The fix is the prompt block in table_techniques.render_for_prompt,")
    print("not the detection.")
    return 1


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "reports")
    if not root.exists():
        print(f"{root} does not exist.", file=sys.stderr)
        return 1
    return check(root)


if __name__ == "__main__":
    sys.exit(main())
