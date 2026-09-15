#!/usr/bin/env python3
"""Check the scan document against what Azure says, resource by resource.

    uv run python scripts/audit-against-azure.py [--limit N] [--type SUBSTRING]

Every bug found on 2026-09-07 was found the same way: comparing a conclusion in
`analysis.json` against the raw API response for that same resource. Three
premises died in one evening, and not one of them was caught by 998 tests --
because every fixture was written by whoever wrote the premise, so the stub and
the assumption agreed with each other.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
It does not re-implement `diagnostics.py`. A second parse written from the same
understanding as the first is not a check, it is the same opinion typed twice.

Instead it asserts relationships that hold no matter how the parse is written:

  * a resource reported as never configured must have NO diagnostic settings
  * a resource reported as logging must have a setting pointing at the target
    workspace -- destination is part of the claim, not metadata about it
  * a table the scan names must exist in THIS workspace -- checked against the
    workspace's own schema list, not the hand-maintained column catalogue,
    which is known incomplete and would flag real tables as suspect
  * a VM's expected table must match its operating system, read from Azure
    rather than guessed from the name: `Event` is documented "Windows Event Log
    on Windows computers", so naming it for a Linux machine is advice that
    cannot be followed

Each of those can be decided from the raw response and an independent fact,
without knowing how Pylon reached its answer. That is what makes them evidence.

A DISAGREEMENT IS NOT AUTOMATICALLY A BUG
-----------------------------------------
It is a place where two sources say different things, which is where a human
should look. The output names the resource, both answers, and which check
disagreed, so the next step is reading two things side by side rather than
trusting this script's verdict -- which would be the same mistake one level up.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pylon import azcli
from pylon.tablemap import AGENT_TABLE_BY_OS

VM_TYPE = "microsoft.compute/virtualmachines"


def _settings(resource_id: str) -> tuple[list | None, str]:
    """Azure's own answer for one resource. `None` means the read failed, which
    is not the same as "no settings" and must not be compared as if it were."""
    p = azcli.run(["monitor", "diagnostic-settings", "list", "--resource", resource_id,
                   "-o", "json"], timeout=azcli.CONTROL_TIMEOUT)
    if p.returncode != 0:
        return None, (p.stderr or "").strip()[:120]
    try:
        payload = json.loads(p.stdout or "[]")
    except json.JSONDecodeError as bad:
        return None, f"unparseable: {bad}"
    return (payload if isinstance(payload, list) else payload.get("value") or []), ""


def _vm_os(resource_id: str) -> str | None:
    """A virtual machine's operating system, from Azure.

    `None` means the read failed -- which is not "unknown OS" and must not be
    compared as if it were. The empty string means Azure answered and did not
    say, which is a real answer and not a failure.
    """
    p = azcli.run(["vm", "show", "--ids", resource_id,
                   "--query", "storageProfile.osDisk.osType", "-o", "tsv"],
                  timeout=azcli.CONTROL_TIMEOUT)
    if p.returncode != 0:
        return None
    return (p.stdout or "").strip().lower()


def _points_at(settings: list, workspace: str) -> bool:
    """True when any setting ships to the workspace the scan measured against.

    A setting pointing somewhere else is not coverage here: no rule in this
    workspace can read what it sends.
    """
    for entry in settings:
        props = entry.get("properties", entry) or {}
        ws = (props.get("workspaceId") or "").lower()
        if ws and workspace and ws.endswith(workspace.lower()):
            return True
    return False


def audit(document: dict, limit: int, type_filter: str) -> list[dict]:
    """One row per disagreement. An empty list means every check agreed."""
    workspace = (document.get("workspace") or "").lower()
    resources = {r["resource_id"]: r for r in (document.get("resources") or [])}
    gaps = document.get("coverage_gaps") or []
    # The workspace's own schema list, which is real evidence about this tenant,
    # unlike the hand-maintained column catalogue.
    provisioned = set(document.get("provisioned_tables") or [])

    seen, problems = set(), []
    for gap in gaps:
        rid = gap["resource_id"]
        if rid in seen:
            continue
        row = resources.get(rid) or {}
        rtype = (row.get("resource_type") or "").lower()
        if type_filter and type_filter.lower() not in rtype:
            continue
        seen.add(rid)
        if len(seen) > limit:
            break

        # Bound as defaults rather than captured: a closure over a loop
        # variable reads whatever the loop holds when it RUNS, which is correct
        # only while every call happens inside the same iteration. That is true
        # today and is exactly the kind of thing that stops being true quietly.
        def flag(check: str, pylon_says: str, azure_says: str,
                 _rid: str = rid, _rtype: str = rtype) -> None:
            problems.append({"resource": _rid.split("/")[-1], "type": _rtype,
                             "check": check, "pylon": pylon_says,
                             "azure": azure_says})

        # ── the expected table must exist in THIS workspace ──────────────────
        # Checked against `provisioned_tables` -- the workspace's own schema
        # list -- and NOT against `TABLE_SCHEMAS`. The hand-maintained catalogue
        # is known incomplete (it has no row for `Event`, a table every Windows
        # VM writes), so checking against it flags real tables as suspect. A
        # check whose false positives outnumber its findings gets muted.
        table = gap.get("expected_table") or ""
        if table and provisioned and table not in provisioned:
            flag("table exists here", f"expects {table}",
                 "the workspace has no schema by that name")

        # ── a VM's table must match its operating system ─────────────────────
        # The check that would have caught C11 before a human did. The OS comes
        # from Azure, not from the resource name: the machine that started
        # this was named for its distro, and "ubuntu" is not spelled "linux".
        if rtype == VM_TYPE and table:
            os_type = _vm_os(rid)
            if os_type is None:
                flag("could read the VM", "—", "could not read osType")
            elif os_type:
                should_be = AGENT_TABLE_BY_OS.get(os_type)
                if should_be and table != should_be:
                    flag("VM table matches OS", f"expects {table}",
                         f"osType is {os_type}, which writes {should_be}")

        # ── and the two structural claims, against the raw response ──────────
        settings, error = _settings(rid)
        if settings is None:
            flag("could read Azure", "—", f"read failed: {error}")
            continue

        reason = (gap.get("dark_reason") or "").lower()
        # "no diagnostic setting" is the only reason that claims an empty list.
        # The first draft matched "never configured", which the scan used for
        # BOTH "nothing exists" and "a setting reaches us but this category is
        # off" -- so it reported a false disagreement on the workspace itself,
        # which had exactly one setting and one category switched off. The
        # ambiguity was real and is now fixed at the source; this reads the
        # narrower string.
        if "no diagnostic setting" in reason and settings:
            flag("no diagnostic setting", "no diagnostic setting",
                 f"{len(settings)} diagnostic setting(s) exist")
        # And the reason that DOES claim a destination elsewhere.
        if "ships elsewhere" in reason and _points_at(settings, workspace):
            flag("ships elsewhere", "ships elsewhere",
                 "a setting does point at the scanned workspace")
        if gap.get("is_logging") and not _points_at(settings, workspace):
            flag("logging reaches workspace", "is_logging=True",
                 "no setting points at the scanned workspace")

    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--analysis", default="analysis.json")
    ap.add_argument("--limit", type=int, default=50,
                    help="how many resources to check (default 50)")
    ap.add_argument("--type", default="", metavar="SUBSTRING",
                    help="only resource types containing this")
    args = ap.parse_args()

    src = pathlib.Path(args.analysis)
    if not src.is_file():
        print(f"no scan document at {src} — run `pylon analyze` first", file=sys.stderr)
        return 2
    document = json.loads(src.read_text(encoding="utf-8"))
    if not document.get("coverage_gaps"):
        print("the document has no coverage rows to check — the resource-activity "
              "read did not run", file=sys.stderr)
        return 2

    print(f"checking up to {args.limit} resource(s) against Azure…\n")
    problems = audit(document, args.limit, args.type)

    if not problems:
        print("every check agreed.\n")
        print("That means the scan's structural claims match the raw API for the "
              "resources checked. It does NOT mean the numbers are right — this "
              "compares relationships, not counts.")
        return 0

    print(f"{len(problems)} disagreement(s). Each is a place two sources differ, "
          f"which is where to look — not a verdict:\n")
    for p in problems:
        print(f"  {p['resource']}  [{p['type']}]")
        print(f"      check : {p['check']}")
        print(f"      pylon : {p['pylon']}")
        print(f"      azure : {p['azure']}")
        print()
    print("Read the resource's raw response next to its row in analysis.json "
          "before changing anything.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
