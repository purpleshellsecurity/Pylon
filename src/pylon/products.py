"""Techniques a security PRODUCT has actually detected in this tenant.

The strongest evidence available for `covered_by_product`, and the only kind
this scan will accept for it: not a claim that Defender detects a technique,
but a row in `SecurityAlert` showing that it did, here, with a date.

Read as a FLOOR, never a ceiling. A product covering a technique nobody has
triggered leaves no trace, so silence proves nothing -- which is why an
unobserved technique falls through to the ordinary verdicts rather than being
marked uncovered by a product. The floor is still worth having: it suppresses
recommending a detection for something already being caught.

Its opposite, `plan_available_not_enabled`, is NOT derivable here and is left
unassigned. A plan that is switched off produces no alerts by definition, so
no amount of reading this tenant can show what it would have caught. The
published reference that could answer it is tactic-level and pinned to
ATT&CK v9, which is too coarse and too stale to suppress a real gap with.
"""

from __future__ import annotations

import collections
import json

from . import azcli

# Sentinel's own scheduled rules land in the same table. They are not a
# product detecting something -- they are the rules this scan already
# inventories, and counting them here would mark a technique "covered by a
# product" on the strength of a rule.
SELF = "Azure Sentinel"


def probe(workspace_guid: str, days: int = 30) -> tuple[dict[str, list[str]], dict]:
    """({technique: [product names]}, read state)."""
    query = (
        f"SecurityAlert | where TimeGenerated > ago({days}d) "
        f"| where ProductName != '{SELF}' "
        "| mv-expand t = todynamic(Techniques) | extend tech = tostring(t) "
        "| where isnotempty(tech) "
        "| summarize alerts=count(), newest=max(TimeGenerated) by ProductName, tech"
    )
    p = azcli.query(workspace_guid, query)
    if p.returncode != 0:
        return {}, {"ran": False,
                    "detail": "could not read SecurityAlert, so no product "
                              f"coverage was observed: {(p.stderr or '').strip()[:160]}"}

    rows = json.loads(p.stdout or "[]")
    observed: dict[str, set[str]] = collections.defaultdict(set)
    for r in rows:
        observed[r["tech"]].add(r["ProductName"])

    out = {tech: sorted(products) for tech, products in observed.items()}
    products = sorted({p for ps in out.values() for p in ps})
    detail = (f"{len(out)} technique(s) observed being detected by "
              f"{len(products)} product(s) in {days}d: {', '.join(products)}. "
              "A floor, not a ceiling: a product covering a technique nobody "
              "triggered leaves no trace here.")
    return out, {"ran": True, "detail": detail}
