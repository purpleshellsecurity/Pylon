"""Does each rule actually return anything against this tenant's data.

The rules leg lists what is deployed. This runs it. The difference matters
because the three ways a rule fails look identical on a dashboard: it queries
a table nothing fills, it references a column that does not exist, or it works
perfectly and the tenant simply has not done the thing it watches for.

The query is run RAW, over everything retained, rather than over the rule's
own queryPeriod -- which is a superset of that window. That makes one verdict
definitive and one weaker, and they are labelled accordingly:

    zero rows over the superset  ->  never-fires, and it cannot fire in any
                                     sub-window either. Definitive.
    rows over the superset       ->  fires: the rule matches data that exists
                                     here. Whether it matched inside its own
                                     15-minute window is not established, and
                                     health_detail says so.

`not-assessed` is refusal, never a judgement: a rule reading a Basic or
Auxiliary table is not run because querying those tiers costs money, and a
tier limitation reported as a dead rule is an accusation nobody measured.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from . import azcli

WORKERS = 6
BILLABLE_TIERS = {"Basic", "Auxiliary"}

# A missing table and a missing column are both "broken", but they are
# different repairs, so the message is kept verbatim rather than summarised.
_UNKNOWN_TABLE = re.compile(r"(SEM0100|Failed to resolve table|could not be resolved)", re.I)


def _run(workspace_guid: str, kql: str,
         timeout: int | None = None) -> tuple[int | None, str | None, int]:
    """(row count, error). A None count means the query did not complete.

    This leg had the only timeout in the scan and now shares the one every leg
    uses. `timeout=None` means "the shared bound", never "no bound" -- passing
    None straight to `subprocess.run` is how a fix for the hang would have
    reintroduced it here.
    """
    wrapped = f"{kql}\n| count"
    p = azcli.query(workspace_guid, wrapped, timeout=timeout)
    if p.returncode != 0:
        return None, (p.stderr or "").strip()[:300], p.returncode
    rows = json.loads(p.stdout or "[]")
    if not rows:
        return 0, None, 0
    try:
        return int(rows[0].get("Count", 0)), None, 0
    except (TypeError, ValueError):
        return None, "count column was not an integer", p.returncode


def _one(rule: dict, workspace_guid: str, tiers: dict[str, str]) -> dict:
    out = dict(rule)
    query = rule.get("_query") or ""

    if not query:
        out["rule_health_status"] = "not-assessed"
        out["health_detail"] = (f"{rule.get('_kind') or 'this'} rule has no KQL to "
                                "run; its health is decided by the service")
        return out

    billable = sorted({t for t in rule.get("tables_referenced", [])
                       if tiers.get(t) in BILLABLE_TIERS})
    if billable:
        out["rule_health_status"] = "not-assessed"
        out["health_detail"] = ("not run: reads " + ", ".join(billable)
                                + " on a billable tier, and a tier limit is not "
                                  "a judgement about a detection")
        return out

    # A table that IS here and whose plan is unknown. Distinct from a table
    # absent from `tiers` altogether, which holds no data and costs nothing to
    # query -- that absence is the never-fires signal below.
    #
    # This used to be impossible to reach, because the caller coerced an
    # unknown plan to "Analytics" before handing the map over. That made an
    # unreadable plan mean FREE, so the gate that exists to stop this tool
    # spending the client's money was open exactly when the control plane
    # would not say. An unknown plan is now refused like a billable one: an
    # unmeasured cost is not a licence to spend.
    unknown = sorted({t for t in rule.get("tables_referenced", [])
                      if t in tiers and not tiers[t]})
    if unknown:
        out["rule_health_status"] = "not-assessed"
        out["health_detail"] = ("not run: the plan for " + ", ".join(unknown)
                                + " could not be read, so whether querying it "
                                  "is billable is unknown")
        return out

    count, err, code = _run(workspace_guid, query)
    if err is not None:
        # The code, not the words. This read `"exceeded" in err` and so decided
        # whether a detection is FAULTY by matching a phrase in a message from
        # another module -- reword the message and every timed-out rule starts
        # being reported as broken. A transport failure means the scan could not
        # look; only a query the service REJECTED is evidence about the rule.
        # A missing extension is the scan being unable to run the query, not
        # the service rejecting it -- but az exits 2 for an unrecognised
        # command, and 2 is not a transport failure, so it landed in "broken".
        # On the first Windows run that labelled 25 of 26 rules faulty because
        # the `log-analytics` extension was absent. "Could not look" reported
        # as "looked and found it broken" is the one mistake this codebase
        # exists to prevent, and it was making it on the most consequential
        # field in the report.
        could_not_look = (code in azcli.TRANSPORT_FAILURES
                          or azcli.missing_extension(err) is not None)
        readable = "unreadable" if could_not_look else "broken"
        out["rule_health_status"] = readable
        out["health_detail"] = err
        return out

    if count:
        out["rule_health_status"] = "fires"
        out["health_detail"] = (f"{count} row(s) over all retained data; whether it "
                                "matched inside the rule's own window is not established")
    else:
        empty = sorted({t for t in rule.get("tables_referenced", [])
                        if t not in tiers})
        out["rule_health_status"] = "never-fires"
        out["health_detail"] = ("no rows over all retained data, so it cannot fire "
                                "in its own window either"
                                + (f"; reads {', '.join(empty)} which hold no data"
                                   if empty else ""))
    return out


def probe(rules: list[dict], workspace_guid: str,
          live_tiers: dict[str, str]) -> tuple[list[dict], dict]:
    """(rules with health filled in, read state)."""
    worker = partial(_one, workspace_guid=workspace_guid, tiers=live_tiers)
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        done = list(pool.map(worker, rules))

    import collections
    tally = collections.Counter(r["rule_health_status"] for r in done)
    return done, {"ran": True,
                  "detail": "; ".join(f"{n} {k}" for k, n in tally.most_common())}
