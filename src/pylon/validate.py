"""`pylon validate` -- run a written detection against the workspace.

Hand it the KQL and a window; it searches the Log Analytics workspace and says
what matched. That is the question you have before deploying anything: would
this fire at all, and is it far too noisy.

    pylon validate --kql d.kql --workspace W --window 7d
    pylon validate --kql -     --workspace W --start 2026-09-01 --end 2026-09-07

Read-only. Two queries per run -- a count, then a small sample only if the count
was non-zero -- both through `az monitor log-analytics query`, so this works on a
base install like `analyze` does rather than needing the SDK.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone

from . import apiversions
from . import azcli
from .logs import get_logger

log = get_logger(__name__)

def _az_json(args: list[str]):
    p = azcli.run([*args, "-o", "json"], timeout=azcli.CONTROL_TIMEOUT)
    if p.returncode != 0:
        raise SystemExit(f"az {' '.join(args[:3])} failed: {(p.stderr or '').strip()[:200]}")
    return json.loads(p.stdout or "null")


def resolve(workspace: str) -> tuple[str, str, str]:
    """(tenant id, workspace arm id, workspace guid)."""
    account = _az_json(["account", "show"])
    hits = _az_json(["graph", "query", "-q",
                     "Resources | where type =~ "
                     "'microsoft.operationalinsights/workspaces' "
                     f"and name =~ '{workspace}' | project id"])["data"]
    if not hits:
        raise SystemExit(f"no workspace named {workspace!r} in reach")
    arm = hits[0]["id"]
    props = _az_json(["rest", "--method", "get", "--url",
                      f"https://management.azure.com{arm}"
                      f"?api-version={apiversions.LOG_ANALYTICS}"])
    return account["tenantId"], arm, (props.get("properties") or {}).get("customerId", "")


# KQL duration literals, which is what someone writing a detection already has
# in their fingers: 30m, 24h, 7d. Mapped to the ISO 8601 the query API wants.
_WINDOW = re.compile(r"^(\d+)\s*([smhd])$")
_ISO = {"s": "PT{}S", "m": "PT{}M", "h": "PT{}H", "d": "P{}D"}

# How many matching rows to show. A detection that matches a million rows is a
# finding in itself, and printing them is not the way to deliver it.
SAMPLE_ROWS = 5


class BadWindow(ValueError):
    """The time window could not be read."""


def parse_window(spec: str) -> str:
    """A KQL duration (``7d``, ``24h``, ``30m``) as an ISO 8601 timespan."""
    hit = _WINDOW.match(spec.strip())
    if not hit:
        raise BadWindow(
            f"{spec!r} is not a KQL duration — use 30m, 24h or 7d"
        )
    count, unit = hit.groups()
    if int(count) == 0:
        raise BadWindow("a zero-length window would search nothing")
    return _ISO[unit].format(count)


def timespan_between(start: datetime, end: datetime) -> str:
    """An explicit start/end pair as the interval the query API wants."""
    if end <= start:
        raise BadWindow(f"--end ({end:%Y-%m-%d %H:%M}) is not after --start")
    stamp = "%Y-%m-%dT%H:%M:%SZ"
    return (f"{start.astimezone(timezone.utc):{stamp}}/"
            f"{end.astimezone(timezone.utc):{stamp}}")


def residual_time_bound(kql: str) -> str:
    """'' when the window governs; otherwise why the query narrowed it itself.

    "No hits in 30 days" is only true if the query was ASKED about 30 days. A
    detection carries its own time bound -- `| where TimeGenerated > ago(1h)` --
    and `--timespan` cannot widen past it, only narrow. So the honest reading of
    an empty result from a query that bounds itself to an hour is "quiet in its
    own window", which is what almost every healthy detection looks like. Calling
    that "no hits" is a conclusion the search did not earn.
    """
    if not re.search(r"\bago\s*\(", kql) and not re.search(r"\bbetween\s*\(", kql):
        return ""
    return ("the detection sets its own time bound, which still applies — the "
            "window can narrow that, never widen it, so an empty result means "
            "quiet in the detection's own window, not across the window you asked for")


def _pipeable(kql: str) -> str:
    """`kql` with a trailing statement terminator removed, so an operator can be
    appended to it.

    The house rules require a let-statement query to END WITH A SEMICOLON, and
    `| count` appended to one is a syntax error:

        Query could not be parsed at '|' on line [60,1]

    which `_run_kql` reports as a non-zero exit and `hunt` then reports as
    "the count query did not run". So the tool could not search for exactly the
    detections that followed the rule, and said only that the search failed.
    One terminator, not every one -- the semicolons between let statements are
    part of the query.
    """
    return kql.rstrip().removesuffix(";").rstrip()


def hunt(kql: str, guid: str, timespan: str) -> tuple[int | None, list[dict], str]:
    """(hits, sample rows, detail) for `kql` over `timespan`.

    `hits` is None where the SEARCH failed. A query that did not run is not a
    detection that found nothing, and reporting it as one is how a broken query
    gets read as a quiet tenant -- the same distinction `observe` keeps.
    """
    kql = _pipeable(kql)
    counted = _run_kql(f"{kql}\n| count", guid, timespan)
    if counted is None:
        why = last_error()
        return None, [], f"the count query did not run: {why}" if why else (
            "the count query did not run")
    hits = int(counted[0].get("Count") or 0) if counted else 0

    if not hits:
        return 0, [], "no rows matched"

    sample = _run_kql(f"{kql}\n| take {SAMPLE_ROWS}", guid, timespan) or []
    more = f", showing {len(sample)}" if hits > len(sample) else ""
    return hits, sample, f"{hits} row(s) matched{more}"


# Why the query could not run, from the LAST attempt. `_run_kql` answers None
# for "did not run", which is the distinction the callers need, and the reason
# was previously discarded -- a detection ending in a semicolon reported only
# "the count query did not run" while Azure had said exactly where it broke.
_last_error = ""


def last_error() -> str:
    """Azure's explanation for the most recent failed query, '' if none."""
    return _last_error


def _sdk():
    """The SDK query module, or None when it is not installed.

    A function rather than an import so BOTH paths stay testable: the CLI path
    still ships for base installs, and a test that stubs the subprocess would
    otherwise be silently testing nothing now that the SDK is preferred.
    """
    try:
        from . import logs_query
    except ImportError:
        return None                # base install: no SDK, the CLI path runs
    return logs_query


def _run_kql(query: str, guid: str, timespan: str) -> list[dict] | None:
    """Rows, or None when the query could not be run at all.

    Prefers the SDK, which reuses one client for the process; falls back to the
    `az` CLI so a base install -- where the SDK is not present -- still works.
    """
    global _last_error
    _last_error = ""
    backend = _sdk()
    started = time.monotonic()
    if backend is not None:
        rows, detail = backend.query(guid, query, timespan)
        elapsed = round(time.monotonic() - started, 2)
        if rows is None:
            _last_error = detail
            # The reason, on the structured channel too. A run that dies at
            # 03:00 in CI leaves no terminal to scroll back through, and this
            # is the sentence that says WHY -- the one the subprocess path
            # threw away for as long as it existed.
            log.warning("workspace query failed after %ss: %s", elapsed, detail,
                        extra={"event": "workspace_query_failed", "backend": "sdk",
                               "elapsed_s": elapsed, "timespan": timespan,
                               "reason": detail[:400]})
        else:
            log.debug("workspace query returned %d row(s) in %ss", len(rows), elapsed,
                      extra={"event": "workspace_query", "backend": "sdk",
                             "rows": len(rows), "elapsed_s": elapsed,
                             "timespan": timespan})
        return rows

    proc = azcli.run(
        ["monitor", "log-analytics", "query", "-w", guid,
         "--analytics-query", query, "--timespan", timespan, "-o", "json"],
        timeout=azcli.QUERY_TIMEOUT,
    )
    elapsed = round(time.monotonic() - started, 2)
    if proc.returncode != 0:
        _last_error = (proc.stderr or "").strip()[:400]
        log.warning("workspace query failed after %ss: %s", elapsed, _last_error,
                    extra={"event": "workspace_query_failed", "backend": "cli",
                           "elapsed_s": elapsed, "timespan": timespan,
                           "reason": _last_error})
        return None
    try:
        rows = json.loads(proc.stdout or "[]")
    except ValueError:
        _last_error = "the query returned something that is not JSON"
        log.warning("workspace query returned unparseable output after %ss", elapsed,
                    extra={"event": "workspace_query_failed", "backend": "cli",
                           "elapsed_s": elapsed, "reason": _last_error})
        return None
    log.debug("workspace query returned %d row(s) in %ss", len(rows), elapsed,
              extra={"event": "workspace_query", "backend": "cli",
                     "rows": len(rows), "elapsed_s": elapsed, "timespan": timespan})
    return rows
