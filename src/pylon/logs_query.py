"""Log Analytics queries through the SDK rather than a subprocess per query.

`validate` shells out to `az monitor log-analytics query`, which is deliberate:
it keeps the free commands runnable on a base install, where the SDK is not
present (see tests/test_reachable_from_the_cli.py). That choice costs 115 MB and
1.7 s of process startup FOR EVERY QUERY, which is invisible for the two queries
a `pylon validate` run makes and expensive for anything that sweeps -- a
verification pass over ten detections is twenty processes.

It also swallows the reason a query failed. `az` writes Azure's explanation to
stderr and the caller keeps only the exit code, so a detection ending in a
semicolon reported "the count query did not run" while Azure had actually said

    Query could not be parsed at '|' on line [60,1]

which is the whole answer, thrown away.

So this module is the SDK path, imported lazily and falling back to the CLI when
the SDK is absent. It lives apart from `validate` because that module is on the
free list and may not import anything from the `design` extra.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus

# What `parse_window` and `timespan_between` produce: the four KQL durations as
# ISO 8601, or an explicit "<start>/<end>" pair.
_DURATION = re.compile(r"^P(?:(\d+)D|T(?:(\d+)H|(\d+)M|(\d+)S))$")


class BadTimespan(ValueError):
    """The timespan string could not be read as a duration or an interval."""


def to_timespan(spec: str):
    """An ISO duration or `start/end` pair -> what the SDK's `timespan` wants."""
    if "/" in spec:
        start, end = spec.split("/", 1)
        return (datetime.fromisoformat(start.replace("Z", "+00:00")),
                datetime.fromisoformat(end.replace("Z", "+00:00")))
    hit = _DURATION.match(spec.strip())
    if not hit:
        raise BadTimespan(f"{spec!r} is neither an ISO duration nor start/end")
    days, hours, minutes, seconds = hit.groups()
    return timedelta(days=int(days or 0), hours=int(hours or 0),
                     minutes=int(minutes or 0), seconds=int(seconds or 0))


_client: LogsQueryClient | None = None


def _shared_client() -> LogsQueryClient:
    """One client, one credential, for the life of the process. Building a
    credential per query is most of what the subprocess was paying for."""
    global _client
    if _client is None:
        _client = LogsQueryClient(DefaultAzureCredential())
    return _client


def query(workspace_guid: str, kql: str, timespan: str) -> tuple[list[dict] | None, str]:
    """(rows, detail). rows is None when the query could not RUN, and `detail`
    then carries Azure's own words rather than an exit code."""
    try:
        result = _shared_client().query_workspace(
            workspace_id=workspace_guid, query=kql, timespan=to_timespan(timespan))
    except Exception as exc:  # noqa: BLE001 - the caller decides what a failure means
        return None, _reason(exc)

    if result.status == LogsQueryStatus.FAILURE:
        return None, str(getattr(result, "partial_error", None) or "query failed")
    tables = result.tables if result.status == LogsQueryStatus.SUCCESS else result.partial_data
    rows: list[dict] = []
    for table in tables or []:
        names = [str(c) for c in table.columns]
        rows += [dict(zip(names, row)) for row in table.rows]
    return rows, ""


def _reason(exc: Exception) -> str:
    """Azure's explanation, deepest first, not the exception's class name.

    The useful sentence is nested two levels down and the top level is the
    useless "The request had some invalid properties":

        error.message      The request had some invalid properties
        .innererror        A recognition error occurred in the query.
        .innererror        Query could not be parsed at '|' on line [2,1]

    The outermost link is an object with attributes and every link below it is a
    plain dict, so both shapes have to be walked. Reading only attributes stops
    at the first level and reports the sentence that says nothing -- which is
    what this function did until it was run against the real service.

    The deepest message leads, because that is the one naming the line.
    """
    def field(link, name):
        if isinstance(link, dict):
            return link.get(name)
        return getattr(link, name, None)

    link, seen = getattr(exc, "error", None), []
    while link is not None and len(seen) < 4:
        message = field(link, "message")
        if message and str(message) not in seen:
            seen.append(str(message))
        link = field(link, "innererror")
    if not seen:
        return f"{type(exc).__name__}: {exc}"
    return " | ".join(reversed(seen))
