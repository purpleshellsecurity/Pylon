"""Offline KQL verification via the kustainer engine (F4).

Static validation (regex over known-bad patterns) is structurally blind to a
novel fabricated column — `ActorRiskScore`, `SourceGeo` hit no rule and pass. The
real KQL engine is not: declare the table as an empty typed ``datatable`` and run
the query against it, and any unresolved column or type mismatch fails with the
engine's own error. No tenant, no data — runnable in CI.

Run the engine as a container and point PYLON_KUSTAINER_URL at it:

    docker run -d --name pylon-kustainer -e ACCEPT_EULA=Y -m 4G -p 8080:8080 \\
        mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
    export PYLON_KUSTAINER_URL=http://localhost:8080

The licence is accepted through the ACCEPT_EULA environment variable. Passing
`--accept-license` as a container ARGUMENT, which this comment used to say, is
not read at all: the container exits 13 with "EULA Not Accepted" and the only
sign is `docker logs`, since a stopped container looks the same as one that was
never started.

On Apple silicon the image is amd64-only and needs Rosetta, not QEMU. Under
colima's default QEMU the Kusto process burned eleven minutes of CPU without
ever binding its port; under Rosetta it starts in about three seconds:

    colima start --vm-type vz --vz-rosetta --cpu 4 --memory 8
    docker run -d --name pylon-kustainer --platform linux/amd64 \\
        -e ACCEPT_EULA=Y -e DOTNET_EnableWriteXorExecute=0 \\
        -m 6G -p 8080:8080 \\
        mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest

`DOTNET_EnableWriteXorExecute=0` is required, not optional: without it Rosetta
kills the process seconds after it reports "answering queries", with
`rosetta error: rt_tgsigqueueinfo failed in pend_signal: 11`. Do NOT also set
`DOTNET_TieredCompilation=0` -- it makes the first query take three minutes to
JIT. Warm queries answer in tens of milliseconds either way, so give the FIRST
request a generous timeout and judge nothing by it.

The default executor POSTs to ``<url>/v1/rest/query``. It is injectable so the
script-building and result-parsing logic is unit-tested without a container.

TWO THINGS MEASURED ON 2026-09-12, both of which change how a caller should use
this:

IT REPORTS NO REASON. A refused query comes back as `General_BadRequest` and a
request id, 238 bytes, and nothing else -- identical for a syntax error and for
an unresolved column, on /v1 and /v2 alike, with no header or client-request
property that unlocks detail and nothing in the container logs. So this is a
pass/fail gate. It says a query is broken, never why, and a caller must not
present its output as guidance.

ROSETTA STILL KILLS IT, with `DOTNET_EnableWriteXorExecute=0` set exactly as
above. The container started in 3.9s, answered five queries, then died with
`rosetta error: rt_tgsigqueueinfo failed in pend_signal: 11` and exit 133. The
env var does not prevent the crash; it may only delay it. Treat the endpoint as
something that can vanish mid-run, which is why `verify_query_offline` returns
ran=False on a transport failure rather than raising, and why a caller must
read `ran` before `ok`.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from functools import lru_cache
from importlib import resources

from .models import OfflineCheck

# Our schema type strings -> Kusto scalar types for a datatable declaration.
_KUSTO_TYPE = {
    "string": "string", "int": "int", "long": "long", "real": "real",
    "double": "real", "bool": "bool", "boolean": "bool", "datetime": "datetime",
    "dynamic": "dynamic", "guid": "guid", "decimal": "decimal", "timespan": "timespan",
}


def _kusto_type(t: str) -> str:
    """Map a schema type string to a Kusto scalar type (default string)."""
    return _KUSTO_TYPE.get((t or "").strip().lower(), "string")


# Sentinel-only constructs and their documented offline equivalents.
#
# `_GetWatchlist` is a Microsoft Sentinel function, not KQL, so a bare engine
# rejects the query outright -- and the exclusion scaffolding the detection
# prompt marks REQUIRED opens every compliant query with it. Left alone, the
# offline gate therefore fails exactly the detections that followed the house
# rule, and passes the ones that ignored it. That is the gate running backwards,
# and it is silent: kustainer answers a rejected batch with "Request is invalid"
# and no line number.
#
# The substitution is not invented. Each generated query already carries its own
# fallback on the following line, commented out and written by the same asset:
#
#     let AllowedActors = _GetWatchlist('ApprovedAutomation') | project SearchKey;
#     // let AllowedActors = dynamic([]);  // fallback: no watchlist in this tenant
#
# so this swaps in the fallback the query itself declares. An empty watchlist is
# also the right semantics for the check: the datatable is empty, nothing is
# excluded, and what is under test is whether the query RESOLVES.
_SENTINEL_ONLY = (
    # `_GetWatchlist('x') | project SearchKey` -> the authored empty fallback.
    (re.compile(r"_GetWatchlist\s*\([^)]*\)\s*\|\s*project\s+\w+", re.IGNORECASE),
     "dynamic([])"),
    (re.compile(r"_GetWatchlist\s*\([^)]*\)", re.IGNORECASE), "dynamic([])"),
)


def substitute_sentinel_functions(kql: str) -> str:
    """Replace Sentinel-only functions with the offline equivalents the query
    itself documents. Returns `kql` unchanged when it uses none."""
    for pattern, replacement in _SENTINEL_ONLY:
        kql = pattern.sub(replacement, kql)
    return kql


def build_check_script(kql: str, table: str, schema: dict[str, str]) -> str:
    """Prepend `let <table> = datatable(col:type, ...) [];` so the query runs
    against an empty, correctly-typed stand-in for the real table. A column the
    query references that isn't in `schema` is unresolved -> the engine errors.
    Columns Sentinel always injects (TimeGenerated/Type/_ResourceId) are added if
    the schema omits them, so their absence never masks a real fabrication.
    Sentinel-only functions are swapped for their documented offline fallbacks
    first -- see `_SENTINEL_ONLY`."""
    kql = substitute_sentinel_functions(kql)
    cols = dict(schema)
    for injected, typ in (("TimeGenerated", "datetime"), ("Type", "string"), ("_ResourceId", "string")):
        cols.setdefault(injected, typ)
    decl = ", ".join(f"{name}:{_kusto_type(typ)}" for name, typ in cols.items())
    return f"let {table} = datatable({decl}) [];\n{kql}"


@lru_cache(maxsize=1)
def _vendored_column_types() -> dict[str, dict[str, str]]:
    """{table: {column: type}} vendored from Azure Monitor's table reference by
    `scripts/refresh-table-column-types.py`. Empty when the file is absent."""
    try:
        raw = (resources.files("pylon.catalog") / "table-column-types.json").read_text(
            encoding="utf-8")
        return json.loads(raw)
    except (FileNotFoundError, ModuleNotFoundError, OSError, ValueError):
        return {}


def schema_for_table(table: str) -> dict[str, str]:
    """Best available typed schema for a table, most authoritative source first.

    The last resort types every column `string`, and that is not a neutral
    default -- it is the source of two failures that make this whole gate
    useless. A name list is always SHORTER than the real table (AzureActivity:
    16 names against 37 real columns), so a query using a real column the list
    omits is rejected as unresolved, by the gate that exists to catch fabricated
    ones. And a `dynamic` column declared `string` breaks exactly the queries
    that matter: AuditLogs `InitiatedBy` and `TargetResources` are both dynamic,
    and the Entra rules require an `mv-expand` over one of them.

    So the vendored reference types sit ahead of the name list, and the name list
    stays only as the answer for a table the reference does not carry.
    Empty dict when the table is unknown — the caller can skip it.
    """
    try:
        from .catalog import service_files

        for svc in service_files().values():
            entry = svc.get("tables", {}).get(table)
            if entry and entry.get("columns"):
                return dict(entry["columns"])
    except (ImportError, OSError, ValueError):
        pass  # catalog optional; fall through to the vendored reference
    typed = _vendored_column_types().get(table)
    if typed:
        return dict(typed)
    try:
        from .validation.schemas import TABLE_SCHEMAS

        cols = TABLE_SCHEMAS.get(table)
        if cols:
            return {c: "string" for c in cols}
    except (ImportError, KeyError):
        pass
    return {}


def _http_executor(url: str) -> Callable[[str], tuple[bool, str]]:
    """Default executor: POST the script to a kustainer REST endpoint. Returns
    (ok, error). A non-200 or a Kusto error payload -> (False, message)."""

    def run(script: str) -> tuple[bool, str]:
        import httpx

        endpoint = url.rstrip("/") + "/v1/rest/query"
        body = {"db": "NetDefaultDB", "csl": script}
        try:
            res = httpx.post(endpoint, json=body, timeout=20.0)
        except httpx.HTTPError as exc:
            return False, f"{type(exc).__name__}: {exc}"
        if res.status_code != 200:
            # Kusto returns the semantic error (unresolved column, type mismatch) here.
            detail = res.text
            try:
                detail = json.loads(res.text).get("error", {}).get("message", res.text)
            except (ValueError, AttributeError):
                pass
            return False, f"HTTP {res.status_code}: {detail}"
        return True, ""

    return run


def verify_query_offline(
    kql: str,
    table: str,
    schema: dict[str, str],
    *,
    executor: Callable[[str], tuple[bool, str]] | None = None,
    url: str | None = None,
) -> OfflineCheck:
    """Run `kql` against an empty typed datatable for `table` in the offline KQL
    engine. `executor` is injectable for testing; otherwise a kustainer endpoint is
    used (arg `url` or PYLON_KUSTAINER_URL). ran=False when no engine is configured."""
    if executor is None:
        url = url or os.environ.get("PYLON_KUSTAINER_URL", "")
        if not url:
            return OfflineCheck(ran=False, error="no kustainer endpoint (set PYLON_KUSTAINER_URL)")
        executor = _http_executor(url)

    script = build_check_script(kql, table, schema)
    try:
        ok, error = executor(script)
    except Exception as exc:  # noqa: BLE001 — an executor failure must not crash the run
        return OfflineCheck(ran=False, error=f"{type(exc).__name__}: {exc}")
    return OfflineCheck(ran=True, ok=ok, error="" if ok else error)
