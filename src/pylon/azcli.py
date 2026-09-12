"""Every `az` invocation, with a bound on how long it may take.

The 2026-09-07 nightly ran `pylon analyze` for 37m58s and was killed by the job
timeout. Nine legs read the workspace and eight of them called `subprocess.run`
with no `timeout=`, so a slow tenant, a throttled API or a hung connection blocks
the scan for as long as Azure feels like taking. `rulehealth` was the exception
and had it right; this makes its choice the only choice.

A timeout is reported as a FAILED CALL, not an empty result. Every caller already
branches on `returncode != 0` and turns it into "could not read, and here is why"
-- so a synthetic non-zero return lands in the path that already exists and says
the true thing. An empty stdout would instead read as "the tenant has none of
this", which is the accusation the whole document is built to avoid making.

This is deliberately not the `workspace.query` seam the review proposed. It is the
smallest change that bounds the scan, in one place, and it is where that seam
starts if it gets built.
"""

from __future__ import annotations

import functools
import json
import os
import tempfile
import shutil
import subprocess

# A data-plane query against a real workspace. `rulehealth` chose 120s before
# any of this and it has held; the value lives here now rather than in a default
# argument nobody else could see. Twelve sequential legs at this bound sit inside
# the 30-minute job timeout the nightly runs under, so a stall degrades one leg
# rather than losing the scan.
QUERY_TIMEOUT = 120

# A control-plane read: `az rest`, `az graph query`, `az account`. These answer
# from ARM rather than scanning data, so a slow one is a sick API, not a big
# tenant, and waiting two minutes for it buys nothing.
CONTROL_TIMEOUT = 60

# `timeout` the shell command uses this for a killed process, and nothing in az's
# own range collides with it. Callers only test `!= 0`; this is for a human
# reading a log.
TIMED_OUT = 124
COULD_NOT_RUN = 127

# The scan could not LOOK, as opposed to the service rejecting what it was
# asked. Only the second is evidence about the thing being scanned: a rule whose
# KQL az refuses is faulty, a rule whose query timed out is unjudged. Callers
# that classify a failure test membership here rather than reading the message.
TRANSPORT_FAILURES = frozenset({TIMED_OUT, COULD_NOT_RUN})


# az installs a missing extension on demand, and by default it ASKS first.
# Under `capture_output=True` there is no terminal to answer with, so the ask
# never returns: the first `az graph query` on a machine without the
# `resource-graph` extension sat there until the 60s bound killed it, and the
# scan reported "the call did not finish" -- true, and no help at all in
# working out that an extension was missing.
#
# Turning it off makes az fail immediately with a command-not-found instead,
# which is a reason a caller can print. Set per call rather than with
# `az config set`, because changing a user's global CLI configuration to suit
# this tool is not this tool's business.
#
# Environment name from Microsoft's own rule: config `extension.
# use_dynamic_install` is `AZURE_{section}_{name}` in caps. Their two pages
# disagree on the default -- the configuration page says `no`, the extensions
# page says on since 2.12.0 -- so this states it rather than trusting either.
_NO_DYNAMIC_INSTALL = {"AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no"}


def environment() -> dict[str, str]:
    """The environment az runs in: the caller's, plus what must not be left
    to chance. A copy, so nothing here leaks into this process."""
    return {**os.environ, **_NO_DYNAMIC_INSTALL}


@functools.lru_cache(maxsize=1)
def executable() -> str:
    """The `az` to hand subprocess.

    On Unix this is the string "az" and PATH lookup does the rest.

    On Windows `az` is `az.cmd`, a batch script, and subprocess runs
    CreateProcess with no shell. Python's own documentation is explicit that
    resolving an unqualified name there is not guaranteed -- "for maximum
    reliability, use a fully qualified path for the executable. To search for
    an unqualified name on PATH, use shutil.which()" -- so `["az", ...]` can
    fail to find a perfectly working install. The symptom is the confusing one:
    `az --version` succeeds in the same terminal that Pylon says it cannot run
    az. The same documentation notes batch files given a full path are launched
    by the OS in a system shell, which is what makes the resolved path work.

    Falls back to the bare name when nothing is found, so a missing `az` still
    arrives as this module's ordinary "could not run az" rather than as a
    different error from a different place.

    Cached: this is asked once per az call and the answer cannot change within
    a run.
    """
    if os.name != "nt":
        return "az"
    return shutil.which("az") or "az"


def run(args: list[str], *, timeout: int) -> subprocess.CompletedProcess:
    """`az *args`, captured, bounded, and never raising.

    Returns a CompletedProcess in every case, so a caller's existing
    `if p.returncode != 0` is the whole error path. A timeout and a missing `az`
    both arrive as a failed call carrying a readable reason.
    """
    try:
        return subprocess.run([executable(), *args], capture_output=True,
                              text=True, timeout=timeout, env=environment())
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args, TIMED_OUT, "",
            f"the call did not finish within {timeout}s and was cancelled")
    except OSError as unavailable:
        # `az` missing from PATH, not executable, no fork available. The scan
        # says so rather than dying with a traceback halfway through a leg.
        return subprocess.CompletedProcess(
            args, COULD_NOT_RUN, "", f"could not run az: {unavailable}")


# Two of the commands this tool depends on are not in the core CLI. Microsoft's
# own reference marks them Extension: `az graph query` needs `resource-graph`,
# and `az monitor log-analytics query` -- the read that answers "which tables
# hold data" -- needs `log-analytics`. Neither is obvious from the command
# name, and az reports a missing one as a command it does not recognise, which
# reads like the user typed something wrong.
EXTENSIONS = {"resource-graph": "the resource inventory",
              "log-analytics": "the table-activity read"}


def missing_extension(reason: str) -> str | None:
    """Which extension az is complaining about, or None.

    Matched on az's own vocabulary rather than an exit code, because az uses
    the same code for every command-not-found. Deliberately narrow: it must
    say something is unrecognised AND name the command group that needs an
    extension, so an expired token is not answered with advice about
    extensions.
    """
    low = reason.lower()
    if not any(w in low for w in ("not in the", "is not an az command",
                                  "not found", "unrecognized", "unrecognised",
                                  "misspelled")):
        return None
    if "graph" in low:
        return "resource-graph"
    if "log-analytics" in low or "log analytics" in low:
        return "log-analytics"
    return None


def install_hint(extension: str) -> str:
    """The sentence a reader can act on, for a failure az words badly."""
    purpose = EXTENSIONS.get(extension, "this read")
    return (f"Azure CLI is missing the {extension} extension, which "
            f"{purpose} needs.\n\n  az extension add --name {extension}\n\n"
            f"Then run this again.")


def loads(proc: subprocess.CompletedProcess, default=None):
    """(payload, error) from a finished `az` call. Never raises.

    `run` guarantees a CompletedProcess in every case. Parsing what it returns
    then reintroduced the failure mode `run` exists to prevent: a caller checked
    `returncode != 0`, found zero, and fed stdout straight to `json.loads`. A
    zero exit with output that is not JSON is not hypothetical -- the first
    Windows run hit it on `az graph query`, and the scan died with a
    JSONDecodeError from inside the json module rather than saying which read
    failed and why.

    Both halves of that are wrong. A traceback is not a finding, and dying
    mid-scan throws away the eleven legs that would have worked. So this returns
    a reason, in the shape every caller already branches on.

    Empty stdout is not an error: `default` is what "az said nothing" means for
    this caller -- usually `[]` or `{}` -- and only the caller knows which.
    """
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip()[:300]
        return default, detail or f"az exited {proc.returncode} without a reason"
    text = (proc.stdout or "").strip()
    if not text:
        return default, None
    try:
        return json.loads(text), None
    except json.JSONDecodeError as bad:
        # The first line, because that is where a notice sits when az prepends
        # one to real JSON -- an extension auto-install being the case that
        # found this. Quoting it turns "Expecting value: line 1" into a
        # sentence naming what az actually said.
        head = text.splitlines()[0][:200] if text.splitlines() else ""
        return default, f"az returned output that is not JSON ({bad}): {head!r}"


LOGS_API = "https://api.loganalytics.io"


def flatten(payload: dict) -> list[dict]:
    """The query API's table-of-columns-and-rows, as a list of row dicts.

    `az monitor log-analytics query` returned row dicts and every caller in
    this codebase parses that shape. The REST API returns
    {"tables": [{"columns": [...], "rows": [[...]]}]} instead, so this converts
    rather than making twelve legs learn a second shape.

    Only the first table. A KQL query returns one result table unless it uses
    a fork or a batch, and nothing here does.
    """
    tables = payload.get("tables") or []
    if not tables:
        return []
    table = tables[0]
    names = [c.get("name") for c in (table.get("columns") or [])]
    return [dict(zip(names, row)) for row in (table.get("rows") or [])]


def query(workspace_guid: str, kql: str,
          timeout: int | None = None) -> subprocess.CompletedProcess:
    """A Log Analytics query, bounded. The shape eight legs were repeating.

    Goes through `az rest` and the Logs query API rather than through
    `az monitor log-analytics query`, because that command rejects valid KQL.
    Azure/azure-cli-extensions#5147 -- "very picky about kusto queries" -- is
    open and in their backlog, and on a real tenant it refused every rule that
    opens with a `let` statement. That is 24 of 26 rules, all reported as
    `broken`, which reads as an accusation about the customer's detections and
    was a defect in the CLI.

    The KQL goes in a JSON body written to a FILE. It is the argument that
    broke, and a query containing quotes, newlines and semicolons has no
    business on a command line at all -- Microsoft's own documentation shows
    the payload-file form for exactly this call.

    Returns a CompletedProcess whose stdout carries the same row-dict JSON the
    old command produced, so no caller changes. The default is read here and
    not in the signature: `timeout=QUERY_TIMEOUT` as a default argument binds
    the value at import, so setting `azcli.QUERY_TIMEOUT` afterwards changes
    nothing while looking like it does -- which is how the first attempt to
    demonstrate the timeout fix hung for two minutes against a stub.
    """
    bound = QUERY_TIMEOUT if timeout is None else timeout
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8")
    try:
        json.dump({"query": kql}, handle)
        handle.close()
        proc = run(["rest", "--method", "post",
                    "--uri", f"{LOGS_API}/v1/workspaces/{workspace_guid}/query",
                    "--resource", LOGS_API,
                    "--headers", "Content-Type=application/json",
                    "--body", f"@{handle.name}"], timeout=bound)
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            # A temp file that will not delete is not a reason to lose a
            # measurement that already succeeded.
            pass

    if proc.returncode != 0:
        return proc
    payload, error = loads(proc, default={})
    if error:
        return subprocess.CompletedProcess(proc.args, 1, "", error)
    return subprocess.CompletedProcess(
        proc.args, 0, json.dumps(flatten(payload or {})), proc.stderr)