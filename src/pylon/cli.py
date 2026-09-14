"""Three verbs, and the boundary between them is what each one is allowed to claim.

    analyze     read the tenant. What is logging, what is detecting, what is
                exposed. Measurement only: every figure comes from something
                this run observed, and a verdict with nothing behind it is the
                one thing the documents refuse to carry.

    recommend   decide about CONTENT. Which Content Hub solutions to connect,
                update, install or remove, and which rule templates are
                installed and never switched on. Reads `analyze`'s output and
                recomputes nothing.

    design      write what does not exist. Takes a platform and a service and
                generates KQL against a grounded catalogue.

    config      store the settings the other three need, in a file readable
                only by its owner.

The line between `analyze` and `recommend` is the one that keeps getting
re-crossed, so it is stated here: **analyze reports state, recommend reports
decisions about content.** A Defender plan being off is state. A solution
shipping 73 rule templates with none enabled is a decision. Putting plan state
into `recommend` is what made the report argue with itself twice.

`design` is the only verb that costs money, which is why the agent stack is an
optional install (`pip install pylon[design]`) and why this module imports it
lazily. `analyze` and `recommend` must run on a machine with no model provider
configured -- a scan that needs an LLM SDK to say which tables are dark has the
wrong shape.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
import textwrap
import time
from pathlib import Path

import yaml

from . import config, logs
from .reportkit import plural

_cli_log = logs.get_logger(__name__)

# Secrets are never printed. `show` needs to prove a key is set without
# disclosing it, and the last four characters are enough to tell two keys apart
# while being useless on their own.
_SECRET = ("KEY", "SECRET", "TOKEN", "PASSWORD")


def _redact(key: str, value: str) -> str:
    if any(m in key.upper() for m in _SECRET):
        return f"set, ends {value[-4:]}" if len(value) > 8 else "set"
    return value


def _analyze(args: argparse.Namespace) -> int:
    from . import inventory, report
    rc = inventory.run(args.workspace)
    if rc:
        return rc
    return report.main()


def _recommend(args: argparse.Namespace) -> int:
    """Render the Content Hub decisions from an existing scan.

    Deliberately does NOT re-scan. `report_detections` refuses to render
    recommendations built from a different scan than the analysis beside them,
    and re-running the tenant read here would paper over exactly the drift that
    check exists to catch.
    """
    from . import report_detections
    return report_detections.main()


def _validate(args: argparse.Namespace) -> int:
    """`pylon validate`: run a written detection against the workspace.

    Read-only, and the three outcomes are kept apart deliberately. A search that
    could not run is NOT a detection that found nothing -- reporting it as one is
    how a broken query gets read as a quiet tenant.
    """
    from datetime import datetime, timezone

    from . import validate

    try:
        kql = sys.stdin.read() if args.kql == "-" else Path(args.kql).read_text(encoding="utf-8")
    except OSError as unreadable:
        print(f"could not read {args.kql}: {unreadable}", file=sys.stderr)
        return 2
    if not kql.strip():
        print("the detection is empty — nothing to search for", file=sys.stderr)
        return 2

    def _as_utc(text: str):
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp

    try:
        if args.start or args.end:
            if not (args.start and args.end):
                print("--start and --end go together; use --window for a "
                      "relative lookback", file=sys.stderr)
                return 2
            timespan = validate.timespan_between(_as_utc(args.start), _as_utc(args.end))
            # What they typed, not what the API wants. `PT1H` is ISO 8601 and
            # means nothing to the person who wrote `--window 1h`.
            window = f"{args.start} to {args.end}"
        else:
            timespan = validate.parse_window(args.window)
            window = f"the last {args.window}"
    except validate.BadWindow as bad:
        print(f"{bad}", file=sys.stderr)
        return 2
    except ValueError as bad:
        print(f"not a date: {bad}", file=sys.stderr)
        return 2

    _tenant, _arm, guid = validate.resolve(args.workspace)
    hits, sample, detail = validate.hunt(kql, guid, timespan)

    if hits is None:
        print(f"NOT SEARCHED  {detail}", file=sys.stderr)
        return 1

    if not hits:
        print(f"no hits in {window}")
        caveat = validate.residual_time_bound(kql)
        if caveat:
            print(f"  note: {caveat}")
        return 0

    shown = f", showing {len(sample)}" if hits > len(sample) else ""
    print(f"HITS  {hits:,} row(s) in {window}{shown}")
    for row in sample:
        print("  " + _row_line(row))
    return 0


def _tabledrift(args: argparse.Namespace) -> int:
    """`pylon tabledrift`: has Azure changed under `tablemap.TABLE_MAP`?

    Read-only, and exits non-zero on drift so a scheduled run can raise it
    without anyone reading the log. A type that could not be READ is not drift
    and does not fail the run -- it is reported and the exit code stays 0,
    because failing on an unreadable type trains people to ignore the failure.
    """
    import json

    from . import inventory, tabledrift

    try:
        rows = inventory.query_graph()
    except RuntimeError as unreadable:
        # 2, not 1. A caller that cannot tell "the map drifted" from "the check
        # never ran" will raise the same alarm for a lapsed `az login` as for a
        # real finding, and a monthly job that cries wolf gets muted.
        print(f"NOT CHECKED  could not list resources: {unreadable}", file=sys.stderr)
        return 2

    findings = tabledrift.survey(tabledrift.representatives(rows))
    print(tabledrift.render(findings))
    if args.json:
        Path(args.json).write_text(
            json.dumps([f.public() for f in findings], indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 1 if any(f.drifted for f in findings) else 0


# Read in this order when the row has them. A Sentinel row is 40-odd columns of
# which most are empty, and dumping it alphabetically buried when/who/what under
# ActivityStatus and ActivitySubstatus -- both blank -- on the first real run.
_FIRST = ("TimeGenerated", "OperationNameValue", "OperationName", "Operation",
          "Caller", "AccountUpn", "ActorUpn", "UserId", "InitiatedBy",
          "CallerIpAddress", "CallerIPAddress", "IPAddress",
          "ResultType", "ActivityStatusValue", "ResourceId", "_ResourceId")


def _row_line(row: dict, width: int = 200) -> str:
    """One matched row, as the columns a person reads first.

    Empty values are dropped rather than printed: a blank column says nothing
    about why the row matched, and it costs the width a populated one needs.
    """
    if not isinstance(row, dict):
        return str(row)[:width]
    filled = {k: v for k, v in row.items() if v not in (None, "", [], {})}
    ordered = [k for k in _FIRST if k in filled]
    ordered += [k for k in filled if k not in _FIRST]

    out, used = [], 0
    for key in ordered:
        text = str(filled[key])
        if len(text) > 60:
            text = text[:57] + "..."
        piece = f"{key}={text}"
        if used + len(piece) + 2 > width:
            out.append(f"(+{len(ordered) - len(out)} more)")
            break
        out.append(piece)
        used += len(piece) + 2
    return "  ".join(out)


def _engine():
    """Import the generation half, or explain why it is not there.

    Probes by importing the MODULE, not a symbol. An earlier version imported a
    name that does not exist, so a correctly installed agent stack reported
    itself as missing -- a check that fails for a reason it does not name is
    worse than no check.
    """
    try:
        from . import engine
    except ImportError as exc:
        print(f"design needs the agent stack ({exc}): "
              "pip install 'pylon[design]'", file=sys.stderr)
        return None
    return engine


def _design_list(args: argparse.Namespace) -> int:
    """What can be targeted, or a run's detections.

    Two shapes, because they answer different questions. Bare, it lists the
    targets -- one line each, which is what a list is for. Named, it explains ONE
    target: its tables, the column and operator a filter needs, and real
    operation strings.

    It printed the explanation for all fourteen at once to begin with. That is a
    reference page, not a list: about 130 lines of output to answer "what can I
    run", and the answer scrolled off the top before the question was read.

    Never a list retyped here. The first version of this CLI hardcoded its
    targets from a docstring, and two went unreachable with no error. It reads
    the catalogue, so a target that stops being grounded stops being printed.
    """
    if args.source:
        from pathlib import Path

        from .models import EngineReport
        src = Path(args.source) / "report.json"
        if not src.is_file():
            # Same directory, one step earlier. Showing the plan is more useful
            # than refusing, and it is the list `design detections --pick` counts
            # against, so the numbers printed here are the ones to type next.
            plan = _load_plan(args.source)
            if plan is None:
                return 2
            print(f"{plan.service}: no detections built yet; "
                  f"{len(plan.attack_vectors)} vector(s) planned\n")
            _show_plan(plan, sys.stdout)
            print(f"\n  next   pylon design detections --from {args.source} "
                  f"--pick ... --out {args.source}")
            return 0
        report = EngineReport.model_validate_json(src.read_text())
        print(f"{report.platform} / {report.service}: "
              f"{len(report.detections)} detection(s)\n")
        _show_detections(report.detections)
        return 0

    from .catalog import table_techniques
    from .services import (operation_column, operation_match,
                           operation_vocabulary, resolve_target, tables_for,
                           targets)

    def detail(target) -> None:
        """One target, in full. Azure names the same thing three ways and none
        can be guessed from the others: the resource type you own, the table it
        writes to, and the string you filter on. All three, read from the
        catalogue -- nothing here is a second copy that can drift from the run."""
        print(target.key)
        if target.label != target.key:
            print(f"    {target.label}")
        for table in tables_for(target.key):
            # A table can reach a target through its CONTRACT before it has a
            # technique-map entry -- AppServiceFileAuditLogs did, the moment it
            # was measured -- and `entry()` returns None for one that has not.
            # Dereferencing it crashed `design list` for the whole target, so a
            # newly measured table took the command down rather than appearing
            # in it without a plane label.
            entry = table_techniques.entry(table)
            plane = {"control": "control plane", "data": "data plane",
                     "identity": "the directory itself"}.get(
                         getattr(entry, "plane", ""), "")
            operator, why = operation_match(table)
            vocab = operation_vocabulary(target.resource_type, table,
                                         target.entra_category)

            print(f"      {table}" + (f"   ({plane})" if plane else ""))
            print(f"        filter on   {operation_column(table)} {operator} \"...\""
                  + (f"   ({why})" if why else ""))
            if vocab:
                print(f"        grounded on {len(vocab)} known operation(s), "
                      "spelled like:")
                for sample in vocab[:3]:
                    print(f'                      "{sample}"')
            else:
                print("        grounded on nothing -- no operation list")
        for refusal in target.refused:
            print(f"      NOT QUERIED {refusal}")
        print(f"\n    run   pylon design detections {target.key}\n")

    typed = " ".join(args.target) if isinstance(args.target, list) else (args.target or "")
    if typed.strip():
        target = resolve_target(typed)
        if target is None:
            print(f"{typed.strip()!r} is not a target this tool can ground.\n",
                  file=sys.stderr)
            # An AMBIGUOUS name is a different failure from an unknown one, and
            # the catalogue has always been able to tell them apart: `storage`
            # means four resource types and `nonsense` means none. That answer
            # existed, was exported, and reached nobody -- so every ambiguous
            # name got the same "not a target" wall as a typo.
            for candidate in _candidates(typed):
                print(f"  did you mean {candidate}?", file=sys.stderr)
            _supported()
            return 2
        detail(target)
        return 0

    # Bare: the accepted values, one per line, and nothing else on stdout. It is
    # the answer to "what may I type", so it is the values themselves -- greppable
    # and pipeable, `pylon design list | fzf` being the obvious use.
    #
    # It carried a tables column and a two-line footer before this. Both were
    # answering a question nobody asked at the menu, and both made the output
    # something you read rather than something you pick from.
    # `Entra` is the whole directory and the rest are slices of it. Sorted
    # plainly it lands LAST, after eleven `Entra Something` rows, where it reads
    # as a stray line with nothing beside it -- a clean-room reader called it a
    # formatting artifact and then could not reconcile 24 visible rows with the
    # 25 that `design coverage` counts. Putting a parent above its children is
    # the whole fix, and it keeps every line a bare value, which is what makes
    # this pipeable.
    def _parent_first(key: str) -> tuple[str, int, str]:
        resolved = resolve_target(key).key
        head = resolved.split(" ")[0]
        return (head.lower(), 0 if " " not in resolved else 1, resolved.lower())

    for key in sorted(targets(), key=_parent_first):
        print(resolve_target(key).key)
    # Where to get more, on stderr so a pipe still receives only values.
    print("\n  pylon design list <value>         what it queries and the "
          "operation strings\n"
          "                                    it grounds against\n"
          "  pylon design detections <value>   design detections for it",
          file=sys.stderr)
    return 0


# How a detection's table was established, shown next to it. Only "deployed" is
# silent: a confirmed table is the expected case and needs no annotation, while
# the other two are claims the reader has to check.
_BASIS_MARK = {
    "deployed": "",
    "catalogue": "  [table not in the scanned workspace]",
    "unchecked": "  [table unconfirmed]",
}


def _show_detections(detections) -> None:
    for n, det in enumerate(detections, 1):
        mark = "" if det.valid else "  [did not validate]"
        basis = _BASIS_MARK.get(getattr(det, "table_basis", "unchecked"), "")
        print(f"  {n:>2}  {det.detection.mitre_technique:<10} "
              f"{det.detection.vector_name}{mark}{basis}")

    # Once, after the list, with the reason. A per-line marker is enough to
    # notice; it is not enough to act on.
    from . import deployed as deployed_mod
    unconfirmed = {}
    for det in detections:
        how = getattr(det, "table_basis", "unchecked")
        if how != "deployed":
            unconfirmed.setdefault((det.log_table, how), 0)
            unconfirmed[(det.log_table, how)] += 1
    for (table, how), count in sorted(unconfirmed.items()):
        print(f"\n  ! {count} detection(s): {deployed_mod.note(table, how)}")


def _supported(stream=None) -> None:
    """Print every target a user can type. Reached from a bad target and from
    `design list --short`, so the two can never disagree about what is offered."""
    from .services import targets
    out = stream or sys.stderr
    print("supported targets:", file=out)
    for target in targets().values():
        print(f"    {target.key}", file=out)
    print("\nfull detail, including the tables each one queries: "
          "pylon design list", file=out)


def _resolve_target(args) -> "object | None":
    """The Azure resource type the user typed, or None with the reason printed.

    Azure's own casing is inconsistent between its documentation, its ARM
    responses and its operation names, so the match is case-insensitive and the
    canonical spelling comes back from the catalogue rather than from what was
    typed.
    """
    from .services import resolve_target
    # `nargs="*"` so `Entra RoleManagement` survives an unquoted shell. Joining
    # is also what makes a quoted one work, so both spellings mean the same thing.
    raw = args.target
    typed = (" ".join(raw) if isinstance(raw, list) else (raw or "")).strip()
    if not typed:
        print("a target is required: an Azure resource type, or `Entra`.",
              file=sys.stderr)
        _supported()
        return None
    target = resolve_target(typed)
    if target is None:
        print(f"{typed!r} is not a target this tool can ground.\n"
              "Azure publishes 14,850 resource types; a detection needs one whose "
              "operations are\nall accounted for, and 14 are.\n", file=sys.stderr)
        _supported()
        return None
    return target


def _show_plan(analysis, stream=None) -> None:
    """The plan, numbered, so a `--pick` can name a line.

    Defaults to stderr because most callers print it beside an error. `design
    list` asks for stdout: there the listing is the result, and a result that
    cannot be piped is half a result.
    """
    out = stream or sys.stderr
    for n, v in enumerate(analysis.attack_vectors, 1):
        print(f"  {n:>2}  {v.mitre_technique:<10} {v.name}", file=out)
        print(f"      {v.log_table} / {v.operation}", file=out)


def _version_line() -> str:
    """Version, and the directory it is running from.

    There was no way to tell which build produced an output. Four playbook runs
    in a row were read as evidence about code that was not installed -- the
    changes were pushed, the tool was not reinstalled, and nothing in the output
    said so. The path matters as much as the number: a repo checkout and a
    `uv tool install` can differ while both report the same version.
    """
    from pathlib import Path

    from . import __version__

    return f"pylon {__version__}\nrunning from {Path(__file__).resolve().parent}"


def _load_plan(source: str):
    """The plan a `design plan` run wrote, or None with the reason printed."""
    from pathlib import Path

    from .models import ThreatAnalysis
    src = Path(source) / "plan.json"
    if not src.is_file():
        print(f"no plan.json in {source} — run `pylon design plan` there first.",
              file=sys.stderr)
        return None
    try:
        return ThreatAnalysis.model_validate_json(src.read_text())
    except Exception as exc:                       # noqa: BLE001 — a bad file is user input
        print(f"{src} is not a readable plan: {exc}", file=sys.stderr)
        return None


def _design_plan(args: argparse.Namespace) -> int:
    """Phase 1 alone: what this tool proposes to build, before it builds it.

    Phase 2 is the whole bill. A measured Key Vault run made 102 model calls and
    101 of them were per-vector work on a list nobody had looked at -- $5.83 and
    fifty-five minutes to find out what was on offer. This shows the offer for the
    price of one call, and `design detections --from` builds only the picks.

    It also makes the run-to-run drift visible instead of expensive: the same
    target enumerated 55 vectors one run and 40 the next, so two plans can be
    diffed rather than two bills.
    """
    args.pick = "none"              # stop after Phase 1
    return _design_detections(args)


def _unconfirmed(have: frozenset[str] | None, tables: list[str]) -> str:
    """Why this run must not proceed, or "" when the tables are confirmed.

    Two different failures with one remedy. No scan at all, and a scan that
    looked and found none of this target's tables holding data. The second is
    the one worth stopping for: a detection over a table with no rows cannot be
    graded, so the run would cost money to produce work nothing can check.
    """
    if have is None:
        return ("refusing to build: no scan confirms these tables exist.\n"
                "  run `pylon analyze` first, or pass --unconfirmed-tables to "
                "build anyway")
    missing = [t for t in tables if t not in have]
    if len(missing) == len(tables):
        return ("refusing to build: the scan found no data in "
                f"{', '.join(missing)}.\n"
                "  a detection over an empty table cannot be graded. Enable the "
                "diagnostic\n"
                "  setting and rescan, or pass --unconfirmed-tables to build "
                "anyway")
    return ""


def _design_detections(args: argparse.Namespace) -> int:
    """Phases 1 and 2: threat analysis, then a detection per attack vector."""
    engine = _engine()
    if engine is None:
        return 2
    # A plan records the target it was made for, so `--from` does not ask again --
    # and must not, because a plan built for one resource cannot be applied to
    # another. The saved value is preferred over anything typed.
    source = getattr(args, "source", "")
    typed_target = args.target
    if isinstance(typed_target, list):
        typed_target = " ".join(typed_target)
    if source and not (typed_target or "").strip():
        peek = _load_plan(source)
        if peek is None:
            return 2
        args.target = getattr(peek, "target", "") or peek.service
    target = _resolve_target(args)
    if target is None:
        return 2
    import asyncio

    # A saved plan, when `--from` names one. Phase 1 is one model call of the
    # hundred a run makes, but it is also five minutes of waiting, and re-running
    # it would give a DIFFERENT list -- 55 vectors one run and 40 the next on
    # identical input -- so the picks you made would no longer point at the same
    # things.
    plan, selection = None, getattr(args, "pick", "") or ""
    if source:
        plan = _load_plan(source)
        if plan is None:
            return 2
        if not selection:
            print(f"--pick is required with --from. {len(plan.attack_vectors)} "
                  f"vector(s) in the plan; `--pick all` builds every one.",
                  file=sys.stderr)
            _show_plan(plan)
            return 2


    from . import console
    print(f"\n{console.heading('DESIGN', sys.stderr)}   {target.key}\n", file=sys.stderr)
    print(f"  {'name':<14}{target.label}", file=sys.stderr)
    print(f"  {'provider':<14}{os.environ.get('PYLON_PROVIDER', 'openai')}",
          file=sys.stderr)
    print(f"  {'pylon':<14}{_version_line().splitlines()[0].removeprefix('pylon ')}",
          file=sys.stderr)
    print(f"  {'cost cap':<14}${args.max_cost:.2f}", file=sys.stderr)

    # What this tenant actually has, so the table a detection names can be
    # CONFIRMED rather than assumed. Absent evidence is not an error -- writing
    # a detection for a service you have not deployed yet is a normal thing to
    # do -- but it changes what the output is allowed to claim.
    from . import deployed as provisioned_tables
    have, why = provisioned_tables.from_analysis()
    print(f"  {'tables':<14}{why}", file=sys.stderr)
    # Which table a category lands in is decided by logAnalyticsDestinationType
    # on the diagnostic setting, and the scan already read it. The surface list
    # comes from a fixed overlay entry, so the two can disagree -- and when they
    # do, every detection is generated against a table this tenant does not
    # fill. The workspace gate then grades them no-match, which reads as "the
    # attack did not happen" rather than "you are querying the wrong table".
    if target.resource_type:
        observed, why = provisioned_tables.destination_tables(target.resource_type)
        if observed:
            elsewhere = [s.table for s in target.surfaces
                         if s.table != "AzureActivity" and s.table not in observed]
            if elsewhere:
                print(f"  {'destination':<14}scan says this tenant fills "
                      f"{', '.join(sorted(observed))} ({why})", file=sys.stderr)
                for table in elsewhere:
                    print(f"  {'':<14}WARNING {table} is in the surface list and the "
                          f"scan saw nothing land there", file=sys.stderr)

    building = getattr(args, "pick", "") != "none"
    if building and not getattr(args, "unconfirmed_tables", False):
        refusal = _unconfirmed(have, list(target.tables) or ["AuditLogs"])
        if refusal:
            print(f"\n{refusal}", file=sys.stderr)
            return 2

    # Which surfaces this run reads, and which it cannot, said BEFORE the money
    # is spent. The refusals are the half that matters: a run against
    # Microsoft.Web/sites reads the control plane and nothing else, and six App
    # Service data-plane tables are the reason -- none of them has an operation
    # vocabulary to check a query against. Printing the surfaces and staying
    # silent about what was left out is how "App Service covered" gets believed.
    tables = list(target.tables) or ["AuditLogs"]
    print(f"  {'queries':<14}{', '.join(tables)}", file=sys.stderr)
    for refusal in target.refused:
        body = textwrap.wrap(refusal, 62) or [""]
        print(f"  {'not queried':<14}{body[0]}", file=sys.stderr)
        for rest in body[1:]:
            print(f"  {'':<14}{rest}", file=sys.stderr)
    print(file=sys.stderr)

    # Entra is not an ARM resource, so it keeps the platform/service path and its
    # single table. Everything else goes through resource mode, which the engine
    # has always had: one request naming the resource type, with its surfaces
    # resolved here so the run cannot widen past what the gate allowed.
    from .services import ENTRA_KEY
    if not target.resource_type:
        request = engine.EngineRequest(
            verify_workspace=getattr(args, "workspace", "") or "",
            verify_window=getattr(args, "verify_window", "") or "",
            platform="entra", service="AuditLogs",
            target_key=target.key,
            entra_category=target.entra_category,
            max_cost=args.max_cost, max_tokens=args.max_tokens,
            provisioned_tables=have,
            analysis=plan, vector_selection=selection,
        )
    else:
        request = engine.EngineRequest(
            verify_workspace=getattr(args, "workspace", "") or "",
            verify_window=getattr(args, "verify_window", "") or "",
            resource=target.resource_type, surfaces=target.surfaces,
            target_key=target.key,
            max_cost=args.max_cost, max_tokens=args.max_tokens,
            provisioned_tables=have,
            analysis=plan, vector_selection=selection,
        )
    try:
        report = asyncio.run(engine.pylon.run(request))
    except Exception as exc:
        from .clients import rate_limit_help
        if type(exc).__name__ == "RateLimitExhausted":
            print(rate_limit_help(), file=sys.stderr)
            return 1
        print(f"design failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    # `WorkflowRunResult` is a LIST subclass, so `getattr(x, "value", x)` returns
    # the list and every attribute lookup after it silently defaults. A
    # five-minute run reported "0 detections" that way with the report sitting
    # in `get_outputs()` untouched.
    outputs = report.get_outputs() if hasattr(report, "get_outputs") else [report]
    result = next((o for o in outputs if hasattr(o, "detections")), None)
    if result is None:
        print(f"design ran but returned no EngineReport (got "
              f"{[type(o).__name__ for o in outputs]}). The run spent tokens; "
              "this is a result-handling bug, not an empty tenant.",
              file=sys.stderr)
        return 1
    plan_only = selection.strip().lower() == "none"
    _print_report(result, plan_only=plan_only, title=target.key)

    # A run that was PAID FOR must not evaporate because a flag was missing.
    # `--out` was optional here and required on `design plan`, and the "next"
    # line `plan` printed omitted it -- so following the tool's own suggestion
    # charged for detections, said "2 produced a valid detection", and wrote
    # nothing but a log. Found by someone testing the release, which is exactly
    # the first hour of a first user.
    #
    # Defaulting beats erroring: refusing after the model calls have been made
    # loses the same work and adds a lecture. `--from DIR` names a directory
    # that already holds the plan these were built from, so writing beside it
    # is where a reader would look anyway.
    out = args.out or args.source
    if not out:
        out = _slug(target.key)
        print(f"\n  no --out given; writing to ./{out}/", file=sys.stderr)
    _write_detections(result, out, plan_only=plan_only)
    return 0


def _print_report(result, plan_only: bool = False, title: str = "") -> None:
    """The run's result, in the same shape `analyze` uses.

    The old version was four dense lines and a list: "yield 100% | catalog
    coverage 3/101" is two real measurements written so only their author can
    read them. They are spelled out now.
    """
    from . import console

    detections = result.detections or []
    valid = [d for d in detections if d.valid]
    vectors = len(result.analysis.attack_vectors)

    print()

    def count(n: int, singular: str, many: str) -> None:
        print(f"  {n:>4}  {singular if n == 1 else many}")

    # A plan built nothing on purpose, so the detections summary reads it as a
    # total failure: "0 produced a valid detection", "0% coverage". That is the
    # opposite of what happened -- the run did its whole job for one model call.
    if plan_only:
        # `result.service` is the TABLE on the Entra path, so a plan for
        # `Entra RoleManagement` announced itself as "AuditLogs".
        print(console.heading("PLAN") + f"   {title or result.service}")
        count(vectors, "vector enumerated", "vectors enumerated")
        by_table: dict[str, int] = {}
        for v in result.analysis.attack_vectors:
            by_table[v.log_table] = by_table.get(v.log_table, 0) + 1
        for table, n in sorted(by_table.items(), key=lambda kv: -kv[1]):
            print(f"        {n:>3} in {table}")
        print()
        _show_plan(result.analysis)
        # A plan is a PAID call and printed no cost at all, while `detections`
        # printed one -- so the cheap half of the flow was the half that looked
        # free. One line, the same shape as the block below.
        print(f"\n  {plural(result.model_calls, 'model call')}, "
              f"{result.input_tokens + result.output_tokens:,} tokens, "
              f"${result.estimated_cost_usd:.2f}")
        return

    print(console.heading("DETECTIONS") + f"   {result.platform} / {result.service}")

    # What was BUILT, and what was left. A `--pick` run said "55 attack vectors
    # enumerated / 8 produced a valid detection", which reads as forty-seven
    # failures when forty-seven were never attempted.
    planned = result.vectors_planned or vectors
    attempted = len(detections)
    if planned > attempted:
        count(attempted, "vector built from a plan of "
                         f"{planned}", f"vectors built from a plan of {planned}")
        count(planned - attempted, "not picked", "not picked")
    else:
        count(vectors, "attack vector enumerated", "attack vectors enumerated")
    count(len(valid), "produced a valid detection", "produced a valid detection")

    print()
    for d in detections:
        print(f"  {'ok ' if d.valid else 'BAD'}  "
              f"{d.detection.mitre_technique:<10} "
              f"{d.detection.vector_name}")
        if not d.valid and d.errors:
            print(f"        {d.errors[0][:96]}")

    # The curated index already knows which technique an operation pins, and
    # nothing compared the model's answer against it. A live run mapped
    # CertificateGet, SecretList and KeyList to T1555.006 and then wrote
    # "unmapped" for CertificateList, which the index pins to the same
    # technique. One wrong label in thirty-three, and nothing said so.
    #
    # Reported, never corrected. The RATE is the signal: one row is a model slip
    # you ignore, ten means the prompt is fighting the index or the index is
    # wrong -- both of which happened this week. Rewriting the label silently
    # would erase the evidence for either.
    from .catalog.table_techniques import second_opinion

    clashes = [
        (v.name, v.operation, v.mitre_technique, pinned)
        for v in result.analysis.attack_vectors
        if (pinned := second_opinion(v.log_table, v.operation, v.mitre_technique))
    ]
    if clashes:
        print()
        print(console.heading("TECHNIQUE DISAGREEMENTS"))
        count(len(clashes),
              "detection uses a different technique than Pylon's own mapping",
              "detections use a different technique than Pylon's own mapping")
        print()
        for name, operation, claimed, pinned in clashes:
            print(f"  {operation:<28} this run: {claimed or 'none':<12} "
                  f"Pylon maps it to: {', '.join(pinned)}")
            print(f"  {'':<28} {name}")

    # Two different questions, and the old line ran them together with a pipe.
    # Yield asks whether generation did its job on what it enumerated. Coverage
    # asks how much of the platform's ATT&CK catalogue is now watched. A run can
    # score 100% on the first while covering three techniques out of a hundred.
    print()
    print(console.heading("COVERAGE"))
    scored = len(detections) if (result.vectors_planned or vectors) > len(detections) \
        else vectors
    noun = "picked" if scored != vectors else "enumerated"
    # COUNTED, not the weighted score. `generation_yield` is computed over
    # distinct, weight-scored TECHNIQUE ids, and this sentence promised a
    # percentage of VECTORS -- two things that only coincide when every vector
    # has its own technique. A run of two vectors sharing one technique with
    # one valid detection printed "100% of the 2 enumerated vectors produced a
    # valid detection" four lines under the word BAD, and wrote
    # generation_yield: 100 into the artifact beside valid: false.
    #
    # The weighted number is still worth having -- missing a weight-10
    # technique is not the same as missing a weight-3 -- so it is kept and
    # labelled as what it is, rather than deleted or left wearing the other
    # one's sentence.
    built = len(valid)
    print(f"  {built} of {plural(scored, f'{noun} vector')} produced a valid "
          "detection")
    if result.generation_yield != (round(100 * built / scored) if scored else 0):
        print(f"  {result.generation_yield:.0f}% by technique weight, which "
              f"differs because vectors can share a technique and techniques "
              f"are not equally important")
    if result.catalog_total:
        print(f"  {result.catalog_covered} of {result.catalog_total} ATT&CK "
              f"techniques catalogued for {result.platform} are now covered")

    print()
    print(console.heading("COST"))
    print(f"  {plural(result.model_calls, 'model call')}, "
          f"{result.input_tokens + result.output_tokens:,} tokens, "
          f"${result.estimated_cost_usd:.2f}"
          + (" (PARTIAL: some calls reported no usage)"
             if result.unreported_calls else ""))


def _stem(index: int, detection, limit: int = 40) -> str:
    """`07-T1098-role-definition-modified` — the filename stem for one detection.

    Uses `text.slugify` rather than a local transform. A local one existed here
    for about an hour and `test_the_slug_transform_is_written_once` caught it:
    the repo already learned that two slug functions drift (`library._slug` and
    `report.slugify` disagreed on the empty case), and wrote a test so it could
    not happen twice. Only the length cap is local, because it is a property of
    filenames rather than of slugs.
    """
    from .text import slugify
    return (f"{index:02d}-{detection.mitre_technique}-"
            f"{slugify(detection.vector_name)[:limit].rstrip('-')}")


# The engine writes this when the workspace gate fails. Matched on its opening
# words rather than on a flag, because the error is a string by the time it
# reaches the artifact and nothing records where it came from.
_WORKSPACE_ERROR = "against real events in the workspace this is"


def _is_a_workspace_error(text: str) -> bool:
    """Whether `text` is the gate's own verdict wearing an error's clothes."""
    return _WORKSPACE_ERROR in text


def _kql_header(d) -> str:
    """The caveats, as KQL comments above the query.

    `engine.py` has said for a while that warnings "surface in the .kql header".
    They did not: the writer was one line and the files begin with the table
    name. A comment asserting a surface that does not exist is how a gap stays
    open -- anyone checking whether the honesty reaches a reader found the claim
    and stopped.

    A .kql file is what gets pasted into Sentinel. If a detection could not be
    checked against Microsoft's column list, or matched nothing real, the person
    pasting it is the last one who can act on that.
    """
    lines = []
    graded = getattr(d, "verification", None)
    if graded is not None and graded.verdict:
        lines.append(f"MEASURED: {graded.verdict} -- {graded.detail}")
    offline = getattr(d, "offline_check", None)
    if offline is not None and offline.ran and not offline.ok:
        lines.append("The KQL engine refused this query.")
    if not d.valid:
        # Errors that a LATER measurement has already superseded are dropped
        # rather than stacked under it. `verify` updates the verdict and never
        # touched `errors`, so a detection re-measured from `dead` to
        # `no-match` carried both "we cannot tell whether the attack simply did
        # not happen or the filter is wrong" and, four lines below, "the fault
        # is in what it MATCHES" -- the exact claim three rounds of work
        # removed, preserved in the one artifact that leaves the tool.
        #
        # Only the workspace error is superseded, and only by a workspace
        # verdict. A static rejection or an engine refusal is about the query
        # text, which no measurement can overturn.
        superseded = graded is not None and graded.verdict
        lines += [f"DID NOT VALIDATE: {x}" for x in (d.errors or [])
                  if not (superseded and _is_a_workspace_error(x))]
    lines += [f"WARNING: {x}" for x in (d.warnings or [])]
    if not lines:
        return ""
    body = "\n".join(f"// {line}" for text in lines
                      for line in textwrap.wrap(text, 96) or [""])
    return body + "\n//\n"


def _write_detections(result, out_dir: str, plan_only: bool = False) -> None:
    """A five-minute run whose output only reaches a terminal is a run you have
    to repeat. Written per detection so one bad row can be dropped without
    regenerating the rest, plus the whole report for `design playbooks`."""
    from pathlib import Path
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for i, d in enumerate(result.detections or [], 1):
        stem = _stem(i, d.detection)
        (out / f"{stem}.kql").write_text(_kql_header(d) + d.detection.kql + "\n")
    # The plan, always. A `design plan` run writes only this; a full run writes it
    # too, so what was ENUMERATED survives beside what was BUILT -- and a later
    # `--from` can pick something this run skipped without paying for Phase 1.
    (out / "plan.json").write_text(result.analysis.model_dump_json(indent=2))
    # report.json is the claim "detections were built". A plan-only run has built
    # none, and writing an empty one turned "you have not built anything yet" into
    # "0 detection(s) available", which reads as a run that produced nothing rather
    # than a step not taken.
    if not plan_only:
        (out / "report.json").write_text(result.model_dump_json(indent=2))
    # The queries are only half of a detection. Until this page existed, the
    # KQL was in one file, the technique it claims in another, and the argument
    # for that technique in a catalogue the reader had no reason to open --
    # so the only way to judge a detection was to already know the answer.
    if plan_only:
        # No detections were built, so there is no detections page to write and a
        # page of nothing would read as a failed run rather than a cheap one.
        print(f"\n  wrote {out}/plan.json")
        print(f"\n  next   pylon design detections --from {out_dir} "
              f"--pick ... --out {out_dir}")
        return

    from . import report_design

    pages = report_design.write(json.loads(result.model_dump_json()), out)
    # Every file, not just the page. It listed detections.html alone while also
    # writing report.json and one .kql per detection, so a reader following the
    # output did not know the queries were on disk.
    written = sorted({Path(p).name for p in pages}
                     | {f"{len(result.detections or [])} .kql file(s)",
                        "report.json", "plan.json"})
    print(f"\n  wrote {out}/")
    for name in written:
        print(f"    {name}")


def _label_of(item) -> tuple[str, str]:
    """(technique, name) for a thing a `--pick` can select.

    Two shapes reach this: a ValidatedDetection, which carries them on `.detection`,
    and an AttackVector, which carries them directly. One resolver for both, so a
    pick means the same thing before and after the money is spent.
    """
    inner = getattr(item, "detection", item)
    return (getattr(inner, "mitre_technique", "") or "",
            getattr(inner, "vector_name", None) or getattr(inner, "name", "") or "")


def _resolve_picks(pick: str, items, noun: str = "detection") -> list[int] | None:
    """Which items a `--pick` selects.

    Numbers are the least intuitive way to choose: you have to look one up
    before you can use it, and a technique id repeats -- three of the eight Key
    Vault detections are T1098.003. So a pick also matches a technique id, or
    any substring of the vector name, case-insensitively. `--pick federation`
    and `--pick T1528` both work, and neither needs a listing first.
    """
    if pick.strip().lower() == "all":
        return list(range(len(items)))
    chosen: list[int] = []
    for term in (t.strip() for t in pick.split(",") if t.strip()):
        if term.isdigit():
            idx = int(term) - 1
            if 0 <= idx < len(items):
                chosen.append(idx)
            else:
                # Silent before. `--pick 51` against a 20-detection report picked
                # nothing and said nothing, so a number aimed at the plan's
                # numbering looked like a detection that had simply not matched.
                print(f"--pick {term}: only {len(items)} {noun}(s) here",
                      file=sys.stderr)
            continue
        low = term.lower()
        hits = [i for i, d in enumerate(items)
                if low == _label_of(d)[0].lower() or low in _label_of(d)[1].lower()]
        if not hits:
            print(f"--pick {term!r} matched no {noun}", file=sys.stderr)
        chosen += hits
    # Ordered, de-duplicated: `--pick T1098.003,1` must not write file 1 twice.
    return sorted(set(chosen))


def _design_playbooks(args: argparse.Namespace) -> int:
    """Phase 3, against detections that already exist.

    Reads a saved report rather than regenerating. `run_playbook_phase` takes a
    single `ValidatedDetection`, so nothing here needs the workflow's state --
    which means asking for a playbook does not mean paying for phases 1 and 2
    again, and the human pick becomes an argument instead of a suspended
    workflow.
    """
    engine = _engine()
    if engine is None:
        return 2
    import asyncio
    from pathlib import Path

    from .models import EngineReport

    src = Path(args.source) / "report.json"
    if not src.is_file():
        # A plan there but no detections is the common case, not a broken
        # directory: the run stopped after Phase 1. Say which step is missing and
        # what the next command is, rather than naming a file the reader never
        # asked for.
        plan = (Path(args.source) / "plan.json")
        if plan.is_file():
            print(f"{args.source} holds a plan but no detections. A playbook is "
                  "written from a detection, so build those first:\n\n"
                  f"  pylon design detections --from {args.source} --pick all "
                  f"--out {args.source}\n", file=sys.stderr)
        else:
            print(f"no report.json in {args.source} -- run `pylon design detections "
                  "--out <dir>` first", file=sys.stderr)
        return 2
    report = EngineReport.model_validate_json(src.read_text())
    detections = report.detections or []
    if not detections:
        print(f"{src} holds no detections, so there is nothing to write a "
              f"playbook from. Run `pylon design detections --from {args.source} "
              f"--pick all --out {args.source}`.", file=sys.stderr)
        return 2

    picks = _resolve_picks(args.pick, detections)
    if picks is None:
        return 2
    if not picks:
        print(f"nothing picked. {len(detections)} detection(s) available:",
              file=sys.stderr)
        _show_detections(detections)
        return 2

    from .usage import current_meter, over_budget, reset_meter

    # A resource-mode run reports platform "resource" and puts the resource type
    # in `service`. Rebuilding it as platform/service would send the playbook
    # phase down the single-table path with "Microsoft.KeyVault/vaults" as a
    # table name, which resolves to nothing and grounds nothing.
    from .services import resolve_target
    if report.platform == "resource":
        again = resolve_target(report.service)
        request = engine.EngineRequest(
            resource=report.service,
            surfaces=again.surfaces if again else (),
            max_cost=args.max_cost, max_tokens=args.max_tokens,
        )
    else:
        request = engine.EngineRequest(
            platform=report.platform, service=report.service,
            max_cost=args.max_cost, max_tokens=args.max_tokens,
        )
    out = Path(args.source)
    print(f"{report.platform} / {report.service}: "
          f"{len(picks)} playbook(s) from {len(detections)} detection(s), "
          f"cap ${args.max_cost:.2f}\n", file=sys.stderr)

    # `run_playbook_phase` has no budget check of its own -- the engine enforces
    # caps between calls inside the workflow, and this path does not go through
    # the workflow. Without this, `--pick all` on the 18-detection Entra run was
    # eighteen uncapped calls, each with a validation retry, and nothing would
    # have stopped it. Checked between playbooks, so a cap is approximate in the
    # same way the engine's is: an in-flight call can push slightly over.
    reset_meter()
    written = skipped = failed = 0
    from .models import Playbook
    for i in picks:
        d = detections[i]
        if over_budget(args.max_cost, args.max_tokens):
            skipped += 1
            report.playbooks_skipped.append(d.detection.vector_name)
            continue
        try:
            text = asyncio.run(engine.run_playbook_phase(request, d))
        except Exception as exc:
            print(f"  FAILED {d.detection.vector_name}: "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)
            failed += 1
            continue
        path = out / f"{_stem(i + 1, d.detection)}-playbook.md"
        path.write_text(text)
        written += 1
        report.playbooks.append(
            Playbook(target=d.detection.vector_name, text=text))
        print(f"  wrote {path.name}  ({d.detection.vector_name})")

    # report.json is the record of what this directory holds. Writing the .md
    # files and leaving `playbooks: []` behind meant the report denied the
    # existence of documents sitting beside it, and anything reading the report
    # rather than globbing the directory saw a run that never wrote a playbook.
    if written or skipped:
        src.write_text(report.model_dump_json(indent=2))

    m = current_meter()
    from .usage import estimate_cost
    print(f"\n  {written} playbook(s), {m.calls} model call(s), "
          f"{m.input_tokens + m.output_tokens:,} tokens, "
          f"${estimate_cost(m.input_tokens, m.output_tokens):.2f}"
          + (" (PARTIAL: some calls reported no usage)" if m.unreported else ""))
    if skipped:
        # Named, never silent. A budget stop that looks like a finished run is
        # how a partial result gets mistaken for a complete one.
        # stdout, not stderr. It is part of the result, not a diagnostic, and
        # splitting the two streams put "STOPPED" above the "wrote" lines it
        # was meant to follow.
        print(f"  STOPPED at the ${args.max_cost:.2f} cap: {skipped} playbook(s) "
              "not generated. Raise --max-cost or narrow --pick.")
        return 1
    # A failure used to print FAILED and exit 0. Every ARM playbook in a run
    # could be discarded and the command still reported success, so nothing
    # scripting this -- CI included -- could tell a finished run from a total
    # loss. What was written decides the status.
    if failed:
        print(f"  {failed} playbook(s) FAILED and were not written.",
              file=sys.stderr)
        return 1
    return 0


def _design_verify(args: argparse.Namespace) -> int:
    """Measure each detection against the events it claims to detect.

    Reads the operation and the KQL from report.json, counts the operation in
    the raw table, counts what the detection returns over the same window, and
    compares. The first number is the ground truth and the detection cannot
    influence it.
    """
    from .models import DetectionVerification, EngineReport
    from . import provenance, validate, verification

    src = Path(args.source) / "report.json"
    if not src.is_file():
        print(f"no report.json in {args.source} -- run `pylon design detections "
              "--out <dir>` first", file=sys.stderr)
        return 2
    # plan.json is no longer opened here. The operation used to be read from it
    # and matched back to a detection by vector name, and the name is not a key
    # -- see the loop below. Each detection now carries the operation it was
    # built for, so the gate on a file this command does not read would have
    # been a precondition that proved nothing.
    report = EngineReport.model_validate_json(src.read_text())
    detections = report.detections or []
    if not detections:
        print(f"{src} holds no detections", file=sys.stderr)
        return 2

    try:
        window = validate.parse_window(args.window)
    except validate.BadWindow as exc:
        print(str(exc), file=sys.stderr)
        return 2
    _tenant, _arm, guid = validate.resolve(args.workspace)

    print(f"{report.platform} / {report.service}: {len(detections)} detection(s) "
          f"against {args.workspace} over {args.window}\n", file=sys.stderr)

    results: list[DetectionVerification] = []
    for d in detections:
        name = d.detection.vector_name
        # The detection RECORDS the operation it was built for. Read that,
        # rather than matching its name back against the plan.
        #
        # The name is not a key. `models.ThreatAnalysis` says so about its own
        # provenance -- "the vector name cannot [join a plan to its detections],
        # because the detection phase rewrites it" -- and the rewrites are not a
        # family that string matching closes. A plan asked for `SecretDelete
        # (delete secret)` and got back a new subtitle; asked for `VM created or
        # updated` and got the operation appended; asked for `VaultPatch (patch
        # vault configuration)` and got `Key Vault configuration patched
        # (VaultPatch)`, which shares no leading word with it at all. Each
        # rewrite bought one more matching rule and the next rewrite defeated
        # it, while every miss reported as `error` -- a detection not measured,
        # sitting in the coverage line as a defect nobody could act on.
        #
        # `operation` is stamped by code at generation, where the vector is
        # known for certain. Falling back to the name match would restore the
        # ambiguity this deletes, so a detection without one is an error and
        # says which half is missing.
        operation = d.operation
        table = d.log_table
        if not operation:
            results.append(DetectionVerification(
                vector_name=name, operation="", verdict="error",
                detail="this detection records no operation, so there is "
                       "nothing to count as ground truth"))
            continue

        # THE SHARED IMPLEMENTATION, not a copy of it. This block used to
        # repeat `verification.measure` line for line -- the same column
        # lookup, the same two counts, the same widen, the same verdict call --
        # and `measure`'s own docstring says it "lives here rather than in the
        # CLI because generation needs it too". It was extracted so there would
        # be ONE of it, and the original was never deleted.
        #
        # The copy then went stale in the one way that mattered. `measure` was
        # taught to pass `narrowed`, which is what separates a detection that
        # matched nothing while filtering only the operation from one that asks
        # for a shape no event had. This path never learned it, so `no-match`
        # was unreachable from `design verify` -- the command whose entire
        # purpose is measuring -- and a behaviour-scoped query was told, falsely
        # and specifically, that it filtered "on nothing beyond the operation
        # itself".
        graded = verification.measure(
            d.detection.kql, table, operation, args.window,
            lambda kql: _count(kql, guid, window))
        if graded.verdict == "error" and graded.observed is None:
            graded.detail = f"{graded.detail}: {validate.last_error()[:160]}"
        graded.vector_name = name
        graded.verified_by = provenance.stamp("design verify")
        graded.workspace = args.workspace
        results.append(graded)

    for r in results:
        # Each verdict on the structured channel, so a coverage question can be
        # answered from the run log rather than by reopening every report.json.
        _cli_log.info("%s: %s", r.operation or r.vector_name, r.detail,
                      extra={"event": "verification", "verdict": r.verdict,
                             "operation": r.operation, "vector": r.vector_name,
                             "expected": r.expected, "observed": r.observed,
                             "widened": r.widened, "workspace": args.workspace})
    _show_verification(results)
    _verify_playbooks(Path(args.source), guid, window, results, detections)
    report.verification = results
    # Put each verdict on the DETECTION as well as in the report's own list, so
    # the page can show it beside the query rather than in a table somewhere
    # else, and so a detection carries its own measurement wherever it travels.
    by_vector = {r.vector_name: r for r in results if r.vector_name}
    for d in report.detections or []:
        graded = by_vector.get(d.detection.vector_name)
        if graded is not None:
            d.verification = graded
    src.write_text(report.model_dump_json(indent=2))

    # Re-render the page. It was written once at generation and never revisited,
    # so a customer who ran this command -- the one built to find a detection
    # that parses, deploys and never fires -- opened the same full-marks page a
    # week later. The file went stale the moment the command that corrects it
    # was run.
    try:
        from . import report_design

        rewritten = [Path(p).name for p in report_design.write(
            json.loads(report.model_dump_json()), Path(args.source))]
        # The .kql files too. They carry a `// MEASURED:` header written at
        # generation, and verify rewrote the page and the report and left them
        # alone -- so the one artifact that LEAVES this tool, the file someone
        # pastes into Sentinel, kept a superseded verdict. On a directory whose
        # verdict changed from `dead` to `no-match`, the page said the query
        # could not be judged and the .kql still said "the fault is in what it
        # MATCHES", which is precisely the claim this release removed.
        for i, d in enumerate(report.detections or [], 1):
            path = Path(args.source) / f"{_stem(i, d.detection)}.kql"
            if path.is_file():
                path.write_text(_kql_header(d) + d.detection.kql + "\n")
                rewritten.append(path.name)
        for name in rewritten[:2] + ([f"{len(rewritten) - 2} more"]
                                     if len(rewritten) > 2 else []):
            print(f"  rewrote {name} with the verdicts", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 - a page is not worth losing verdicts over
        print(f"  verdicts saved, but the page could not be rewritten: {exc}",
              file=sys.stderr)

    counts = verification.summarise(results)
    defects = sum(counts.get(v, 0) for v in verification.DEFECTS)
    return 1 if defects else 0


def _verify_playbooks(source, guid: str, window: str, measured, detections) -> None:
    """Run every query in every playbook the directory holds.

    Not behind a flag. `verify --from DIR` answers for the directory, and a
    playbook carries six to ten queries a responder pastes under pressure; a
    check nobody remembers to ask for is a check that does not happen, which is
    the shape of every fault found today.

    The alert values come from a REAL row of the detection's own operation, so a
    query that runs is one that could return something rather than one that
    merely parses.
    """
    from . import validate, verification

    playbooks = sorted(source.glob("*-playbook.md"))
    if not playbooks:
        return

    values = _alert_values(guid, window, measured, detections)

    print(f"\n  {len(playbooks)} playbook(s), the queries a responder would run",
          file=sys.stderr)
    total = failed = 0
    for path in playbooks:
        queries = verification.runnable(path.read_text(), values)
        if not queries:
            print(f"  {path.name[:58]:60} no queries")
            continue
        bad = []
        for i, q in enumerate(queries, start=2):
            total += 1
            if validate._run_kql(validate._pipeable(q) + "\n| count", guid, window) is None:
                failed += 1
                bad.append((i, validate.last_error()[:110]))
        print(f"  {path.name[:58]:60} {len(queries) - len(bad)}/{len(queries)} run")
        for i, why in bad:
            print(f"      block {i}: {why}")
    if failed:
        print(f"\n  {failed} of {total} playbook queries FAILED to run.")
    else:
        print(f"\n  all {total} playbook queries run.")


# Where each table keeps the alert fields. No table agrees with another, and
# assuming otherwise is what broke every query the first time this ran.
_ACTOR = {
    "AuditLogs": "tostring(InitiatedBy.user.userPrincipalName)",
    "AZKVAuditLogs": "tostring(Identity.claim.upn)",
    "AzureActivity": "Caller",
}
_ACTOR_ID = {
    "AuditLogs": "tostring(InitiatedBy.user.id)",
    "AZKVAuditLogs": "tostring(Identity.claim.oid)",
    "AzureActivity": 'tostring(parse_json(Claims)["http://schemas.microsoft.com'
                     '/identity/claims/objectidentifier"])',
}
_SRC_IP = {
    "AuditLogs": "tostring(InitiatedBy.user.ipAddress)",
    "AZKVAuditLogs": "CallerIpAddress",
    "AzureActivity": "CallerIpAddress",
}
_TARGET = {
    "AuditLogs": "tostring(TargetResources[0].id)",
    "AZKVAuditLogs": "_ResourceId",
    "AzureActivity": "ResourceId",
}


def _alert_values(guid: str, window: str, measured, detections) -> dict:
    """The alert row a responder would be holding, taken from a real event.

    Filling the blanks with placeholders proves only that the query parses.
    Filling them from a row the workspace actually contains means a query that
    runs is one that could return something.
    """
    from . import validate
    from .services import operation_column

    values = {"window": "24h", "time": "", "actor": "", "actor_id": "",
              "src_ip": "", "target": "", "correlation_id": ""}
    table_of = {d.detection.vector_name: d.log_table for d in detections}
    for r in measured:
        table = table_of.get(r.vector_name)
        if not (r.operation and r.expected and table):
            continue
        column = operation_column(table)
        # The actor is in a different place on every table, which is the fault
        # behind most of what was found today. Taking the raw column instead
        # substituted a whole dynamic object where a string belonged and failed
        # every query with "could not be parsed at 'claim'".
        rows = validate._run_kql(
            f'{table} | where {column} =~ "{r.operation}" | take 1\n'
            f"| project TimeGenerated, CorrelationId,\n"
            f"          Actor = {_ACTOR.get(table, '\"\"')},\n"
            f"          ActorId = {_ACTOR_ID.get(table, '\"\"')},\n"
            f"          SrcIp = {_SRC_IP.get(table, '\"\"')},\n"
            f"          Target = {_TARGET.get(table, '_ResourceId')}",
            guid, window)
        if not rows:
            continue
        row = rows[0]
        stamp = str(row.get("TimeGenerated", "")).replace(" ", "T")[:19]
        values.update(
            time=f"{stamp}Z" if stamp else "",
            actor=row.get("Actor") or "",
            actor_id=row.get("ActorId") or "",
            src_ip=row.get("SrcIp") or "",
            target=row.get("Target") or "",
            correlation_id=row.get("CorrelationId") or "")
        break
    return values


def _count(kql: str, guid: str, window: str) -> int | None:
    """How many rows `kql` returns, or None when it could not run."""
    from . import validate

    rows = validate._run_kql(f"{validate._pipeable(kql)}\n| count", guid, window)
    if rows is None:
        return None
    return int(rows[0].get("Count") or 0) if rows else 0


def _show_verification(results) -> None:
    """The table, then the count of what is actually wrong."""
    from . import verification

    width = max((len(r.operation) for r in results), default=10)
    width = min(max(width, 10), 46)
    print(f"  {'operation':{width}}  {'events':>6} {'rows':>6}  verdict")
    print("  " + "-" * (width + 34))
    for r in results:
        print(f"  {r.operation[:width]:{width}}  {str(r.expected or 0):>6} "
              f"{str(r.observed if r.observed is not None else '-'):>6}  {r.verdict}")
    counts = verification.summarise(results)
    print()
    # Every verdict `verification` can produce, in a stated order -- not six of
    # the eight typed out here by hand. `aggregates` and `no-match` were missing,
    # so a run of two detections where one summarised printed a tally of one.
    # That detection was absent from the count, absent from the callouts (which
    # cover defects only), absent from the "not a pass" warning (special-cased
    # to no-ground-truth), and did not affect the exit code -- so a CI caller was
    # told everything passed about a detection whose correctness was never
    # established.
    #
    # Ordered here, complete from there: a ninth verdict lands at the end and is
    # counted, rather than being silently dropped until someone notices a total
    # that does not add up.
    first = ("exact", "under", "over", "dead", "no-match", "aggregates",
             "no-ground-truth", "error")
    for call in first + tuple(v for v in verification.VERDICTS if v not in first):
        if counts.get(call):
            print(f"  {counts[call]:3}  {call}")
    for r in results:
        if r.verdict in verification.DEFECTS:
            print(f"\n  {r.verdict.upper()}  {r.operation}\n        {r.detail}")
    # WHY it matched nothing. `no-match` used to end at "counting the operation
    # cannot tell them apart", which is true of the count and false of the
    # query: putting each filter back one at a time says which line took the
    # rows to zero. Printed for every verdict that reached zero rows, defect or
    # not, because "the tenant is quiet" and "this filter is wrong" are the two
    # readings and this is what separates them.
    for r in results:
        if not r.narrowing:
            continue
        print(f"\n  {r.operation} — rows surviving each filter:")
        for step in r.narrowing:
            mark = "  <-- this filter" if step.filter == r.killed_by else ""
            rows = "  ?" if step.rows is None else str(step.rows)
            # The line this whole table exists to print is the one that gets
            # truncated, so give it room: 76 chars cut the offending filter
            # mid-word and the reader still had to open the KQL.
            print(f"    {rows:>7}  {step.filter[:110]}{mark}")
    untested = counts.get("no-ground-truth", 0)
    if untested:
        # Named, never counted as a pass. "Nothing happened" is exactly what a
        # detection that can never fire also looks like.
        print(f"\n  {untested} detection(s) had no events to test against. That is "
              "not a pass;\n  it means this workspace cannot answer the question.")


def _candidates(typed: str) -> list[str]:
    """Resource types an ambiguous friendly name could have meant, narrowed to
    the ones this tool can actually be aimed at. Empty for a name that is simply
    unknown, so the caller prints nothing rather than a shrug."""
    from .catalog import resource_candidates
    from .services import targets

    known = {getattr(t, "resource_type", "") for t in targets().values()}
    return [c for c in resource_candidates(typed) if c in known]


def _design_tuning(args) -> int:
    """Print the tuning contract: one row per target, assembled from the
    catalogues. Free -- it reads vendored data and makes no model call and no
    workspace query."""
    from . import tuning
    from .services import targets

    if args.target:
        wanted = " ".join(args.target).strip().lower()
        key = next((k for k in targets() if k == wanted), None)
        if key is None:
            print(f"no such target: {' '.join(args.target)}\n"
                  f"run `pylon design list` for the ones that exist", file=sys.stderr)
            return 2
        text = tuning.render(tuning.contract(key))
    else:
        text = tuning.render_all()

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
        return 0
    print(text)
    return 0


def _slug(target: str) -> str:
    """A directory name for a target. Stable, so a sweep resumes into the same
    place it left, and readable, so `ls` answers what was run.

    `text.slugify` does the transform -- it is written once, and a test holds
    that line. This only caps the length, because a filesystem has an opinion
    about that and a slug function should not.
    """
    from .text import slugify

    return slugify(target)[:48]


def _design_sweep(args: argparse.Namespace) -> int:
    """Plan, build, write playbooks for and grade every target, in one command.

    This was a thirty-line shell script I hand-wrote to walk nine directories,
    and the hand-writing is the point: the loop already closed around ONE
    detection -- generate, check against the regexes, the KQL engine and the
    workspace, correct once -- and then stopped, because choosing what to run
    next was a person's job. Sixteen of twenty-five targets had never been run
    at all, and nothing tracked which.

    RESUMABLE AND IDEMPOTENT, because the expensive half is the model calls and
    a sweep that cannot be interrupted is a sweep nobody starts. Each stage is
    skipped when its output is already on disk; `--force` redoes it. The state
    file records what finished, so a run killed at target nine resumes at nine
    rather than at one.

    COST-CAPPED ACROSS THE WHOLE SWEEP, not per target. A per-target cap is not
    a budget: twenty-five targets at $5 each is $125 and the flag reads like it
    means five. The cap here is the real number.

    Checked BETWEEN stages, so it can overshoot by at most one stage. A model
    call already in flight cannot be un-spent, and the engine's own cap is
    likewise checked between calls -- so a cap smaller than one stage does not
    prevent that stage, it prevents the next one. Stated rather than implied,
    because a flag called "hard ceiling" that is not one is worse than no
    flag.

    Targets with no telemetry are NOT skipped. A detection nothing can grade is
    reported as `no-ground-truth`, which is an answer -- it says the workspace
    cannot settle the question, which is different from the detection being
    wrong and different again from nobody having asked. Skipping them would
    quietly shrink the denominator of every coverage figure.
    """
    from .services import resolve_target, targets as all_targets

    def _known(typed: str):
        """The catalogue's own resolution, so `sweep` accepts exactly what
        `design list` and `design plan` accept -- any case, the same spellings.
        Matching the raw keys instead rejected `Microsoft.Authorization/
        roleAssignments`, which is the form printed by every other command."""
        try:
            return resolve_target(typed)
        except Exception:  # noqa: BLE001 - an unknown name is a message, not a trace
            return None

    root = Path(args.out_root)
    root.mkdir(parents=True, exist_ok=True)
    state_path = root / ".sweep.json"
    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        state = {}

    if args.targets:
        unknown = [t for t in args.targets if _known(t) is None]
        if unknown:
            print(f"unknown target(s): {', '.join(unknown)}\n"
                  "`pylon design list` prints every value", file=sys.stderr)
            return 2
        wanted = [_known(t).key for t in args.targets]
    else:
        wanted = [resolve_target(k).key for k in all_targets()]

    stages = args.stages or ["plan", "detections", "playbooks", "verify"]
    if "verify" in stages and not args.workspace:
        print("--workspace is required to verify; pass one, or "
              "--stages plan detections playbooks", file=sys.stderr)
        return 2

    spent = float(state.get("_spent", 0.0))
    started = time.time()
    print(f"  sweeping {len(wanted)} target(s) into {root}/  "
          f"(cap ${args.max_cost:,.2f}, ${spent:,.2f} already spent)",
          file=sys.stderr)

    done_any = False
    for n, target in enumerate(wanted, 1):
        slug = _slug(target)
        out = root / slug
        seen = state.setdefault(slug, {})
        seen["target"] = target
        for stage in stages:
            if spent >= args.max_cost > 0:
                print(f"  budget reached (${spent:,.2f}); stopping before "
                      f"{target} / {stage}", file=sys.stderr)
                state["_spent"] = spent
                state_path.write_text(json.dumps(state, indent=1))
                _sweep_summary(state, started)
                return 0
            if seen.get(stage) == "done" and not args.force:
                continue
            code, cost = _sweep_stage(stage, target, out, args)
            spent += cost
            seen[stage] = "done" if code == 0 else f"failed:{code}"
            done_any = True
            state["_spent"] = spent
            state_path.write_text(json.dumps(state, indent=1))
            if code != 0:
                # One target failing is not the sweep failing. The state file
                # records which stage stopped, so a rerun retries just that.
                print(f"  {target} / {stage} exited {code}; continuing",
                      file=sys.stderr)
                break
        print(f"  [{n}/{len(wanted)}] {target}", file=sys.stderr)

    if not done_any:
        print("  everything was already done; --force redoes it", file=sys.stderr)
    _sweep_summary(state, started)
    return 0


def _sweep_stage(stage: str, target: str, out: Path,
                 args: argparse.Namespace) -> tuple[int, float]:
    """Run one stage for one target. (exit code, USD spent by it).

    Calls the same functions the subcommands do, with a namespace built here,
    rather than shelling out. A subprocess would lose the meter and make the
    budget unenforceable across the sweep, which is the one thing this command
    adds over the shell script it replaces.
    """
    from . import usage

    def _spent_so_far() -> float:
        m = usage.current_meter()
        return usage.estimate_cost(m.input_tokens, m.output_tokens)

    before = _spent_so_far()
    ns = argparse.Namespace()
    if stage == "plan":
        if (out / "plan.json").is_file() and not args.force:
            return 0, 0.0
        ns.target, ns.out, ns.source = [target], str(out), ""
        ns.max_cost, ns.max_tokens = args.max_cost, 0
        code = _design_plan(ns)
    elif stage == "detections":
        if (out / "report.json").is_file() and not args.force:
            return 0, 0.0
        ns.target, ns.source, ns.out = [], str(out), str(out)
        ns.pick, ns.max_cost, ns.max_tokens = args.pick, args.max_cost, 0
        # Grade while generating when the sweep was given a workspace. Without
        # this a sweep builds every target blind and only finds out at the
        # verify stage, one stage too late to correct anything.
        ns.workspace = args.workspace or ""
        ns.verify_window = args.window
        ns.unconfirmed_tables = getattr(args, "unconfirmed_tables", False)
        code = _design_detections(ns)
    elif stage == "playbooks":
        ns.source, ns.pick = str(out), "all"
        ns.max_cost, ns.max_tokens = args.max_cost, 0
        code = _design_playbooks(ns)
    elif stage == "verify":
        ns.source, ns.workspace, ns.window = str(out), args.workspace, args.window
        code = _design_verify(ns)
    else:
        return 2, 0.0
    return code, max(0.0, _spent_so_far() - before)


def _sweep_summary(state: dict, started: float) -> None:
    """What the sweep produced, read back off disk rather than accumulated in
    memory -- so an interrupted sweep summarises correctly on the next run."""
    rows = [(k, v) for k, v in state.items() if not k.startswith("_")]
    failed = [(k, s) for k, v in rows for s, r in v.items()
              if isinstance(r, str) and r.startswith("failed")]
    print(f"\n  {len(rows)} target(s), ${state.get('_spent', 0.0):,.2f}, "
          f"{(time.time() - started) / 60:.0f}m", file=sys.stderr)
    if failed:
        print(f"  {len(failed)} stage(s) did not finish:", file=sys.stderr)
        for target, stage in failed[:10]:
            print(f"    {target} / {stage}", file=sys.stderr)
    print("  `pylon design coverage` for the verdicts", file=sys.stderr)


def _surfaces(kql: str, column: str) -> bool:
    """Whether `kql`'s final projection carries `column`.

    A query's OUTPUT is what a caller can select on. `| project TimeGenerated,
    Caller, ResourceId` ends the row at those three columns however many the
    table has, so asking the workspace for a fourth is a query that cannot run.
    """
    import re as _re

    projections = [l for l in kql.splitlines()
                   if _re.match(r"\s*\|\s*project\b", l)]
    if not projections:
        return column in kql
    return column in projections[-1]


def _distinct(rows: list[dict]) -> list[dict]:
    """`rows` with duplicates removed, keyed by EventDataId where there is one.

    A table ingested by both an export and a connector writes each event twice
    under one EventDataId. Recording both makes a fixture claim a size it does
    not have -- 8 rows, 4 events -- and every detection dedupes them anyway.
    """
    seen, out = set(), []
    for row in rows:
        key = row.get("EventDataId") or row.get("_ItemId") or id(row)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _design_record(args: argparse.Namespace) -> int:
    """Capture real events as offline fixtures, one per detection.

    The facts this tool depends on came from reading real rows -- that
    `Authorization.evidence.role` is the caller's, that `ResourceId` is empty on
    every role-assignment row, that the assignment id arrives dashed on writes
    and undashed on most deletes. They live as prose in a prompt file, where
    nothing tests them and nothing notices when they go stale.

    A recorded fixture makes them executable: the rows are captured once,
    stripped of the tenant, and every future detection is graded against them
    offline. No workspace, no credentials, no retention window.

    Nothing is generated and nothing is spent. This reads.
    """
    from . import provenance, record, validate, verification
    from .models import EngineReport
    from .services import operation_column
    from .text import slugify

    src = Path(args.source) / "report.json"
    if not src.is_file():
        print(f"no report.json in {args.source} -- run `pylon design detections "
              "--out <dir>` first", file=sys.stderr)
        return 2
    report = EngineReport.model_validate_json(src.read_text())
    detections = report.detections or []
    if not detections:
        print(f"{src} holds no detections", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    _tenant, _arm, guid = validate.resolve(args.workspace)
    window = validate.parse_window(args.window)

    def rows(kql: str, spread: str = "", correlate: str = "") -> list[dict]:
        """Up to `--rows` rows, spread across `spread` when one is given.

        A bare `take N` returns whatever the engine reaches first, and that is
        how a fixture ends up unable to prove anything. Recording a diagnostic
        settings detection took three `Start` rows and two `Failure` rows for a
        query filtering `ActivityStatusValue =~ "Success"` -- so the detection
        could not fire on a single true positive, `grade` reported it silent,
        and the explanation blamed a threshold. There were eleven matching
        Success rows in the same window.

        Spreading across the status column fixes that class without the
        recorder having to read the detection's filters, which would be
        circular: a fixture built from rows the query already matches proves
        only that the query matches itself.
        """
        if correlate:
            # WHOLE EVENTS, not a stratified sample of unrelated rows.
            #
            # `partition by <outcome> (take K)` samples each outcome
            # INDEPENDENTLY, so the Start rows and the Success rows came from
            # different operations. A detection that joins Start to Success on
            # CorrelationId -- which is how every ARM detection reads the role
            # or the request body, because only Start carries it -- could never
            # produce a row from such a fixture. Measured: the Start row fully
            # satisfied the predicate, the Success row existed, and the two
            # CorrelationId sets did not intersect at all.
            #
            # More rows does not fix that; it only improves the odds of drawing
            # a matching pair by luck. So the sample is taken over correlation
            # ids that have BOTH halves, and then every row belonging to them.
            ids = validate._run_kql(
                f"{kql}\n| where isnotempty({correlate})\n"
                f"| summarize Halves = dcount({spread}) by {correlate}\n"
                f"| where Halves > 1\n| take {max(1, args.rows // 2)}",
                guid, window)
            keys = [str(r.get(correlate, "")) for r in (ids or [])
                    if r.get(correlate)]
            if keys:
                joined = ", ".join(f'"{k}"' for k in keys)
                got = validate._run_kql(
                    f"{kql}\n| where {correlate} in ({joined})", guid, window)
                if got:
                    return got
            # No correlated pair in the window. Fall through to the stratified
            # sample rather than returning nothing: a fixture of unrelated rows
            # still grades a detection that does not correlate.
        if spread:
            per = max(1, args.rows // 3)
            kql = f"{kql}\n| partition by {spread} (take {per})"
        got = validate._run_kql(f"{kql}\n| take {args.rows}", guid, window)
        return got or []

    def status_column(table: str) -> str:
        """The column carrying an operation's OUTCOME, or "".

        Almost every detection filters on it, and it is the axis a fixture most
        needs variety along. Named per table rather than guessed: AzureActivity
        carries ActivityStatusValue, the Sentinel and data-plane tables carry
        ResultType or ResultSignature, AuditLogs carries Result.
        """
        return {"AzureActivity": "ActivityStatusValue",
                "AuditLogs": "Result",
                "AZKVAuditLogs": "ResultType",
                "StorageBlobLogs": "StatusText"}.get(table, "")

    written = skipped = 0
    for d in detections:
        operation, table = d.operation, d.log_table
        if not operation:
            continue
        column = operation_column(table)
        # True positives: the operation this detection is FOR. True negatives:
        # anything else in the same table, which is what catches a filter that
        # matches the wrong thing or dropped itself entirely.
        # TRUE POSITIVES ARE WHAT THE DETECTION MATCHED, not what it might
        # like. This selected by operation, then by outcome spread, then by
        # correlation -- three guesses across three rounds of testing, each
        # wrong, because none asked the only question that decides the answer:
        # does the query match this row.
        #
        # The query can just be run. On the case that exposed it, `verify` had
        # measured this detection matching 4 rows of 110 in the same window and
        # `record` captured none of them -- the information was produced and
        # thrown away inside the same tool.
        #
        # WHAT THIS CHANGES ABOUT A FIXTURE, said plainly because it weakens a
        # claim I have been making for it. Positives taken from the query's own
        # output cannot prove the query is right; the query will always fire on
        # them. They are a REGRESSION ANCHOR: change the detection later and
        # stop matching what it used to, and `grade` says so. The evidence now
        # lives in the negatives -- real rows of the same operation the query
        # does NOT match, which is what proves it stays quiet.
        # Ask the detection WHICH rows it matched, then fetch those rows from
        # the table. Running the query and keeping its output is not the same
        # thing and I shipped that first: a detection ending in `project
        # TimeGenerated, Scope, Action, ...` handed back its own columns, so
        # the fixture held `Scope` and `DiagnosticSettingName` and none of the
        # `Authorization` or `Properties` the query reads. It graded silent
        # against rows it had itself selected. The other detection in the same
        # run worked only because it ends `summarize take_any(*)`, which keeps
        # every column by accident.
        #
        # `EventDataId` is the key every detection here already dedupes on. A
        # query that does not surface it gets None back from the projection and
        # falls through, rather than this guessing at another key.
        widened = validate._pipeable(
            verification.widen(d.detection.kql, args.window)[0])
        # Only ask for the key when the query actually surfaces it. Asking
        # regardless made the workspace refuse the query -- "Failed to resolve
        # scalar expression named 'EventDataId'" -- once per detection, printed
        # as a raw warning, before falling through silently. Measured: 11 of 106
        # generated detections project it, so nine in ten runs showed a user a
        # scary error and then quietly used the old heuristics.
        matched = []
        if _surfaces(d.detection.kql, "EventDataId"):
            keys = rows(f"{widened}\n| project EventDataId")
            ids = [str(r.get("EventDataId")) for r in keys if r.get("EventDataId")]
            if ids:
                matched = rows(f'{table} | where EventDataId in '
                               f'({", ".join(chr(34) + i + chr(34) for i in ids)})')
        if not matched:
            # Say which fixture this is, rather than letting a weaker one look
            # like the strong kind. A sample of the operation proves a detection
            # stays quiet on rows it should not match; it does not anchor what
            # it DOES match, because nothing here knows which rows those are.
            anchored = False
            print(f"  sample only: {d.detection.vector_name[:44]} does not "
                  f"project EventDataId, so its positives are representative "
                  f"rather than rows it matched", file=sys.stderr)
        else:
            anchored = True
        spread = status_column(table)
        correlate = "CorrelationId" if "join" in d.detection.kql.lower() else ""
        if matched:
            tp = matched
        else:
            # Nothing matched, so there is nothing to anchor. Fall back to a
            # representative sample: a fixture of rows the detection does not
            # fire on still proves it stays quiet, and `grade` reporting
            # `silent` against them is the honest answer rather than an empty
            # file.
            tp = rows(f'{table} | where {column} =~ "{operation}"', spread,
                      correlate)
        tn = rows(f'{table} | where {column} !~ "{operation}"')
        if not tp:
            # No events means no fixture. Recording an empty one would assert
            # that this detection matches nothing, which is not what was
            # measured -- it is what could not be measured.
            skipped += 1
            print(f"  no events for {operation}", file=sys.stderr)
            continue
        # Truncated at a word boundary. `...-write-that-dis.yaml` and
        # `...-deleted-loggin.yaml` are two filenames a reader cannot tell
        # apart, and a mid-word cut looks like corruption rather than a limit.
        name = slugify(f"{report.service}-{d.detection.vector_name}")
        if len(name) > 72:
            name = name[:72].rsplit("-", 1)[0]
        # AzureActivity is commonly ingested twice, so a correlated capture
        # returns each row twice and a fixture advertised as 8 rows holds 4.
        # The detection dedupes on EventDataId, so the duplicates collapse and
        # the fixture is half the size its own count claims.
        tp = _distinct(tp)
        tn = _distinct(tn)
        graded = d.verification.model_dump(mode="json") if d.verification else None
        body = record.fixture(name, table, d.detection.kql, operation, tp, tn,
                              measured=graded, anchored=anchored)
        body["recorded_by"] = provenance.stamp("design record").model_dump()
        (out / f"{name}.yaml").write_text(
            yaml.safe_dump(body, sort_keys=False, width=100))
        written += 1
        print(f"  {len(tp)} tp / {len(tn)} tn  {name}", file=sys.stderr)

    print(f"\n  {written} fixture(s) in {out}/", file=sys.stderr)
    if skipped:
        print(f"  {skipped} detection(s) had no events to record. Those need the "
              f"operation performed once; nothing here can invent them.",
              file=sys.stderr)
    print("  they grade offline from now on -- no workspace, no retention window",
          file=sys.stderr)
    if written:
        print("  GUIDs, UPNs and IPs are replaced; NAMES ARE NOT. Resource "
              "groups and resources keep theirs -- read one before committing "
              "a fixture recorded from a tenant that is not yours to publish.",
              file=sys.stderr)
    return 0


def _design_survey(args: argparse.Namespace) -> int:
    """Which planned vectors the workspace can actually settle, before you pay.

    Phase 2 is almost the whole bill and a plan enumerates a service's entire
    operation vocabulary, while a tenant exercises a handful of it. Measured
    across every plan on disk: 39 of 169 planned operations had ever happened.
    Generating the other 130 costs real money and returns `no-ground-truth`,
    which is not a pass and not a failure -- it is a question nobody could
    answer, bought at full price.

    One query per table answers it in advance, and costs nothing. `--pick` then
    takes the numbers this prints, so choosing what to build becomes a
    measurement instead of a guess.

    A vector with no events is NOT worthless. It may be the detection that
    matters most on a tenant where the thing has not happened yet. This says
    which can be proven today, not which are worth writing.
    """
    from . import validate
    from .services import operation_column

    plan_path = Path(args.source) / "plan.json"
    if not plan_path.is_file():
        print(f"no plan.json in {args.source} -- run `pylon design plan` first",
              file=sys.stderr)
        return 2
    plan = json.loads(plan_path.read_text())
    vectors = plan.get("attack_vectors") or []
    if not vectors:
        print(f"{plan_path} enumerates no vectors", file=sys.stderr)
        return 2

    _t, _a, guid = validate.resolve(args.workspace)
    window = validate.parse_window(args.window)

    # One query per TABLE, not per vector. A plan of 54 vectors over one table
    # is one round trip, not 54.
    tables = {v.get("log_table", "") for v in vectors if v.get("log_table")}
    counts: dict[str, dict[str, int]] = {}
    for table in sorted(tables):
        column = operation_column(table)
        rows = validate._run_kql(
            f"{table} | summarize n=count() by Op=tostring({column})", guid, window)
        if rows is None:
            print(f"  {table}: could not be read, so nothing below is measured "
                  f"for it", file=sys.stderr)
            counts[table] = {}
            continue
        counts[table] = {str(r.get("Op", "")).lower(): int(r.get("n") or 0)
                         for r in rows}

    gradable, blind = [], []
    for i, v in enumerate(vectors, 1):
        events = counts.get(v.get("log_table", ""), {}).get(
            (v.get("operation") or "").lower(), 0)
        (gradable if events else blind).append((i, v, events))

    width = max((len(v.get("name", "")) for _i, v, _n in gradable + blind),
                default=20)
    width = min(max(width, 20), 56)
    print(f"\n  {'#':>3}  {'vector':{width}}  {'events':>7}")
    print("  " + "-" * (width + 16))
    for i, v, n in gradable + blind:
        print(f"  {i:>3}  {v.get('name','')[:width]:{width}}  {n:>7}")

    print(f"\n  {len(gradable)} of {len(vectors)} can be graded against this "
          f"workspace.", file=sys.stderr)
    if blind:
        print(f"  {len(blind)} have no events. Generating them costs the same "
              f"and returns `no-ground-truth`, which is not a pass -- trigger "
              f"the operation first, or build them knowing they are unproven.",
              file=sys.stderr)
    if gradable:
        # Names --out, like `design plan`'s hint does. Harmless now that it
        # defaults to --from, but two hints for the same next step disagreeing
        # is how a reader decides one of them is wrong.
        print(f"\n  pylon design detections --from {args.source} --pick "
              f"\"{','.join(str(i) for i, _v, _n in gradable)}\" "
              f"--out {args.source}", file=sys.stderr)
    return 0


def _design_grade(args: argparse.Namespace) -> int:
    """Run every recorded fixture through the offline engine.

    `design record` wrote a source of truth and nothing in the product read it.
    `evaluate_fixture` worked and had no caller -- the same mistake as the
    offline engine being built and never wired, made again in the same session.

    The whole `tp` set is loaded and the query must return something; the whole
    `tn` set is loaded and it must return nothing. Set-based, not row-by-row,
    because an ARM role grant writes a Start row carrying the request body and a
    Success row carrying the outcome, and the detection joins them. One row at a
    time cannot satisfy that join, so a correct detection scored zero.
    """
    import yaml as _yaml

    from .golden_eval import evaluate_fixture
    from .kusto_offline import schema_for_table

    if not os.environ.get("PYLON_KUSTAINER_URL", "").strip():
        # The ARM invocation where the machine needs it. The README carries the
        # Apple silicon note and this message did not -- so the one place a
        # reader sees it at the moment they need it handed them the command
        # that exits 133 under Rosetta. Printed conditionally rather than
        # always, because a line about Rosetta on an Intel box is noise.
        arm = platform.machine().lower() in ("arm64", "aarch64")
        extra = (" --platform linux/amd64 -e DOTNET_EnableWriteXorExecute=0"
                 if arm else "")
        memory = "6G" if arm else "4G"
        print("no KQL engine configured. Grading runs queries, so it needs one:\n"
              f"  docker run -d --name pylon-kustainer{extra} \\\n"
              f"      -e ACCEPT_EULA=Y -m {memory} -p 8080:8080 \\\n"
              "      mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest\n"
              "  export PYLON_KUSTAINER_URL=http://localhost:8080"
              + ("\n  (the image is amd64-only; on Apple silicon it can still "
                 "die mid-run under Rosetta)" if arm else ""),
              file=sys.stderr)
        return 2

    paths = sorted(Path(args.fixtures).glob("*.yaml"))
    if not paths:
        print(f"no fixtures in {args.fixtures} -- run `pylon design record` first",
              file=sys.stderr)
        return 2

    rows, failed = [], 0
    for path in paths:
        try:
            fx = _yaml.safe_load(path.read_text())
        except (OSError, _yaml.YAMLError) as exc:
            print(f"  {path.name}: unreadable ({exc})", file=sys.stderr)
            failed += 1
            continue
        result = evaluate_fixture(fx.get("query", ""), fx.get("table", ""),
                                  schema_for_table(fx.get("table", "")),
                                  fx.get("events") or [])
        rows.append((fx.get("name", path.stem), result,
                     (fx.get("measured") or {}).get("verdict", ""),
                     bool(fx.get("anchored")),
                     (fx.get("measured") or {}).get("observed")))

    # Fixture names all begin with the target they came from, so truncating
    # from the left made two rows read identically -- you could not tell which
    # one failed. The shared prefix is the one part every row already agrees on,
    # so it is the part to drop.
    shared = os.path.commonprefix([n for n, _r, _m, _a, _o in rows]) if len(rows) > 1 else ""
    shared = shared[:shared.rfind("-") + 1] if "-" in shared else ""
    labels = {n: (n[len(shared):] or n) for n, _r, _m in rows}
    if shared:
        print(f"\n  all names begin {shared!r}; dropped below", file=sys.stderr)
    width = min(max((len(v) for v in labels.values()), default=24), 54)
    print(f"\n  {'fixture':{width}}  {'verdict':>8}  {'attack':>6}  {'benign':>6}")
    print("  " + "-" * (width + 26))
    for name, r, _m, _a, _o in rows:
        print(f"  {labels[name][:width]:{width}}  {r.verdict:>8}  "
              f"{str(r.on_attack if r.on_attack is not None else '-'):>6}  "
              f"{str(r.on_benign if r.on_benign is not None else '-'):>6}")

    noisy = [n for n, r, _m, _a, _o in rows if r.verdict == "noisy"]
    silent = [n for n, r, _m, _a, _o in rows if r.verdict == "silent"]
    errors = [n for n, r, _m, _a, _o in rows if r.verdict == "error"]
    # A detection a LIVE run already measured as matching nothing is not a
    # mystery, and offering a benign explanation for it was the tool starting
    # from zero on a question it had already answered.
    # Keyed on what was MEASURED, not on the word. This tested the verdict
    # label, so an `aggregates` verdict that produced zero groups -- a live run
    # that matched nothing -- slipped past into the generic "a fixture this size
    # may not hold" branch, which is the benign misexplanation three earlier
    # rounds were about.
    known = [n for n, r, m, _a, observed in rows
             if r.verdict == "silent"
             and (m in ("dead", "no-match") or observed == 0)]
    print(f"\n  {sum(1 for _n, r, _m, _a, _o in rows if r.passed)} of {len(rows)} fired "
          f"on the attack and stayed quiet on the benign.", file=sys.stderr)
    if noisy:
        print(f"  {plural(len(noisy), 'fixture')} also matched rows of OTHER "
              f"operations: {', '.join(noisy[:4])}", file=sys.stderr)
    if known:
        print(f"  {plural(len(known), 'fixture')} matched nothing, and a live "
              f"run had already measured that detection the same way -- so the "
              f"fixture is reproducing a known result, not discovering one: "
              f"{', '.join(known[:3])}", file=sys.stderr)
    silent = [n for n in silent if n not in known]
    if silent:
        print(f"  {plural(len(silent), 'fixture')} matched nothing. That is not "
              f"always wrong -- a detection filtering on a value inside the "
              f"operation, or counting toward a threshold, needs rows a fixture "
              f"this size may not hold: {', '.join(silent[:4])}", file=sys.stderr)
    if errors or failed:
        print(f"  {len(errors) + failed} could not be run.", file=sys.stderr)
    return 1 if (noisy or errors) else 0


def _design_coverage(args: argparse.Namespace) -> int:
    """Which targets have been generated, and which of those were measured.

    Verification lives in each run's own report.json, so "have we checked all of
    this" was a question nobody could answer without remembering every directory
    they had ever written. Four runs is rememberable. Twenty-five targets and
    several hundred operations is not, and an unanswerable coverage question
    reads as full coverage by default.

    A target that was never run and a detection that was never verified are both
    reported. Neither is a pass.
    """
    from .models import EngineReport
    from .services import targets as all_targets
    from . import verification

    roots = [Path(p) for p in (args.paths or ["."])]
    reports: list[tuple[Path, EngineReport]] = []
    for root in roots:
        if not root.exists():
            print(f"no such path: {root}", file=sys.stderr)
            continue
        found = [root / "report.json"] if (root / "report.json").is_file() \
            else sorted(root.rglob("report.json"))
        for path in found:
            try:
                reports.append((path, EngineReport.model_validate_json(path.read_text())))
            except (OSError, ValueError):
                print(f"  unreadable: {path}", file=sys.stderr)

    if not reports:
        print(f"no report.json under {', '.join(str(r) for r in roots)}", file=sys.stderr)
        return 2

    print(f"  {'target':44} {'dets':>5} {'checked':>8}  verdicts")
    print("  " + "-" * 82)
    seen_targets: set[str] = set()
    total_d = total_v = 0
    defects = 0
    for path, report in sorted(reports, key=lambda x: x[1].service):
        dets = len(report.detections or [])
        checks = report.verification or []
        counts = verification.summarise(checks)
        defects += sum(counts.get(v, 0) for v in verification.DEFECTS)
        total_d += dets
        total_v += len(checks)
        # `report.service` is the TABLE on the Entra path, not the target: an
        # `Entra RoleManagement` run records "AuditLogs" there, which matches no
        # target and counted nine runs as seven. The plan beside it records what
        # was ASKED for, which is the only field that is a target on every path.
        seen_targets.add(report.service)
        plan_path = path.with_name("plan.json")
        if plan_path.is_file():
            try:
                asked = json.loads(plan_path.read_text()).get("target")
            except (OSError, ValueError):
                asked = None
            if asked:
                seen_targets.add(asked)
        shown = " ".join(f"{n} {v}" for v, n in sorted(counts.items())) or "-"
        print(f"  {report.service[:44]:44} {dets:5} {len(checks):8}  {shown}")

    print("  " + "-" * 82)
    print(f"  {'TOTAL':44} {total_d:5} {total_v:8}")

    unverified = total_d - total_v
    offered = all_targets()
    # `service` is the TABLE on the Entra path, so a target is matched by either.
    covered = {t.key for t in offered.values()
               if t.key in seen_targets or (t.resource_type and t.resource_type in seen_targets)}
    never_run = len(offered) - len(covered)

    print()
    if unverified:
        print(f"  {unverified} detection(s) generated but never measured against real events.")
    if never_run:
        print(f"  {never_run} of {len(offered)} targets have never been run at all.")
    if defects:
        print(f"  {defects} detection(s) measured as dead, over-matching or errored.")
    if not (unverified or never_run or defects):
        print("  every target run, every detection measured, nothing defective.")
    return 1 if (defects or unverified) else 0


def _config(args: argparse.Namespace) -> int:
    """Show, set or locate the stored settings.

    `show` reports WHERE each value came from, which is the whole point. A
    config file's failure mode is "it works and I cannot see why", and its
    nastier twin is an exported environment variable silently overriding a file
    the operator edited five minutes ago. Precedence is stated on every row
    rather than left to be discovered.
    """
    path = config.user_config_path()
    if args.action == "path":
        print(path)
        return 0

    if args.action == "set":
        if "=" not in (args.assignment or ""):
            print("usage: pylon config set KEY=VALUE", file=sys.stderr)
            return 2
        key, value = args.assignment.split("=", 1)
        key, value = key.strip(), value.strip()
        if key not in config._ALLOWED:
            # An arbitrary KEY=value file that could set PATH or LD_PRELOAD is a
            # much worse thing than a config file, so the writer refuses what
            # the loader would ignore rather than writing a line silently
            # dropped on read.
            print(f"{key} is not a setting pylon reads. Known settings:",
                  file=sys.stderr)
            for k in sorted(config._ALLOWED):
                print(f"  {k}", file=sys.stderr)
            return 2
        values = config.load([path]) if path.is_file() else {}
        values[key] = value
        written = config.write(values, path)
        print(f"wrote {key} to {written} (mode 600)")
        if os.environ.get(key):
            print(f"NOTE: {key} is also set in your environment, which wins. "
                  "This file will have no effect until you unset it.")
        return 0

    # show
    used, applied = config.apply()
    print(f"config file : {used or 'none found'}")
    print(f"searched    : {', '.join(str(p) for p in config.candidate_paths())}")
    print()
    any_set = False
    for key in sorted(config._ALLOWED):
        value = os.environ.get(key)
        if not value:
            continue
        any_set = True
        source = "file" if key in applied else "environment"
        print(f"  {key:<34} {_redact(key, value):<26} from {source}")
    if not any_set:
        print("  nothing set")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pylon",
        description="Read a Sentinel tenant, say what it detects, "
                    "and write what it does not.",
        epilog="analyze, recommend, validate and design work on a tenant. "
               "tabledrift and config maintain Pylon itself.")
    parser.add_argument(
        "--version", action="version", version=_version_line(),
        help="the installed version and where it is installed from")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="measure the tenant: telemetry, rules, exposure")
    a.add_argument("--workspace", required=True,
                   help="the Sentinel workspace to measure against: a name, "
                        "or a full ARM resource id")
    a.set_defaults(func=_analyze)

    r = sub.add_parser("recommend",
                       help="what to connect, update, install or remove in Content Hub")
    r.set_defaults(func=_recommend)

    v = sub.add_parser("validate",
                       help="search the workspace for a written detection's hits")
    v.add_argument("--kql", required=True, metavar="FILE",
                   help="the detection to search for; `-` reads stdin")
    v.add_argument("--workspace", required=True)
    # A KQL duration, because that is what someone writing a detection already
    # has in their fingers. --start/--end take ISO 8601 for a fixed window.
    v.add_argument("--window", default="24h", metavar="DURATION",
                   help="how far back to look: 30m, 24h, 7d (default: 24h)")
    v.add_argument("--start", metavar="WHEN",
                   help="explicit window start instead of --window, ISO 8601")
    v.add_argument("--end", metavar="WHEN", help="explicit window end, ISO 8601")
    v.set_defaults(func=_validate)

    # Named as maintenance, because it is the one verb here that says nothing
    # about the tenant. It checks PYLON, and its old help line -- "check
    # tablemap against the categories Azure offers" -- used an internal name
    # and never said who it was for, so it read as a fifth thing to run in an
    # engagement.
    td = sub.add_parser(
        "tabledrift",
        help="maintenance: has Pylon's own category-to-table map gone stale",
        description="A maintenance check on Pylon, not an assessment of your "
                    "tenant. Pylon carries a hand-written map from diagnostic "
                    "category to log table, because Azure will name the "
                    "categories a resource type offers and never the table they "
                    "land in. Every 'enable X to fill Y' in the report comes "
                    "from that map. This asks Azure what your resource types "
                    "offer today and checks each one still has a row, so a "
                    "category Azure adds cannot go silently missing from every "
                    "report.")
    td.add_argument("--json", metavar="FILE",
                    help="also write the findings as JSON, for diffing between runs")
    td.set_defaults(func=_tabledrift)

    d = sub.add_parser("design", help="generate detections, playbooks or a target list")
    # A noun is required. Bare `pylon design` errors and names the three rather
    # than guessing which one was meant.
    dn = d.add_subparsers(dest="noun", required=True)

    dp_ = dn.add_parser("plan",
                        help="what it would build, for the price of one call")
    dp_.add_argument("target", nargs="*", metavar="TARGET",
                     help="e.g. Microsoft.KeyVault/vaults, Entra, or "
                          "`Entra RoleManagement` (see `pylon design list`)")
    dp_.add_argument("--out", metavar="DIR", required=True,
                     help="write plan.json here; `design detections --from DIR`"
                          " then builds the ones you pick")
    dp_.add_argument("--max-cost", type=float, default=5.0,
                     help="hard USD ceiling (default 5.00; 0 = no cap)")
    dp_.add_argument("--max-tokens", type=int, default=0,
                     help="hard token ceiling (0 = no cap)")
    dp_.set_defaults(func=_design_plan, source="")

    dd = dn.add_parser("detections", help="threat analysis, then KQL per vector")
    # Phase 2 is 99% of the bill, so building from a plan you have read is the
    # cheap path and building blind is the convenient one. Both stay.
    dd.add_argument("--from", dest="source", metavar="DIR",
                    help="a directory written by `design plan`; builds only "
                         "--pick from it and does not re-run phase 1")
    dd.add_argument("--pick", default="",
                    help='which of the plan to build: "all", a technique id, part '
                         'of a name, or numbers (e.g. "T1555.006,purge"). Numbers '
                         'count against the plan -- the list printed when --pick '
                         'is missing, and saved as plan.json')
    # The Azure resource type, positionally, because it is the only name Azure
    # itself uses -- and one target now carries every table the resource writes
    # to, so there is no plane left to select.
    dd.add_argument("target", nargs="*", metavar="TARGET",
                    help="e.g. Microsoft.Storage/storageAccounts/queueServices, "
                         "Entra, or `Entra RoleManagement` "
                         "(see `pylon design list`)")
    dd.add_argument("--out", metavar="DIR",
                    help="write .kql and report.json here")
    dd.add_argument("--max-cost", type=float, default=5.0,
                    help="hard USD ceiling (default 5.00; 0 = no cap)")
    dd.add_argument("--max-tokens", type=int, default=0,
                    help="hard token ceiling (0 = no cap)")
    # The third gate, as a flag. It was reachable only through
    # PYLON_VERIFY_WORKSPACE, and an environment variable is not a feature
    # anyone finds: every other verb here takes --workspace, so a reader has no
    # reason to look for one. The env var still works and the flag wins, which
    # is what lets a sweep set it once for every target it drives.
    dd.add_argument("--workspace", default="",
                    help="grade each detection against the real events in this "
                         "Log Analytics workspace while generating it, and "
                         "re-prompt once when it matches nothing. Without it a "
                         "detection is only checked for being well formed, "
                         "which is not the same as working")
    dd.add_argument("--verify-window", default="", metavar="DURATION",
                    help="how far back --workspace grades (default: 30d)")
    # A run without a scan writes detections naming tables nobody confirmed
    # exist. It used to warn and carry on, and every detection it produced
    # carried "No scan was run" where its table basis should be -- which is the
    # tool spending money to answer a question it has already said it cannot
    # check. Confirming the tenant comes first; this is the escape hatch for
    # writing detections for a service that is not deployed yet, which is a
    # real thing to want and must be asked for rather than defaulted into.
    dd.add_argument("--unconfirmed-tables", action="store_true",
                    help="build even though no scan confirms the tables hold "
                         "data. For a service you have not deployed yet; the "
                         "output says the table was never confirmed")
    dd.set_defaults(func=_design_detections)

    dp = dn.add_parser("playbooks", help="IR playbooks for detections already generated")
    dp.add_argument("--from", dest="source", required=True, metavar="DIR",
                    help="a directory written by `design detections --out`")
    dp.add_argument("--pick", default="all", metavar="WHICH",
                    help="`all` (default), a technique like T1528, part of a "
                         "vector name like federation, or numbers like 1,3. "
                         "Numbers count against the detections in report.json, "
                         "NOT the plan: a vector that failed to build is absent "
                         "and every number after it has shifted. "
                         "`pylon design list --from DIR` prints that numbering. "
                         "Names and technique ids do not shift, so prefer them")
    dp.add_argument("--max-cost", type=float, default=5.0,
                    help="hard USD ceiling (default 5.00; 0 = no cap)")
    dp.add_argument("--max-tokens", type=int, default=0,
                    help="hard token ceiling (0 = no cap)")
    dp.set_defaults(func=_design_playbooks)

    dv = dn.add_parser("verify",
                       help="measure detections against the events they claim to detect")
    dv.add_argument("--from", dest="source", required=True, metavar="DIR",
                    help="a directory written by `design detections --out`")
    dv.add_argument("--workspace", required=True,
                    help="the Log Analytics workspace holding the real events")
    dv.add_argument("--window", default="30d", metavar="DURATION",
                    help="how far back to compare: 24h, 7d, 30d (default: 30d). "
                         "Each detection's own time bound is widened to this, "
                         "or a detection bounded to an hour can never be seen")
    dv.set_defaults(func=_design_verify)

    dsw = dn.add_parser("sweep",
                        help="plan, build, write playbooks for and grade every "
                             "target, resumably, under one budget")
    dsw.add_argument("targets", nargs="*", metavar="TARGET",
                     help="which to run (default: every target `design list` prints)")
    dsw.add_argument("--out-root", default=".", metavar="DIR",
                     help="one directory per target is written here (default: .)")
    dsw.add_argument("--workspace",
                     help="the Log Analytics workspace to grade against; "
                          "required unless --stages omits verify")
    dsw.add_argument("--window", default="30d", metavar="DURATION",
                     help="how far back to grade (default: 30d)")
    dsw.add_argument("--pick", default="all",
                     help="which vectors of each plan to build (default: all)")
    dsw.add_argument("--stages", nargs="*",
                     choices=["plan", "detections", "playbooks", "verify"],
                     help="run only these, in this order (default: all four)")
    dsw.add_argument("--max-cost", type=float, default=25.0, metavar="USD",
                     help="budget ACROSS THE WHOLE SWEEP, not per target "
                          "(default: 25.00; 0 = no cap). A per-target cap is "
                          "not a budget: 25 targets at $5 is $125. Checked "
                          "BETWEEN stages, so a sweep can overshoot by at most "
                          "one stage -- a model call already in flight cannot "
                          "be un-spent")
    dsw.add_argument("--unconfirmed-tables", action="store_true",
                     help="build targets whose tables no scan confirms hold "
                          "data. Without it a sweep skips them and says so")
    dsw.add_argument("--force", action="store_true",
                     help="redo stages whose output is already on disk")
    dsw.set_defaults(func=_design_sweep)

    dr = dn.add_parser("record",
                       help="capture real events as offline fixtures, so a "
                            "detection can be graded without a tenant")
    dr.add_argument("--from", dest="source", required=True, metavar="DIR",
                    help="a directory written by `design detections --out`")
    dr.add_argument("--workspace", required=True,
                    help="the Log Analytics workspace to record from")
    dr.add_argument("--out", default="fixtures", metavar="DIR",
                    help="where the .yaml fixtures are written (default: fixtures)")
    dr.add_argument("--window", default="30d", metavar="DURATION",
                    help="how far back to look for events (default: 30d)")
    dr.add_argument("--rows", type=int, default=5, metavar="N",
                    help="rows of each kind to capture (default: 5). More rows "
                         "is more shape variety, not more confidence")
    dr.set_defaults(func=_design_record)

    dsv = dn.add_parser("survey",
                        help="which planned vectors this workspace can grade, "
                             "before you pay to build them")
    dsv.add_argument("--from", dest="source", required=True, metavar="DIR",
                     help="a directory written by `design plan`")
    dsv.add_argument("--workspace", required=True,
                     help="the Log Analytics workspace to measure against")
    dsv.add_argument("--window", default="30d", metavar="DURATION",
                     help="how far back to look for events (default: 30d)")
    dsv.set_defaults(func=_design_survey)

    dg = dn.add_parser("grade",
                       help="run recorded fixtures through the offline KQL "
                            "engine: does each detection fire on the attack and "
                            "stay quiet on the benign")
    dg.add_argument("--fixtures", default="fixtures", metavar="DIR",
                    help="where `design record` wrote them (default: fixtures)")
    dg.set_defaults(func=_design_grade)

    dc = dn.add_parser("coverage",
                       help="which targets were generated, and which were measured")
    dc.add_argument("paths", nargs="*", metavar="DIR",
                    help="directories to scan for report.json (default: .)")
    dc.set_defaults(func=_design_coverage)

    dt = dn.add_parser("tuning",
                       help="what an analyst needs to make a target's rules "
                            "usable: fields, known noise, a baseline query, "
                            "levers and a severity floor")
    dt.add_argument("target", nargs="*", metavar="TARGET",
                    help="one target, or every target when omitted")
    dt.add_argument("--out", metavar="FILE",
                    help="write the markdown to a file instead of stdout")
    dt.set_defaults(func=_design_tuning)

    dl = dn.add_parser("list",
                       help="every target you can design against, or a run's detections")
    dl.add_argument("target", nargs="*", metavar="TARGET",
                    help="explain one target instead of listing them all")
    dl.add_argument("--from", dest="source", metavar="DIR",
                    help="a directory written by `design detections --out`; "
                         "lists its detections instead of the platforms")
    dl.set_defaults(func=_design_list)

    c = sub.add_parser("config", help="store the settings the other verbs need")
    c.add_argument("action", nargs="?", default="show",
                   choices=["show", "set", "path"],
                   help="show what is set and where it came from (default), "
                        "set one KEY=VALUE, or print the file path")
    c.add_argument("assignment", nargs="?", help="KEY=VALUE, for `set`")
    c.set_defaults(func=_config)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    # The one call that makes the engine's progress visible. Without it the
    # `pylon` logger has no handlers, sits at WARNING, and every phase line and
    # per-detection counter the engine emits is discarded before it is
    # formatted -- so a design run printed its header and then nothing at all
    # for the length of a paid model call, which reads as a hang. The run's
    # JSONL record was never written either, for the same reason.
    #
    # It was called only by the test suite, which is why the tests passed and
    # the tool was silent. Entry points install handlers; libraries do not.
    jsonl = logs.configure()
    # What was actually invoked. The record answered "what did it do" and never
    # "what was it asked to do", so a JSONL from a failed run could not be tied
    # to a command line. Secrets never reach argv here -- credentials come from
    # the environment and the config file -- but the workspace name does, and
    # it is the one field that makes a run identifiable, so it stays.
    _cli_log.info("pylon %s", " ".join(sys.argv[1:]) or "(no arguments)",
                  extra={"event": "command",
                         "command": getattr(args, "command", ""),
                         "argv": sys.argv[1:],
                         "jsonl": str(jsonl) if jsonl else ""})
    # Load the file before the verb runs, so `analyze` and `design` see stored
    # settings. `config` does its own apply so it can report the source; doing
    # it twice would be harmless but would make `show` unable to tell a value
    # that came from the file from one that was already in the environment.
    if args.command != "config":
        config.apply()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
