#!/usr/bin/env python3
"""Re-measure every table contract against a live workspace.

A contract is a set of claims about what a table contains -- which columns never
carry a value, how the outcome is typed, what has to be true before a row names
a principal -- and every one of them was measured once, by hand, against one
tenant on one day. Nothing re-checks them. A schema change, a new category, or a
claim that was only ever true of a quiet lab would sit in the catalogue
indefinitely, teaching a model something false and asserting it in a gate.

    python scripts/verify-contracts.py --workspace <name|id|guid> [--days 30]

Read-only. Three checks per contract:

  recipes        every query shape in the contract is RUN. A contract that
                 cannot execute is not a contract, and the recipes are what the
                 prompt tells a model to adapt.
  emptiness      every column claimed never-populated is re-counted. One that
                 has started carrying data makes the gate reject correct work.
  attribution    the claim that a row only names a principal under some
                 condition is re-counted both ways.

A table with no rows is reported UNVERIFIED, never as passing. "Nobody looked"
and "looked and agreed" are different answers and the whole tool exists to keep
them apart.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _operations_doc() -> dict:
    """`data-plane-operations.yaml`, keyed by table."""
    import yaml

    text = (ROOT / "src/pylon/catalog/data-plane-operations.yaml").read_text(encoding="utf-8")
    return (yaml.safe_load(text) or {}).get("tables") or {}


def run(guid: str, kql: str) -> tuple[list, str]:
    proc = subprocess.run(
        ["az", "monitor", "log-analytics", "query", "-w", guid,
         "--analytics-query", kql, "-o", "json"],
        capture_output=True, text=True, timeout=300)
    if proc.returncode:
        detail = re.sub(r"\s+", " ", proc.stderr).strip()
        return [], detail[:160]
    return json.loads(proc.stdout or "[]"), ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--table", default="", help="verify one table only")
    args = ap.parse_args()

    sys.path.insert(0, str(ROOT / "src"))
    from pylon import contracts, validate

    _t, _a, guid = validate.resolve(args.workspace)
    window = f"{args.days}d"
    tables = [args.table] if args.table else sorted(contracts.tables())
    failures = 0

    for table in tables:
        c = contracts.for_table(table)
        if not c:
            print(f"{table}: NO CONTRACT"); failures += 1; continue

        rows, err = run(guid, f"{table} | where TimeGenerated > ago({window}) | count")
        if err:
            print(f"\n{table}: UNVERIFIED — {err}"); continue
        total = int(rows[0].get("Count", 0)) if rows else 0
        if not total:
            print(f"\n{table}: UNVERIFIED — no rows in {window}, so none of its "
                  f"claims can be re-measured")
            continue
        print(f"\n{table}: {total} rows in {window}")

        # 1. an operation this tenant really writes, to instantiate recipes with
        ops, _ = run(guid, f"{table} | where TimeGenerated > ago({window}) "
                           f"| summarize n=count() by {c['operation']['column']} "
                           f"| top 1 by n desc")
        operation = (ops[0].get(c["operation"]["column"]) if ops else "") or ""

        for name, body in (c.get("recipes") or {}).items():
            fields = set(re.findall(r"\{(\w+)\}", body))
            filled = body.format(**{
                f: {"table": table, "window": window, "operation": operation,
                    "threshold": "0", "array": "logs",
                    "category": "", "operations": f'"{operation}"'}.get(f, "x")
                for f in fields})
            _r, err = run(guid, filled)
            print(f"   {'FAIL' if err else 'ok  '}  recipe {name}"
                  + (f" — {err}" if err else ""))
            failures += bool(err)

        # 2. columns the contract says are never populated
        never = list(c.get("never_populated") or [])
        if table == "StorageBlobLogs":
            never += list(c.get("never_populated_blob_only") or [])
        schema, _ = run(guid, f"{table} | getschema | project ColumnName, ColumnType")
        present = {r["ColumnName"] for r in schema}
        absent = [col for col in never if col not in present]
        if absent:
            print(f"   FAIL  emptiness — the contract names {absent}, which "
                  f"{table} does not have")
            failures += 1
        never = [col for col in never if col in present]
        if never:
            # KQL names an aggregate `name = expr`, not `expr as name`. And
            # isnotempty() is a string function: a never-populated column can be
            # typed int or bool, so it goes through tostring() first.
            counts = ", ".join(
                f"{col} = countif(isnotempty(tostring({col})))" for col in never)
            got, err = run(guid, f"{table} | where TimeGenerated > ago({window}) "
                                 f"| summarize {counts}")
            if err:
                print(f"   FAIL  emptiness — {err}"); failures += 1
            else:
                live = {k: int(v) for k, v in (got[0] if got else {}).items()
                        if k in never and int(v or 0) > 0}
                if live:
                    print(f"   FAIL  emptiness — now carrying data: {live}. The "
                          f"contract says these are always empty and a gate "
                          f"rejects queries that read them.")
                    failures += 1
                else:
                    print(f"   ok    emptiness — {len(never)} columns still empty")

        # 1b. TYPING. Never checked until now, and it should have been from the
        # start: `typing` reaches the prompt AND the gate, and nothing
        # re-measured it, so every type claim in every contract had been
        # asserted once and never looked at again. Found by a reader comparing
        # FunctionAppLogs.EventId -- contracted as string, int in the live
        # schema and int in Microsoft's own reference.
        #
        # A wrong type is not cosmetic: `EventId == "5"` against an int column
        # does not compile, and the model is told the type by the contract.
        typed = {k: v for k, v in (c.get("typing") or {}).items()
                 # AzureDiagnostics types by SUFFIX (suffix_s, suffix_g) rather
                 # than by column, because every column there is a string
                 # whatever its name ends with. Those are not column names.
                 if not str(k).startswith("suffix_")}
        if typed:
            live = {r["ColumnName"]: r["ColumnType"] for r in schema}
            # KQL reports the same numeric type under two names depending on the
            # column's origin, and a contract saying `int` where the schema says
            # `long` is not a defect a query could ever notice.
            same = {("int", "long"), ("long", "int"), ("real", "double"),
                    ("double", "real")}
            wrong, missing = [], []
            for column, claimed in typed.items():
                actual = live.get(column)
                if actual is None:
                    missing.append(column)
                elif actual != claimed and (claimed, actual) not in same:
                    wrong.append(f"{column}: contract says {claimed}, "
                                 f"schema says {actual}")
            if wrong or missing:
                if wrong:
                    print(f"   FAIL  typing — {'; '.join(wrong)}")
                    failures += 1
                if missing:
                    print(f"   FAIL  typing — the contract types {missing}, "
                          f"which {table} does not have")
                    failures += 1
            else:
                print(f"   ok    typing — {len(typed)} column type(s) match "
                      f"the live schema")

        # 2a. columns the contract calls EFFECTIVELY empty, with a count.
        # A claim with a number in it needs the number re-measured, or it is
        # the same drift as an unchecked emptiness claim with a softer word.
        # AzureActivity.OperationId sat in never_populated until this script
        # caught fourteen rows carrying it; the replacement claim says which
        # fourteen, and this is what keeps that honest.
        for column, detail in (c.get("effectively_empty") or {}).items():
            got, err = run(guid, f"{table} | where TimeGenerated > ago({window}) "
                                 f"| summarize rows = countif(isnotempty("
                                 f"tostring({column}))), total = count()")
            if err:
                print(f"   FAIL  effectively_empty {column} — {err}"); failures += 1
                continue
            rows = int((got[0] if got else {}).get("rows") or 0)
            total = int((got[0] if got else {}).get("total") or 0) or 1
            share = 100.0 * rows / total
            claimed = 100.0 * int(detail.get("rows") or 0) / (int(detail.get("of") or 1))
            # One percent of rows is no longer "effectively empty": at that
            # point a detection could reasonably read it and the contract owes
            # the reader a real answer rather than "treat as empty".
            if share > max(1.0, claimed * 10):
                print(f"   FAIL  effectively_empty {column} — now on {rows} of "
                      f"{total} rows ({share:.2f}%); the contract claims "
                      f"{detail.get('rows')} of {detail.get('of')} "
                      f"({claimed:.2f}%). Re-measure and say what it carries.")
                failures += 1
            else:
                print(f"   ok    effectively_empty {column} — {rows}/{total} "
                      f"({share:.2f}%), still not usable")

        # 2c. a MEASURED operation vocabulary, re-measured.
        # Every other vocabulary in data-plane-operations.yaml is hand-written
        # from Microsoft's published list and checked against a harvest of it.
        # AppServiceFileAuditLogs has no published list, so it declares
        # `source: measured` and is exempt from that comparison -- and this is
        # what the exemption costs. Without it, "measured" would be a word that
        # bought a table out of the only check it had.
        ops_doc = _operations_doc().get(table) or {}
        if ops_doc.get("source") == "measured":
            column = (c.get("operation") or {}).get("column") or "OperationName"
            got, err = run(guid, f"{table} | where TimeGenerated > ago({window}) "
                                 f"| summarize by {column}")
            if err:
                print(f"   FAIL  vocabulary — {err}"); failures += 1
            else:
                live = {str(r.get(column)) for r in got if r.get(column)}
                claimed = set(ops_doc.get("operations") or {})
                unseen = sorted(claimed - live)
                unclaimed = sorted(live - claimed)
                if unseen or unclaimed:
                    if unseen:
                        print(f"   FAIL  vocabulary — claimed and never produced: "
                              f"{unseen}")
                        failures += 1
                    if unclaimed:
                        print(f"   FAIL  vocabulary — the workspace produced "
                              f"{unclaimed}, which the catalogue does not name")
                        failures += 1
                else:
                    print(f"   ok    vocabulary — {len(claimed)} measured "
                          f"operation(s), all still produced and none missing")

        # 2b. per-service sections. A shared table's claims are per provider
        # and category, and checking only the table-level ones reported a clean
        # bill for a contract whose real content had never been re-measured.
        for key, section in (c.get("services") or {}).items():
            provider, _, category = key.partition("/")
            scope = (f'| where ResourceProvider =~ "{provider}" '
                     f'| where Category =~ "{category}"')
            for column, values in (section.get("observed_values") or {}).items():
                if column.endswith("_note") or not isinstance(values, list):
                    continue
                got, err = run(guid, f"""{table} | where TimeGenerated > ago({window})
{scope} | summarize n = count() by {column}""")
                if err:
                    print(f"   FAIL  {key} / {column} — {err}"); failures += 1; continue
                live = {r[column] for r in got if r.get(column)}
                if not live:
                    print(f"   --    {key} / {column} — no rows to re-measure")
                    continue
                unseen = sorted(live - {str(v) for v in values})
                if unseen:
                    print(f"   FAIL  {key} / {column} — now also holds {unseen}, "
                          f"which the contract does not list, so a generated "
                          f"detection will never be taught them")
                    failures += 1
                else:
                    print(f"   ok    {key} / {column} — {len(live)} value(s) still as recorded")
            for column in (section.get("redacted") or []):
                got, err = run(guid, f"""{table} | where TimeGenerated > ago({window})
{scope} | summarize unredacted = countif({column} != "{{scrubbed}}" and isnotempty({column}))""")
                if not err and got and int(got[0].get("unredacted", 0)) > 0:
                    print(f"   FAIL  {key} / {column} — recorded as always redacted "
                          f"and {got[0]['unredacted']} row(s) carry a real value")
                    failures += 1
                elif not err:
                    print(f"   ok    {key} / {column} — still redacted")
                else:
                    print(f"   FAIL  {key} / {column} — {err}"); failures += 1

        # 3. the attribution gate, re-counted both ways
        attribution = c.get("attribution") or {}
        gate = attribution.get("gate")
        who = (c.get("roles") or {}).get("who")
        parts = str(gate).split(None, 2) if gate else []
        if gate and len(parts) != 3:
            # A gate is a `column op value` comparison. Anything else is a
            # malformed contract and gets REPORTED -- unpacking it blindly
            # crashed the whole run and reported nothing about the eleven
            # other contracts.
            print(f"   FAIL  attribution — gate {gate!r} is not a "
                  f"`column op value` comparison")
            failures += 1
        elif gate and who and not who.startswith(("see ", "none")):
            column, _op, value = parts
            # "Unattributed" has two shapes and counting only emptiness sees
            # one of them. The storage family leaves the principal column EMPTY
            # when its gate fails; AppServiceAuditLogs fills it with the
            # site-level publishing credential "$sitename", which is not empty
            # and names nobody. A contract that says which shape it means gets
            # checked for that shape.
            placeholder = attribution.get("placeholder_matches") or ""
            if attribution.get("unattributed") == "placeholder" and placeholder:
                names = (f'isnotempty({who}) and not({who} matches regex '
                         f'@"{placeholder}")')
            else:
                names = f"isnotempty({who})"
            got, err = run(guid, f"""{table} | where TimeGenerated > ago({window})
| extend gated = {column} {_op} {value}
| summarize rows=count(), named=countif({names}) by gated""")
            if err:
                print(f"   FAIL  attribution — {err}"); failures += 1
            else:
                broken = [r for r in got
                          if (str(r["gated"]).lower() == "true" and int(r["named"]) != int(r["rows"]))
                          or (str(r["gated"]).lower() == "false" and int(r["named"]) != 0)]
                if broken:
                    print(f"   FAIL  attribution — {gate} no longer decides it: {broken}")
                    failures += 1
                else:
                    print(f"   ok    attribution — {gate} still decides it")

    print(f"\n{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
