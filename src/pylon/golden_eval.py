"""Golden-set evaluation: does a detection actually fire on an attack and stay
quiet on benign traffic?

Static + offline-parse checks prove a query is syntactically sound; they say
nothing about whether it DETECTS. This harness runs a query against a datatable
seeded with ONE labeled event at a time in the offline KQL engine (kustainer): a
true-positive event must produce a row, a true-negative event must not. From that,
per-detection precision and recall — a real pass/fail, in CI, with no tenant.

Fixtures pair a query pattern with typed events (see catalog/golden/*.yaml). The
row-execution executor is injectable, so the precision/recall logic is unit-tested
without a container.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from importlib import resources

import yaml
from pydantic import BaseModel

from .kusto_offline import _kusto_type, schema_for_table


class GoldenResult(BaseModel):
    """Confusion-matrix outcome of running one query over its labeled events."""

    tp: int = 0  # true-positive events that matched (good)
    fn: int = 0  # true-positive events that did NOT match (missed detection)
    fp: int = 0  # true-negative events that matched (false alarm)
    tn: int = 0  # true-negative events that did NOT match (good)
    errors: list[str] = []

    @property
    def precision(self) -> float | None:
        d = self.tp + self.fp
        return round(self.tp / d, 3) if d else None

    @property
    def recall(self) -> float | None:
        d = self.tp + self.fn
        return round(self.tp / d, 3) if d else None

    @property
    def passed(self) -> bool:
        """Every labeled event classified correctly and nothing errored."""
        return self.fn == 0 and self.fp == 0 and not self.errors and (self.tp + self.tn) > 0


class FixtureResult(BaseModel):
    """Whether a detection fired on the attack rows and stayed quiet on the
    benign ones. Counts rather than booleans, because "fired on 6 of 4 attack
    rows" says the query is multiplying and that is a defect the live check
    calls `over`."""

    on_attack: int | None = None   # rows returned with only the tp set loaded
    on_benign: int | None = None   # rows returned with only the tn set loaded
    errors: list[str] = []

    @property
    def fires(self) -> bool:
        return bool(self.on_attack)

    @property
    def quiet(self) -> bool:
        return self.on_benign == 0

    @property
    def passed(self) -> bool:
        """Fired on the attack, silent on the benign, nothing errored."""
        return self.fires and self.quiet and not self.errors

    @property
    def verdict(self) -> str:
        if self.errors:
            return "error"
        if self.on_attack is None:
            return "not-run"
        if not self.fires:
            # Not necessarily wrong: it may need more rows than a fixture holds
            # to cross its own threshold.
            return "silent"
        return "fires" if self.quiet else "noisy"


def _kql_literal(value, kusto_type: str) -> str:
    """Render a Python value as a KQL scalar literal of the given Kusto type."""
    kt = _kusto_type(kusto_type)
    if value is None:
        # A datatable literal will not take `string(null)`. Kusto accepts the
        # typed null for dynamic, datetime and the numerics, and refuses it for
        # string -- the whole script comes back as a bad request and every event
        # in the fixture errors.
        #
        # This never surfaced because the harness was only ever exercised with
        # an injected row_counter, so no real engine had seen the script it
        # builds. A fixture with any unspecified string column -- which is every
        # recorded fixture, since a real row leaves most of a 37-column table
        # empty -- could not be graded at all.
        return '""' if kt == "string" else f"{kt}(null)"
    if kt in ("int", "long", "real", "decimal"):
        return str(value)
    if kt == "bool":
        return "true" if value else "false"
    if kt == "datetime":
        return f"datetime({value})"
    if kt == "dynamic":
        return f"dynamic({json.dumps(value)})"
    return f'"{str(value).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'


def build_single_row_script(kql: str, table: str, schema: dict[str, str], row: dict) -> str:
    """A script that declares `table` as a one-row datatable populated with `row`
    (values rendered as typed literals; unspecified columns get a type-appropriate
    empty), then runs the query. `<query> | count` tells the caller if it matched."""
    cols = dict(schema)
    for injected, typ in (("TimeGenerated", "datetime"), ("Type", "string"), ("_ResourceId", "string")):
        cols.setdefault(injected, typ)
    names = list(cols)
    decl = ", ".join(f"{n}:{_kusto_type(cols[n])}" for n in names)
    literals = ", ".join(_kql_literal(row.get(n), cols[n]) for n in names)
    body = kql.strip().rstrip(";").rstrip()
    return f"let {table} = datatable({decl}) [ {literals} ];\n{body}\n| count"


def build_set_script(kql: str, table: str, schema: dict[str, str],
                     rows: list[dict]) -> str:
    """A script declaring `table` as a datatable holding ALL of `rows`, then
    running the query.

    One row at a time cannot grade most of what this tool generates. An ARM role
    grant writes TWO rows -- a `Start` carrying the request body that says which
    role, and a `Success` carrying the outcome -- and the detection joins them on
    CorrelationId. Hand that query a one-row table and the join has nothing to
    join to, so it returns nothing: the detection is correct and the test is
    wrong. The same is true of anything comparing against a baseline, deduping
    on EventDataId, or counting toward a threshold.

    The query's own time bound is widened, because a recorded row is fixed in
    time and the query says `ago(1h)`. Without that a fixture stops grading the
    moment it is older than the window its detection happens to use, which makes
    a recording expire -- the one property the whole idea exists to avoid.
    """
    cols = dict(schema)
    for injected, typ in (("TimeGenerated", "datetime"), ("Type", "string"),
                          ("_ResourceId", "string")):
        cols.setdefault(injected, typ)
    names = list(cols)
    decl = ", ".join(f"{n}:{_kusto_type(cols[n])}" for n in names)
    literals = ",\n  ".join(
        ", ".join(_kql_literal(r.get(n), cols[n]) for n in names) for r in rows)
    from .verification import widen

    body, _widened = widen(kql.strip().rstrip(";").rstrip(), "3650d")
    return f"let {table} = datatable({decl}) [\n  {literals}\n];\n{body}\n| count"


def evaluate_fixture(
    kql: str,
    table: str,
    schema: dict[str, str],
    events: list[dict],
    *,
    row_counter: Callable[[str], int] | None = None,
    url: str | None = None,
) -> "FixtureResult":
    """Does this detection fire on the attack and stay quiet on the benign?

    The whole `tp` set is loaded and the query must return SOMETHING; the whole
    `tn` set is loaded and it must return NOTHING. That is the question a
    detection is actually asked in production, and unlike per-row grading it
    survives a join.

    A detection that fires on neither is not necessarily wrong. It may count
    toward a threshold no four-row fixture can cross, which is the same
    `aggregates` caveat the live check carries, and is reported rather than
    scored as a miss.
    """
    if row_counter is None:
        url = url or os.environ.get("PYLON_KUSTAINER_URL", "")
        if not url:
            return FixtureResult(errors=["no kustainer endpoint (set PYLON_KUSTAINER_URL)"])
        row_counter = _kustainer_row_counter(url)

    res = FixtureResult()
    for label, attr in (("tp", "on_attack"), ("tn", "on_benign")):
        rows = [{k: v for k, v in e.items() if k != "label"}
                for e in events if e.get("label") == label]
        if not rows:
            continue
        try:
            setattr(res, attr, row_counter(build_set_script(kql, table, schema, rows)))
        except Exception as exc:  # noqa: BLE001 - one bad set shouldn't sink the rest
            res.errors.append(f"{label}: {type(exc).__name__}: {exc}")
    return res


def evaluate_detection(
    kql: str,
    table: str,
    schema: dict[str, str],
    events: list[dict],
    *,
    row_counter: Callable[[str], int] | None = None,
    url: str | None = None,
) -> GoldenResult:
    """Run `kql` against each event (label 'tp'/'tn') one row at a time and tally the
    confusion matrix. `row_counter(script) -> int` returns the query's row count for a
    one-row datatable (>0 = matched); it is injectable for testing, otherwise a
    kustainer endpoint is used (arg `url` or PYLON_KUSTAINER_URL)."""
    if row_counter is None:
        url = url or os.environ.get("PYLON_KUSTAINER_URL", "")
        if not url:
            return GoldenResult(errors=["no kustainer endpoint (set PYLON_KUSTAINER_URL)"])
        row_counter = _kustainer_row_counter(url)

    res = GoldenResult()
    for ev in events:
        label = ev.get("label")
        row = {k: v for k, v in ev.items() if k != "label"}
        script = build_single_row_script(kql, table, schema, row)
        try:
            matched = row_counter(script) > 0
        except Exception as exc:  # noqa: BLE001 — one bad event shouldn't sink the eval
            res.errors.append(f"{type(exc).__name__}: {exc}")
            continue
        if label == "tp":
            res.tp += 1 if matched else 0
            res.fn += 0 if matched else 1
        elif label == "tn":
            res.fp += 1 if matched else 0
            res.tn += 0 if matched else 1
    return res


def load_golden_cases() -> list[dict]:
    """Every vendored golden-set case (catalog/golden/*.yaml). Each case is
    {name, table, query, events:[{label, ...cols}]}. Empty when the dir is absent."""
    cases: list[dict] = []
    try:
        root = resources.files("pylon.catalog").joinpath("golden")
        if not root.is_dir():
            return cases
        for entry in root.iterdir():
            if entry.name.endswith((".yaml", ".yml")):
                doc = yaml.safe_load(entry.read_text(encoding="utf-8")) or {}
                if doc.get("query") and doc.get("events"):
                    cases.append(doc)
    except (FileNotFoundError, OSError):
        pass
    return cases


def run_golden_suite(
    *, row_counter: Callable[[str], int] | None = None, url: str | None = None
) -> dict[str, GoldenResult]:
    """Evaluate every vendored golden case, returning {case name: GoldenResult}.
    Schema per case comes from the table's catalog/hardcoded columns, unioned with
    the columns the events reference (so a fixture can exercise a column the curated
    schema omits)."""
    out: dict[str, GoldenResult] = {}
    for case in load_golden_cases():
        schema = dict(schema_for_table(case["table"]))
        for ev in case["events"]:
            for col in ev:
                if col != "label":
                    schema.setdefault(col, "string")
        out[case["name"]] = evaluate_detection(
            case["query"], case["table"], schema, case["events"],
            row_counter=row_counter, url=url,
        )
    return out


def _kustainer_row_counter(url: str) -> Callable[[str], int]:
    """Default row_counter: POST the `| count` script to kustainer, return the count
    (or raise on a query error so the caller records it)."""

    def count(script: str) -> int:
        import httpx

        endpoint = url.rstrip("/") + "/v1/rest/query"
        res = httpx.post(endpoint, json={"db": "NetDefaultDB", "csl": script}, timeout=20.0)
        if res.status_code != 200:
            detail = res.text
            try:
                detail = json.loads(res.text).get("error", {}).get("message", res.text)
            except (ValueError, AttributeError):
                pass
            raise RuntimeError(f"HTTP {res.status_code}: {detail}")
        # A `| count` query returns a single Count column in the primary table.
        payload = res.json()
        tables = payload.get("Tables") or payload.get("tables") or []
        for t in tables:
            rows = t.get("Rows") or t.get("rows") or []
            if rows and rows[0]:
                return int(rows[0][0])
        return 0

    return count
