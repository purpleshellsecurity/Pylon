#!/usr/bin/env python3
"""Check every schema asset AND the validator's copy against Microsoft's reference.

The problem this solves shipped and cost a live run. `AZKVAuditLogs.md` described
the DEDICATED Key Vault table using the AzureDiagnostics column convention —
`identity_s`, `id_s`, `httpStatusCode_d`, `CallerIPAddress`. Those are the names
Key Vault logs get when they land in the shared `AzureDiagnostics` table. The
dedicated table has `Identity`, `Id`, `HttpStatusCode`, `CallerIpAddress`. Right
filename, wrong table's columns, so generation was grounded on names that cannot
exist and the workspace refused the query.

Two things make that class of bug survive:

**The types matter as much as the names.** `SQLSecurityAuditEvents.md` taught
`succeeded_s == "true"` as CORRECT and `== true` as WRONG. `Succeeded` is a
`bool`. A name check cannot see that, and it is the more dangerous half: a query
comparing a bool to a string does not error the way a missing column does — it
parses, matches nothing, and the rule is silently dead. So this checks the type a
claim asserts, and the type its example queries IMPLY.

**There is more than one copy.** The asset, `validation/schemas.py`, and a test
all carried the same wrong AZKVAuditLogs columns and drifted together, so
`validate_kql` PASSED the query the workspace refused. Fixing the assets and
leaving the validator approving bad queries reproduces the original bug, so both
are checked here against the same authority.

The authority is Azure Monitor's generated table reference, one page per table at
a deterministic URL:

    .../azure-monitor/reference/tables/<lowercased table name>

It carries a `| Column | Type | Description |` table, which is exactly the two
facts needed. Learn serves it as markdown with `?accept=text/markdown`, so this
parses a documented table rather than scraping rendered HTML.

**It reports; it does not rewrite.** The assets are not a schema dump. They carry
hand-written gotchas, "Fields That DO NOT Exist" sections that are the whole
defence against a model reaching for an AzureDiagnostics name, and parsing rules
learned from failures. A naive sync would delete all of it. What a mismatch needs
is a person reading the reference and deciding, which is what the AZKVAuditLogs
rewrite was.

Usage:
    python scripts/audit-table-schemas.py                 # every asset
    python scripts/audit-table-schemas.py --only AZKVAuditLogs
    python scripts/audit-table-schemas.py --quiet         # counts only

Exit code 1 when anything is contradicted. No Azure credentials: public docs.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.request import ProxyHandler, build_opener, getproxies

BASE = "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables"
# Defender XDR advanced hunting is a DIFFERENT product with a different schema for
# the same table names, and Pylon's defender-endpoint platform targets it on
# purpose — its prompt says "The time column is Timestamp — NOT TimeGenerated."
# The Azure Monitor reference describes the copy Sentinel ingests, where the same
# column is TimeGenerated. Auditing the Device* assets against the wrong one of
# those reports five correct assets as broken, which is how an audit gets
# ignored. So each table is checked against the reference for the product it is
# actually written for.
DEFENDER = "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-{slug}-table"
ASSETS = Path("src/pylon/prompts/assets/tables")
# Column lists read from a real workspace with `getschema`, so a finding can say
# whether it survived contact with a live table or is still one tenant away from
# certainty. Read by every run. The capture path went with `sentinel` in the
# gap-scan removal, so these are frozen: still authoritative until they age
# out, and re-capturing one now means a query by hand. The reference pages are
# authoritative but not infallible (the standard-column omission below is
# documented; `_ResourceId` was reported as fabricated in six tables before that
# was understood), and a live schema is the only thing that settles a
# disagreement. Committed so the settling is not repeated per developer.
SNAPSHOTS = Path("scripts/live-column-snapshots.json")

# How long a captured schema is trusted. Past this a snapshot stops being used —
# it is not merely doubted, it is DROPPED and the run falls back to the reference
# pages. A snapshot both adds columns to the reference and wins on type, so a
# stale one silently suppresses the finding a new upstream column should raise,
# which is the exact failure this script exists to catch. Degrading to the weaker
# authority is the safe direction; trusting old data is not.
#
# 180 days is a convention, not a measurement. Azure Monitor tables gain columns
# on no schedule anyone publishes, and this job runs weekly, so anything at half
# a year has had ample chance to be refreshed.
SNAPSHOT_STALE_DAYS = 180

# These recorded a REAL WORKSPACE's schema into the repository, so what could be
# recorded was bounded to the tables Microsoft documents publicly — the ones this
# directory already has assets for. Their column names are published reference
# material and recording them leaks nothing. The bound still applies to anything
# added by hand.
#
# Custom-log and DCR-created tables are the opposite: their columns are whatever
# the tenant named them, which is internal information about that tenant's
# environment, and a `_CL` table can carry a customer's own field names straight
# into a commit. Nothing outside the documented set is captured, whatever it is
# pointed at.
_CUSTOM_TABLE = re.compile(r"_CL$", re.IGNORECASE)

# --- what a type contradiction is --------------------------------------------
#
# KQL's scalar types collapse into a handful of comparison classes. Two claims
# contradict when their CLASSES differ, not when the words differ: `int` and
# `long` behave the same way against a literal, and flagging that would bury the
# one that matters under noise.

_CLASS = {
    "string": "string", "strings": "string", "guid": "string",
    "int": "numeric", "long": "numeric", "real": "numeric",
    "double": "numeric", "decimal": "numeric",
    "bool": "bool", "boolean": "bool",
    "datetime": "temporal", "timespan": "temporal",
    "dynamic": "dynamic",
}
_TYPE_WORD = re.compile(r"\b(" + "|".join(_CLASS) + r")\b", re.IGNORECASE)

# `dynamic` is compatible with everything by design — a property bag is indexed
# and cast, so an asset saying "string" about a dynamic column is describing what
# comes out of tostring(), not contradicting the reference.
_COMPATIBLE = {"dynamic"}


def _klass(word: str) -> str:
    return _CLASS.get(word.lower(), "")


# --- the authority ------------------------------------------------------------

# Log Analytics STANDARD columns: present on every table in a workspace, and
# documented on their own page rather than on the per-table references —
# https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-standard-columns
# which says outright: "Some of the standard columns won't show in the schema
# view or intellisense in Log Analytics, and they won't show in query results
# unless you explicitly specify the column in the output."
#
# So a per-table page omitting `_ResourceId` is not evidence the column is
# absent, and the first run of this script reported it as fabricated across six
# identity tables. It is real, `LAQueryLogs.md` documents it correctly, and
# deleting it from those assets would have broken working grounding. The
# inconsistency is visible in the pages themselves: AZMSRunTimeAuditLogs lists
# `_ResourceId`, SigninLogs does not.
#
# Types are as the per-table pages give them where they appear at all
# (AZKVAuditLogs and AZMSRunTimeAuditLogs both list four of these); `_ItemId`
# appears on no per-table page, so its type is left unasserted rather than
# guessed — the name is what the fabrication check needs.
_STANDARD_COLUMNS = {
    "TenantId": "string",
    "TimeGenerated": "datetime",
    "_TimeReceived": "datetime",
    "Type": "string",
    "_ItemId": "",
    "_ResourceId": "string",
    "_SubscriptionId": "string",
    "_IsBillable": "string",
    "_BilledSize": "real",
}

# Azure Monitor: | Column | Type | Description |
# Defender XDR:   | `Column` | `type` | Description |   (backticked)
_COLUMN_ROW = re.compile(r"^\|\s*`?([A-Za-z_][A-Za-z0-9_]*)`?\s*\|\s*`?([A-Za-z]+)`?\s*\|")
_COLUMNS_HEADING = ("## Columns", "| Column name |")


def authority(table: str) -> tuple[str, str]:
    """(url, label) — the reference for the product this asset is written for."""
    if table.startswith("Device"):
        return DEFENDER.format(slug=table.lower()), "defender-xdr"
    return f"{BASE}/{table.lower()}", "azure-monitor"


def fetch(table: str, opener) -> str | None:
    """The reference page's markdown, or None on 404."""
    url = f"{authority(table)[0]}?accept=text/markdown"
    try:
        with opener.open(url, timeout=60) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def parse_reference(markdown: str) -> dict[str, str]:
    """{column: type} from the page's Columns table.

    Scoped to the section under `## Columns` so the attributes table above it —
    which has the same two-cell shape — cannot contribute rows.
    """
    body = markdown
    for heading in _COLUMNS_HEADING:
        if heading in body:
            body = body.split(heading, 1)[-1]
            break
    out: dict[str, str] = {}
    for raw in body.splitlines():
        # Learn escapes a leading underscore for markdown, so `_ResourceId`
        # arrives as `\_ResourceId`. Unescaped, the workspace-standard columns
        # would all read as fabrications in every asset that uses them.
        line = raw.replace("\\_", "_")
        match = _COLUMN_ROW.match(line)
        if match and match.group(1) not in ("Column", "Data"):
            out[match.group(1)] = match.group(2).lower()
    return out


# --- documented value sets ----------------------------------------------------
#
# Some column descriptions carry the VALUES a column takes. A wrong value
# parses, validates, executes and matches nothing, so the rule is silently dead.
#
# TWO KINDS, and conflating them manufactures that same bug from the other side:
#
#   "Possible values:"  a CLOSED set. Enforceable.
#   "for example"       illustrative. MUST NOT be enforced -- the pages list
#                       RemoteIPType without `LinkLocal`, which a live workspace
#                       returns, so enforcing would reject a correct query.
#
# The bold-bullet shape is deliberately NOT parsed. DeviceLogonEvents documents
# LogonType as "**Remote interactive (RDP) logons**", which is prose; the value
# is `RemoteInteractive`. Harvesting the label feeds a value that cannot match.
# That set needs confirming against a live table first.
_DESC_ROW = re.compile(
    r"^\|\s*`?([A-Za-z_][A-Za-z0-9_]*)`?\s*\|\s*`?([A-Za-z]+)`?\s*\|\s*(.*?)\s*\|?\s*$"
)
_POSSIBLE = re.compile(r"Possible values:\s*(.+?)(?:\.\s|$)", re.IGNORECASE)
_FOR_EXAMPLE = re.compile(r"\bfor example,?\s+(.+?)(?:\.\s|$)", re.IGNORECASE)
_COLON_LIST = re.compile(
    r":\s*([A-Z][A-Za-z0-9]*(?:\s*,\s*(?:or\s+)?[A-Za-z][A-Za-z0-9]*)+)\s*$"
)
_PAREN_GLOSS = re.compile(r"\s*\([^)]*\)")
_VALUE_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def _split_values(blob: str) -> list[str]:
    """Members of a documented list, or [] if any member does not parse.

    All-or-nothing on purpose: a half-read set is worse than none, because the
    half that parsed would be asserted as the whole vocabulary.
    """
    blob = _PAREN_GLOSS.sub("", blob)
    blob = re.sub(r"\band\b|\bor\b", ",", blob)
    out: list[str] = []
    for part in blob.split(","):
        part = part.strip().strip("`\"'. ")
        if not part:
            continue
        if not _VALUE_TOKEN.match(part):
            return []
        out.append(part)
    return out if len(out) >= 2 else []


def parse_value_sets(markdown: str) -> dict[str, dict]:
    """{column: {"values": [...], "exhaustive": bool}} from the Columns table."""
    body = markdown
    for heading in _COLUMNS_HEADING:
        if heading in body:
            body = body.split(heading, 1)[-1]
            break
    found: dict[str, dict] = {}
    for raw in body.splitlines():
        line = raw.replace("\\_", "_")
        match = _DESC_ROW.match(line)
        if not match or match.group(1) in ("Column", "Data"):
            continue
        column, declared_type, description = (
            match.group(1), match.group(2).lower(), match.group(3)
        )
        if "**" in description:
            continue          # bold-bullet prose — see the note above
        for pattern, exhaustive in (
            (_POSSIBLE, True), (_FOR_EXAMPLE, False), (_COLON_LIST, False)
        ):
            hit = pattern.search(description)
            if not hit:
                continue
            values = _split_values(hit.group(1))
            if values:
                found[column] = {
                    "values": values,
                    "exhaustive": exhaustive,
                    "type": declared_type,
                }
                break
    return found


# --- what an asset claims -----------------------------------------------------

_DENIAL_HEADING = re.compile(r"^###\s+Fields That DO NOT Exist", re.IGNORECASE)
_HEADING = re.compile(r"^###\s+(.*)$")
# `Name` (type) / `A`, `B` (strings — note) — the backticked house style.
_TICKED = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")
_PARENTHETICAL = re.compile(r"^\s*\(([^)]*)\)")
# - Name — TYPE. description   — the older bullet style. The separator must be
# SPACED: `- High-value pairing:` is a compound word, not a column called High.
_BULLET = re.compile(r"^-\s+([A-Za-z_][A-Za-z0-9_]*)\s+[—–-]\s+(.*)$")
# A denial entry: the name being denied is whatever sits left of the arrow.
_DENIAL = re.compile(r"^-\s+`?([A-Za-z_][A-Za-z0-9_]*)`?\s*(?:→|->)")

_KQL_LINE = re.compile(r"\|\s*(?:where|extend|project|summarize|mv-expand|parse|order|sort)\b")
# A line the asset presents as an example of what NOT to write. Its columns are
# being named in order to be rejected, exactly like a denial entry, so counting
# them as claims turns every well-taught gotcha into a false positive.
_COUNTER_EXAMPLE = re.compile(r"\bWRONG\b|❌|\bnever\b|\bdo not\b|\bdon't\b", re.IGNORECASE)
_ASSIGNED = re.compile(r"\b([A-Za-z_]\w*)\s*=(?![=~])")
_ROOT = r"(?<![.\w])([A-Za-z_]\w*)"    # not preceded by a dot: a column, not a sub-field
_STR_CMP = re.compile(
    _ROOT + r"\s*(?:==|!=|=~|!~)\s*['\"]"
    r"|" + _ROOT + r"\s+(?:has|contains|startswith|endswith|has_any|has_all|"
    r"matches\s+regex)\s"
)
_NUM_CMP = re.compile(_ROOT + r"\s*(?:==|!=|>=|<=|>|<)\s*\d")
_BOOL_CMP = re.compile(_ROOT + r"\s*(?:==|!=)\s*(?:true|false)\b")


@dataclass
class Claims:
    """What one asset says about its table."""

    declared: dict[str, str] = field(default_factory=dict)   # column -> asserted class
    referenced: set[str] = field(default_factory=set)        # named in a KQL example
    implied: dict[str, str] = field(default_factory=dict)    # column -> class its examples imply
    denied: set[str] = field(default_factory=set)            # "does not exist here"


def _declared_type(rest: str) -> str:
    """The type a bullet DECLARES, or "" — never a type word it merely contains.

    `- TranslatedIp — destination IP after translation (the real internal target)`
    declares nothing. Reading "real" out of that prose produced a type
    contradiction against a string column, which is the kind of false positive
    that makes an audit get ignored. A declaration is the first word, an
    ALL-CAPS type, or a parenthesised type right after the name.
    """
    rest = rest.strip()
    first = _TYPE_WORD.match(rest)
    if first:
        return _klass(first.group(1))
    paren = _PARENTHETICAL.match(rest)
    if paren:
        word = _TYPE_WORD.search(paren.group(1))
        if word:
            return _klass(word.group(1))
    shouty = re.search(r"\b([A-Z]{3,})\b", rest)
    if shouty and _klass(shouty.group(1)):
        return _klass(shouty.group(1))
    return ""


def parse_asset(text: str) -> Claims:
    """Everything the asset asserts, split by how strongly it asserts it.

    Denials are collected separately and never counted as claims — the whole
    point of that section is to name a column so the model does NOT use it.
    """
    claims = Claims()
    denying = False
    # Accumulated across the whole asset, not per line: the snippets are
    # multi-line, and `| extend NewValue = ...` three lines above `| where
    # NewValue == "false"` is what defines it. Scoping this to one line reported
    # every computed column in every parsing guide as a fabrication. Erring
    # toward "defined" is the right direction for an audit that has to be
    # trusted enough to read.
    computed: set[str] = set()
    for line in text.splitlines():
        heading = _HEADING.match(line)
        if heading:
            denying = bool(_DENIAL_HEADING.match(line))
            continue

        if denying:
            match = _DENIAL.match(line.strip())
            if match:
                claims.denied.add(match.group(1))
            continue

        # Backticked names, optionally sharing one parenthesised type.
        ticks = list(_TICKED.finditer(line))
        for i, tick in enumerate(ticks):
            name = tick.group(1)
            rest = line[tick.end():]
            # The type applies to a run of names ending at the parenthetical, so
            # only look ahead past commas and the remaining names in the run.
            run = rest
            for later in ticks[i + 1:]:
                if not re.match(r"^[,\s`]*$", line[tick.end():later.start()]):
                    break
                run = line[later.end():]
            paren = _PARENTHETICAL.match(run)
            if paren:
                word = _TYPE_WORD.search(paren.group(1))
                if word:
                    claims.declared.setdefault(name, _klass(word.group(1)))

        bullet = _BULLET.match(line)
        if bullet:
            name, rest = bullet.group(1), bullet.group(2)
            claims.declared.setdefault(name, _declared_type(rest))

        if _KQL_LINE.search(line) and not _COUNTER_EXAMPLE.search(line):
            computed |= set(_ASSIGNED.findall(line))
            for pattern, kind in ((_STR_CMP, "string"), (_NUM_CMP, "numeric"),
                                  (_BOOL_CMP, "bool")):
                for match in pattern.finditer(line):
                    name = next(g for g in match.groups() if g)
                    if name not in computed:
                        claims.implied.setdefault(name, kind)
                        claims.referenced.add(name)
    for name in computed:
        claims.declared.pop(name, None)
        claims.referenced.discard(name)
    return claims


# --- the comparison -----------------------------------------------------------

@dataclass
class Findings:
    fabricated: list[str] = field(default_factory=list)
    wrong_case: list[str] = field(default_factory=list)
    wrong_type: list[str] = field(default_factory=list)
    denied_real: list[str] = field(default_factory=list)

    def total(self) -> int:
        return (len(self.fabricated) + len(self.wrong_case)
                + len(self.wrong_type) + len(self.denied_real))


def compare(names: dict[str, str], reference: dict[str, str], *,
            declared: dict[str, str] | None = None,
            implied: dict[str, str] | None = None,
            denied: set[str] | None = None) -> Findings:
    """One source's claims against the reference.

    `names` is every column the source says exists. A name absent from the
    reference entirely is fabricated; one that differs only in case is worse than
    it looks, because KQL column names are case-sensitive and the query fails at
    run time having passed every static check.
    """
    found = Findings()
    lower = {c.lower(): c for c in reference}

    for name in sorted(names):
        if name in reference:
            continue
        real = lower.get(name.lower())
        if real:
            found.wrong_case.append(f"{name} -> {real}")
        else:
            found.fabricated.append(name)

    for source, label in ((declared or {}, "says"), (implied or {}, "example implies")):
        for name, asserted in sorted(source.items()):
            actual = reference.get(name)
            if not actual or not asserted:
                continue    # "" means present but with no type asserted here
            actual_class = _klass(actual)
            if not actual_class or actual_class in _COMPATIBLE or asserted in _COMPATIBLE:
                continue
            if asserted != actual_class:
                found.wrong_type.append(
                    f"{name}: asset {label} {asserted}, reference says {actual} "
                    f"({actual_class})"
                )

    for name in sorted(denied or ()):
        if name in reference:
            found.denied_real.append(name)
    return found


# --- reporting ----------------------------------------------------------------

def load_snapshots() -> tuple[dict[str, dict[str, str]], list[str]]:
    """({table: {column: type}} still in date, [stale table warnings]).

    A snapshot past SNAPSHOT_STALE_DAYS is not returned at all. See the constant
    for why dropping beats doubting.
    """
    if not SNAPSHOTS.is_file():
        return {}, []
    try:
        doc = json.loads(SNAPSHOTS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}, []

    today = datetime.now(timezone.utc).date()
    fresh: dict[str, dict[str, str]] = {}
    stale: list[str] = []
    for table, entry in (doc.get("tables") or {}).items():
        columns = entry.get("columns") or {}
        captured = entry.get("captured_at") or ""
        try:
            age = (today - date.fromisoformat(captured)).days
        except ValueError:
            stale.append(f"{table}: captured_at is missing or unreadable")
            continue
        if age > SNAPSHOT_STALE_DAYS:
            stale.append(
                f"{table}: captured {age} days ago, past the {SNAPSHOT_STALE_DAYS}-day "
                "limit — not used, so findings on it fall back to the reference page"
            )
            continue
        fresh[table] = columns
    return fresh, stale


def _report(rows, quiet: bool) -> None:
    width = max((len(r[0]) for r in rows), default=0)
    for name, cols, claimed, found, source in rows:
        flag = "" if not found.total() else f"   CONTRADICTED {found.total()}"
        note = "" if source == "azure-monitor" else f"  [{source}]"
        print(f"  {name:<{width}}  columns {cols:>3}   claimed {claimed:>3}{note}{flag}")
        if found.total() and not quiet:
            print("      " + ("confirmed against a live table — settled"
                              if source == "live" else
                              "docs-only — no live table has confirmed this yet"))
        if quiet or not found.total():
            continue
        for label, items in (
            ("fabricated ", found.fabricated),
            ("wrong case ", found.wrong_case),
            ("wrong type ", found.wrong_type),
            ("denies real", found.denied_real),
        ):
            for item in items:
                print(f"      {label}  {item}")


VALUE_CATALOG = Path("src/pylon/catalog/column-values.json")


def emit_value_sets(tables: list[str]) -> int:
    """Vendor every documented value set into the catalog the generator reads.

    Same pages, same fetch and same cache as the audit — this reads the half of
    each column row the audit throws away. Writing it is safe in a way that
    rewriting an ASSET would not be: the assets carry gotchas and denial lists
    that a sync would delete, while this file has no hand-written content to
    lose.
    """
    opener = build_opener(ProxyHandler(getproxies()))
    opener.addheaders = [("User-Agent", "pylon-audit-table-schemas")]

    catalog: dict[str, dict] = {}
    exhaustive = illustrative = missing = 0
    for table in tables:
        try:
            markdown = fetch(table, opener)
        except Exception as exc:  # noqa: BLE001 - one bad page must not stop the run
            print(f"  ! {table}: {exc}", file=sys.stderr)
            continue
        if markdown is None:
            missing += 1
            continue
        found = parse_value_sets(markdown)
        if not found:
            continue
        catalog[table] = found
        for spec in found.values():
            if spec["exhaustive"]:
                exhaustive += 1
            else:
                illustrative += 1

    if not catalog:
        # Refusing to write an empty file, for the reason
        # refresh-entra-graph-catalogs.py refuses a short one: a harvest that
        # silently produced nothing would replace real grounding with none.
        print("no value sets parsed — refusing to write an empty catalog",
              file=sys.stderr)
        return 1

    VALUE_CATALOG.parent.mkdir(parents=True, exist_ok=True)
    VALUE_CATALOG.write_text(
        json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {VALUE_CATALOG}: {len(catalog)} tables, "
          f"{exhaustive} enforceable + {illustrative} illustrative value sets"
          + (f" ({missing} tables have no reference page)" if missing else ""))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="one table name")
    ap.add_argument("--quiet", action="store_true", help="counts, no column detail")
    ap.add_argument("--emit-values", action="store_true",
                    help="vendor every DOCUMENTED value set from the same reference "
                         "pages into src/pylon/catalog/column-values.json, which the "
                         "generator and validator read. Network, no credentials")
    args = ap.parse_args()

    if not ASSETS.is_dir():
        print(f"{ASSETS} not found — run from the repo root.", file=sys.stderr)
        return 2

    if args.emit_values:
        return emit_value_sets([p.stem for p in sorted(ASSETS.glob("*.md"))])

    sys.path.insert(0, str(Path("src").resolve()))
    from pylon.validation.schemas import TABLE_SCHEMAS

    snapshots, stale = load_snapshots()
    for warning in stale:
        print(f"  ! stale snapshot  {warning}", file=sys.stderr)

    opener = build_opener(ProxyHandler(getproxies()))
    opener.addheaders = [("User-Agent", "pylon-audit-table-schemas")]

    asset_rows, schema_rows = [], []
    totals = Findings()
    schema_totals = Findings()
    missing_page = failed = 0

    for path in sorted(ASSETS.glob("*.md")):
        table = path.stem
        if args.only and table.lower() != args.only.lower():
            continue
        try:
            markdown = fetch(table, opener)
        except Exception as exc:  # noqa: BLE001 - one bad page must not stop the run
            print(f"  ! {table}: {exc}", file=sys.stderr)
            failed += 1
            continue
        if markdown is None:
            print(f"  ? {table}: no reference page", file=sys.stderr)
            missing_page += 1
            continue

        reference = parse_reference(markdown)
        if reference and authority(table)[1] == "azure-monitor":
            # Only for Log Analytics tables. Defender XDR advanced hunting is a
            # different query surface and these are not its columns.
            for name, kind in _STANDARD_COLUMNS.items():
                reference.setdefault(name, kind)
        if not reference:
            print(f"  ? {table}: reference page has no Columns table", file=sys.stderr)
            missing_page += 1
            continue

        # A live reading beats the page it disagrees with, and adds what the page
        # omits. Where a snapshot exists the findings below survived BOTH, which
        # is what `confirmed` means in the output.
        live = snapshots.get(table) or {}
        reference.update(live)

        claims = parse_asset(path.read_text(encoding="utf-8"))
        # Table names are not columns, and assets legitimately cross-reference
        # each other; drop them before anything is called fabricated.
        others = {p.stem for p in ASSETS.glob("*.md")} | set(TABLE_SCHEMAS)
        named = (set(claims.declared) | claims.referenced) - others
        found = compare(
            {n: "" for n in named}, reference,
            declared=claims.declared, implied=claims.implied, denied=claims.denied,
        )
        asset_rows.append((table, len(reference), len(named), found,
                           "live" if live else authority(table)[1]))
        for attr in ("fabricated", "wrong_case", "wrong_type", "denied_real"):
            getattr(totals, attr).extend(getattr(found, attr))

        # The second copy. Same authority, same run — the two drifting apart is
        # what let a wrong column reach a live workspace with a green validator.
        vendored = TABLE_SCHEMAS.get(table)
        if vendored is not None:
            sfound = compare({c: "" for c in vendored}, reference)
            schema_rows.append((table, len(reference), len(vendored), sfound,
                                "live" if live else authority(table)[1]))
            for attr in ("fabricated", "wrong_case", "wrong_type", "denied_real"):
                getattr(schema_totals, attr).extend(getattr(sfound, attr))

    print("\nASSETS — src/pylon/prompts/assets/tables/*.md")
    _report(asset_rows, args.quiet)
    bad_assets = sum(1 for r in asset_rows if r[3].total())
    print("-" * 78)
    print(f"{len(asset_rows)} assets checked, {len(asset_rows) - bad_assets} clean, "
          f"{bad_assets} contradicted")
    print(f"  {len(totals.fabricated):>3} columns claimed that the reference does not have")
    print(f"  {len(totals.wrong_case):>3} claimed with the wrong case (KQL is case-sensitive)")
    print(f"  {len(totals.wrong_type):>3} type contradictions")
    print(f"  {len(totals.denied_real):>3} real columns denied")

    print("\nVALIDATOR — src/pylon/validation/schemas.py TABLE_SCHEMAS")
    _report(schema_rows, args.quiet)
    bad_schemas = sum(1 for r in schema_rows if r[3].total())
    print("-" * 78)
    print(f"{len(schema_rows)} vendored schemas checked, "
          f"{len(schema_rows) - bad_schemas} clean, {bad_schemas} contradicted")
    print(f"  {len(schema_totals.fabricated):>3} columns validate_kql would approve that "
          "do not exist")
    print(f"  {len(schema_totals.wrong_case):>3} with the wrong case")

    if stale:
        print(f"\n{len(stale)} snapshot(s) past {SNAPSHOT_STALE_DAYS} days and therefore "
              "IGNORED — those tables were checked against documentation only.")
        print("  No refresh path: the live capture went with `sentinel`. Re-run "
              "`getschema` by hand and edit the file, or drop the entry.")
    if missing_page or failed:
        print(f"\n{missing_page} without a usable reference page; {failed} failed to fetch")
    print("\nNothing was rewritten. A mismatch needs a person reading the reference:\n"
          "the assets carry gotchas and denial lists a sync would delete.")
    return 1 if (bad_assets or bad_schemas or failed) else 0


if __name__ == "__main__":
    raise SystemExit(main())
