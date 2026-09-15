"""Loader for the table -> candidate ATT&CK technique index (`table-techniques.yaml`).

This is the REVERSE of the direction generation runs in. Generation goes
service -> tables -> techniques; the gap scan needs, given the tables that have
data, which techniques are even detectable in this tenant. No catalog in the repo
answered that, so the index is a hand-authored file and this module is the only
way to read it.

Two lookups, and the difference between them is the whole honesty argument:

    candidates(table)        every technique the table's telemetry could support
    techniques_for(table, op) only the techniques a specific operation pins down

`techniques_for` returning nothing does NOT mean "not covered" — it means the
operation was not distinctive enough (or the table has no operation vocabulary at
all). Callers must degrade to table resolution there, never to "uncovered".
"""

from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

import yaml

from ..library import _slug
from ..scoring import normalize_technique_id

_INDEX_FILE = "table-techniques.yaml"


@dataclass(frozen=True)
class TableTechnique:
    """One curated (table, technique) claim and the telemetry that evidences it."""

    table: str
    technique: str            # normalized ATT&CK ID, e.g. "T1555.006"
    operations: tuple[str, ...]  # slugified operation literals; () = table resolution only
    basis: str
    # WHY this table is the technique's primary home, when it is. Not a label:
    # there is no `primary: true` in the index, the field's value IS the argument,
    # so the fact cannot be asserted without being made. Empty is the default and
    # claims nothing either way. At most one table per technique may carry it —
    # asserted by tests/test_table_techniques.py, since two would leave the table
    # tie-break undefined.
    primary: str = ""
    # The operation literals as the log actually spells them. Kept alongside the
    # slugs because matching wants a slug and a PROMPT wants the exact string --
    # teaching a model "new-inboxrule" would have it emit a value no log contains.
    raw_operations: tuple[str, ...] = ()

    def operation_scoped(self) -> bool:
        """True when this claim can be matched at operation resolution."""
        return bool(self.operations)

    def is_primary(self) -> bool:
        """True when this claim argues it is the technique's primary home."""
        return bool(self.primary)


@dataclass(frozen=True)
class TableEntry:
    """One indexed table: its platform, an optional caveat, and its claims."""

    table: str
    platform: str
    plane: str
    note: str
    techniques: tuple[TableTechnique, ...]


# The shortest thing that could still be an argument. `primary: yes` would parse
# as a bool and `primary: canonical` as a one-word label, and both would defeat
# the point of putting the reason IN the field — so the loader refuses them rather
# than degrading to a silent flag.
_MIN_REASON = 40


def _reason(value, table, technique) -> str:
    """`primary`'s value, or "" when absent. Raises when it is not an argument."""
    if value is None:
        return ""
    where = f"{table} / {technique}"
    if not isinstance(value, str):
        raise TypeError(
            f"table-techniques.yaml: {where} has `primary: {value!r}`. There is no "
            "boolean form — the field's value must be the REASON this table is the "
            "technique's primary home, so the claim cannot be made without an "
            "argument for it."
        )
    reason = " ".join(value.split())
    if len(reason) < _MIN_REASON:
        raise ValueError(
            f"table-techniques.yaml: {where} has `primary: {reason!r}`, which is a "
            f"label rather than a reason (under {_MIN_REASON} characters). Say why "
            "this table is the primary home for the technique and what the other "
            "candidates evidence instead."
        )
    return reason


@lru_cache(maxsize=1)
def _load() -> dict[str, TableEntry]:
    """Parse the vendored index into table -> TableEntry. Empty if unavailable."""
    try:
        text = (resources.files(__name__.rsplit(".", 1)[0]) / _INDEX_FILE).read_text(
            encoding="utf-8"
        )
    except (FileNotFoundError, OSError):
        return {}
    doc = yaml.safe_load(text) or {}
    out: dict[str, TableEntry] = {}
    for table, block in (doc.get("tables") or {}).items():
        claims = tuple(
            TableTechnique(
                table=table,
                technique=normalize_technique_id(str(e["id"])),
                operations=tuple(_slug(o) for o in (e.get("operations") or []) if _slug(o)),
                basis=str(e.get("basis", "")),
                primary=_reason(e.get("primary"), table, e.get("id")),
                raw_operations=tuple(str(o) for o in (e.get("operations") or []) if str(o).strip()),
            )
            for e in (block.get("techniques") or [])
        )
        out[table] = TableEntry(
            table=table,
            platform=str(block.get("platform", "")),
            plane=str(block.get("plane", "")),
            note=" ".join(str(block.get("note", "")).split()),
            techniques=claims,
        )
    return out


def index() -> dict[str, TableEntry]:
    """The whole index, table -> TableEntry."""
    return _load()


def indexed_tables() -> set[str]:
    """Every table this index has an opinion about."""
    return set(_load())


def has_table(table: str) -> bool:
    """True when the index knows what `table` can support. False means 'unknown',
    NOT 'nothing' — callers must report those tables rather than drop them."""
    return table in _load()


def entry(table: str) -> TableEntry | None:
    """The index entry for `table`, or None when it isn't indexed."""
    return _load().get(table)


def candidates(table: str) -> tuple[TableTechnique, ...]:
    """Every technique claim for `table` — the candidate set the gap is computed
    against. Empty tuple for an unindexed table."""
    e = _load().get(table)
    return e.techniques if e else ()


def primary_table(technique: str) -> tuple[str, str]:
    """(table, reason) that argues it is `technique`'s primary home, or ("", "").

    The index is keyed table -> techniques and this question runs the other way,
    so it is answered by scanning rather than by a second block keyed by
    technique. Deliberate: a technique -> table map is a second place the same
    truth lives, and it goes stale invisibly — a table added later that should be
    primary is simply missing from it, with nothing to notice. Scanning the claims
    means the fact sits beside the claim it qualifies and an author adding a table
    is in front of the question.
    """
    for table, entry in sorted(_load().items()):
        for claim in entry.techniques:
            if claim.technique == technique and claim.primary:
                return table, claim.primary
    return "", ""


def techniques_for(table: str, operation_slug: str) -> set[str]:
    """Techniques that `operation_slug` pins down in `table`, at OPERATION
    resolution. Empty when the operation is unknown or the table has no
    separating vocabulary — which means 'cannot tell', not 'no'."""
    return {
        c.technique
        for c in candidates(table)
        if operation_slug and operation_slug in c.operations
    }


def basis_for(table: str, operation: str, technique: str) -> str:
    """Why THIS operation argues for `technique`, or "".

    Scoped by operation, because a technique id is not unique within a table.
    `T1685.002` on AzureActivity has three separate claims -- diagnostic
    settings, Key Vault, and SQL auditing -- each with its own prose, and
    twelve technique ids on that table collide the same way, one discarding
    four alternatives.

    A caller keying a dict by technique alone keeps whichever entry came last.
    A diagnostic-settings detection was rendered under a heading saying "why
    this technique" with the SQL auditing argument beneath it: text about
    extendedAuditingSettings and Ledger digest uploads, on a query that touches
    none of them and does not read SQLSecurityAuditEvents.

    That was a REGRESSION EXPOSED BY A FIX. Before technique ids were
    normalised onto their current spellings, the run said T1685.002 while the
    catalogue said T1562.008, the lookup missed, and the section was simply
    absent. Making the two sides agree turned a missing section into a
    confidently wrong one, which is worse: curated prose under a specific
    heading gives a reader no reason to doubt it.
    """
    wanted = normalize_technique_id(str(technique))
    slug = _slug(operation)
    for claim in candidates(table):
        if not claim.basis:
            continue
        if normalize_technique_id(claim.technique) != wanted:
            continue
        if slug and slug in claim.operations:
            return claim.basis
    return ""


def second_opinion(table: str, operation: str, claimed: str) -> tuple[str, ...]:
    """What the index pins for `operation`, when that differs from `claimed`.

    Three answers, not two, and the empty tuple carries two of them:

        the index pins nothing for this operation   cannot tell
        it pins exactly what was claimed            agree
        it pins something else                      the pinned techniques

    "Cannot tell" and "agree" are both silence to a caller, deliberately: the
    only thing worth a line on screen is a real disagreement. Everything else
    would be a report of a non-event.

    Exists because nothing checked the model's technique against the index that
    already knows the answer. A live run mapped CertificateGet, SecretList and
    KeyList to T1555.006 and then wrote "unmapped" for CertificateList, which
    the index pins to the same technique -- one slip in thirty-three, invisible.

    It reports rather than corrects. The disagreement RATE is the signal: one
    row is a model slip you ignore, ten rows means the prompt is fighting the
    index or the index is wrong, and a caller that silently rewrites the label
    destroys the evidence for both. The model is sometimes the one that is right.
    """
    pinned = techniques_for(table, _slug(operation))
    if not pinned:
        return ()
    if normalize_technique_id(str(claimed)) in pinned:
        return ()
    return tuple(sorted(pinned))


def render_for_prompt(
    table: str, max_techniques: int = 24
) -> str:
    """The table's curated technique vocabulary, as a prompt block.

    Exists because technique selection was the one grounded thing that wasn't.
    A generation prompt hands the model a documented OPERATION vocabulary and
    then says only "do not fabricate MITRE mappings" about techniques — a
    negative constraint with nothing positive behind it. So the model recalls a
    technique instead of choosing from a list, and a real-but-wrong ID passes
    every check we have: verify_mitre_ids confirms an ID EXISTS in the ATT&CK
    bundle, not that it fits the behaviour.

    Found live: two Exchange inbox-rule detections came back as T1098.003
    (Additional Cloud Roles), while this index has said all along that
    New-InboxRule means T1114.003 or T1564.008 — and explains which is which.


    Returns "" for an unindexed table, so a caller adds nothing rather than an
    empty section claiming there are no techniques for it.
    """
    e = _load().get(table)
    if not e or not e.techniques:
        return ""

    claims = e.techniques

    from .attack import load_catalog

    names = {t.mitre: t.name for t in load_catalog()}

    lines = [
        (f"Curated ATT&CK mappings for {table}, matched to its real operation vocabulary.\n"
         "RULE: when a detection fires on one of the operations listed below, use the "
         "technique listed FOR THAT OPERATION. Do not substitute a parent technique, a "
         "sibling, or one that merely sounds close — the specific sub-technique is the "
         "correct answer and the broader one is wrong, not merely less precise. Only when "
         "a detection fires on an operation that appears nowhere below may you choose "
         "another verified ID."),
        "",
    ]
    for c in claims[:max_techniques]:
        name = names.get(c.technique, "")
        header = f"  {c.technique}  {name}".rstrip()
        if c.raw_operations:
            header += f"\n      operations: {', '.join(c.raw_operations)}"
        lines.append(header)
        if c.basis:
            # The basis prose carries the disambiguations that make this worth
            # injecting at all -- e.g. that the same three inbox-rule operations
            # mean forwarding (T1114.003) or hiding (T1564.008) depending on the
            # rule's parameters, which no operation list alone can express.
            lines.append(f"      {' '.join(c.basis.split())}")
    if len(claims) > max_techniques:
        lines.append(f"  (+{len(claims) - max_techniques} more not listed)")
    if e.note:
        lines += ["", f"  Note: {e.note}"]
    return "\n".join(lines)
