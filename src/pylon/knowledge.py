"""Everything known about one operation, assembled from every source, with its
provenance attached.

Four different things are known about a detection surface and they live apart
for good reasons. Operations come from the ARM manifest and change when Azure
ships. Techniques and tactics come from the ATT&CK bundle and change when MITRE
revokes something, which happened three times in one afternoon. Column and parse
facts come from measuring a live workspace and are true of one tenant on one
day. Exclusions are a recorded human decision with a written rule behind them.

Merging the FILES would not help. The drift this module exists to prevent
happened inside a single YAML file: a fact the checker read and the prompt never
stated. Co-location is not the fix; one way in is.

So this is the one way in. Every consumer -- the prompt, the gates, the plan --
asks here rather than reaching into a catalogue directly, and every answer says
where it came from, because "measured on one tenant last Tuesday" and "published
by MITRE" are not the same kind of claim and a reader has to be able to tell.
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

# Where a fact came from. A caller reporting a verdict has to be able to say
# whether it is repeating a measurement, a published standard, or a decision
# somebody made.
MEASURED = "measured"          # counted in a real workspace, one tenant, one day
PUBLISHED = "published"        # Microsoft or MITRE says so
DECIDED = "decided"            # a recorded human judgement, with a written rule


@dataclass(frozen=True)
class Fact:
    value: Any
    source: str
    detail: str = ""


@dataclass
class Knowledge:
    """What is known about one (table, operation) pair."""

    table: str
    operation: str
    in_vocabulary: Fact | None = None
    techniques: list[Fact] = field(default_factory=list)
    tactics: list[Fact] = field(default_factory=list)
    excluded_by: Fact | None = None
    contract: Fact | None = None
    tier_exception: Fact | None = None
    # ATT&CK's published countermeasures for the mapped technique(s). These are
    # CATEGORIES ("Data Backup", "Multi-factor Authentication"), never Azure
    # controls, and they are carried so the Prevention section can separate the
    # published half of a recommendation from Pylon's own half. Empty is a real
    # answer: ATT&CK publishes no countermeasure for most discovery techniques,
    # on the stated grounds that preventing discovery breaks the service.
    mitigations: list[Fact] = field(default_factory=list)

    @property
    def accounted(self) -> bool:
        """Mapped or deliberately excluded. Neither is a gap; both are answers."""
        return bool(self.techniques or self.excluded_by)

    @property
    def tier_floor_applies(self) -> bool:
        """Whether the early-chain floor should lower this vector's priority.

        False when an exception is recorded. Measured across the catalogue: 41
        mapped operations sit in an early tier and the floor is right about
        almost all of them -- ListBlobs and GetBlobMetadata are enumeration. It
        is wrong about the handful that read an authorization boundary, and
        wrong in the quiet direction, which is the worse one.
        """
        return self.tier == "early" and self.tier_exception is None

    @property
    def tier(self) -> str:
        """Where this sits in the published kill chain, or "" when unmapped.

        Taken from ATT&CK's own tactics rather than from an opinion about what
        is worth alerting on. `assessPatches` is discovery because MITRE says
        T1518 is discovery, not because somebody graded it low.
        """
        names = {str(t.value) for t in self.tactics}
        for early in ("reconnaissance", "discovery", "resource-development"):
            if early in names:
                return "early"
        for late in ("impact", "exfiltration", "credential-access"):
            if late in names:
                return "late"
        return "mid" if names else ""


@functools.lru_cache(maxsize=1)
def _techniques() -> dict[str, dict]:
    raw = (resources.files("pylon.catalog") / "mitre_index.json").read_text(encoding="utf-8")
    return json.loads(raw)["techniques"]


@functools.lru_cache(maxsize=1)
def _table_techniques() -> dict[str, dict]:
    """The curated map. Needs PyYAML, which the base install does not carry, so
    it is imported here rather than at module scope -- `technique_names` must
    work on an install that can render a report and nothing else."""
    try:
        import yaml
    except ModuleNotFoundError:
        return {}
    raw = (resources.files("pylon.catalog") / "table-techniques.yaml").read_text(encoding="utf-8")
    return (yaml.safe_load(raw) or {}).get("tables") or {}


def technique_names() -> dict[str, str]:
    """ATT&CK id -> name, from the vendored index.

    Here rather than in the report so the page and the gates read one source.
    Deliberately JSON-only: the base install renders reports without PyYAML.
    """
    try:
        return {k: v.get("name", "") for k, v in _techniques().items()}
    except (FileNotFoundError, OSError):
        return {}


def _norm(operation: str) -> str:
    return (operation or "").casefold().strip()


def about(table: str, operation: str = "", resource_type: str = "") -> Knowledge:
    """Everything known about one operation on one table."""
    from . import contracts

    k = Knowledge(table=table, operation=operation)
    block = _table_techniques().get(table) or {}

    if operation and resource_type:
        from .services import operation_vocabulary
        try:
            vocab = {_norm(o) for o in operation_vocabulary(resource_type, table)}
        except Exception:
            vocab = set()
        if vocab:
            k.in_vocabulary = Fact(
                _norm(operation) in vocab, PUBLISHED,
                f"{len(vocab)} operations catalogued for {resource_type} on {table}")

    if operation:
        for entry in (block.get("techniques") or []):
            if _norm(operation) in {_norm(o) for o in (entry.get("operations") or [])}:
                tid = entry.get("id")
                k.techniques.append(Fact(tid, DECIDED, f"{table} technique map"))
                published = _techniques().get(tid) or {}
                for tactic in published.get("tactics") or []:
                    k.tactics.append(Fact(tactic, PUBLISHED, f"ATT&CK, {tid}"))
                # Deduped across techniques: two techniques on one operation
                # share countermeasures constantly, and the Prevention section
                # is a list of controls, not a list per technique.
                seen = {str(m.value) for m in k.mitigations}
                for name in published.get("mitigations") or []:
                    if name not in seen:
                        seen.add(name)
                        k.mitigations.append(
                            Fact(name, PUBLISHED, f"ATT&CK countermeasure for {tid}"))
        # TWO shapes for the same idea, and reading only one is how a gap of
        # 284 was reported when 345 of those operations were already excluded
        # with written reasons. Entra names a rule and defines it once;
        # AzureActivity writes the reason inline, per service. Both are
        # deliberate decisions and both have to be found.
        rule = next((r for o, r in (block.get("rejected") or {}).items()
                     if _norm(o) == _norm(operation)), None)
        if rule:
            why = (block.get("rejection_rules") or {}).get(rule, "")
            k.excluded_by = Fact(rule, DECIDED, " ".join(str(why).split())[:300])
        else:
            for _service, entries in (block.get("rejected_by_service") or {}).items():
                reason = next((v for o, v in (entries or {}).items()
                               if _norm(o) == _norm(operation)), None)
                if reason:
                    k.excluded_by = Fact("inline", DECIDED,
                                         " ".join(str(reason).split())[:300])
                    break

    if operation:
        exception = next((v for o, v in (block.get("tier_exceptions") or {}).items()
                          if _norm(o) == _norm(operation)), None)
        if exception:
            k.tier_exception = Fact(True, DECIDED,
                                    " ".join(str(exception).split())[:400])

    rendered = contracts.render(table)
    if rendered:
        k.contract = Fact(rendered, MEASURED,
                          f"contract for {table}, verified against a live workspace")
    return k


def unaccounted(table: str, resource_type: str) -> list[str]:
    """Operations that are neither mapped nor excluded -- the real gap.

    Deliberately not "unmapped". An operation with a written exclusion rule is
    an answer, and counting it as a gap is what made a 46% figure look like
    1,465 missing mappings when the true number was 284.
    """
    from .services import operation_vocabulary
    try:
        vocab = operation_vocabulary(resource_type, table)
    except Exception:
        return []
    return sorted(o for o in vocab if not about(table, o, resource_type).accounted)


def technique_block(table: str, resource_type: str = "") -> str:
    """The technique map as prompt text, with each operation's kill-chain tier.

    The tier is ATT&CK's own tactic, not a grade somebody assigned. `T1518` is
    discovery because MITRE says so, which is what lets a recon operation be
    mapped AND deprioritised instead of deleted -- the third state the catalogue
    could not express.
    """
    from .services import operation_vocabulary

    try:
        vocab = sorted(operation_vocabulary(resource_type, table))
    except Exception:
        return ""
    if not vocab:
        return ""
    lines, excluded = [], 0
    for operation in vocab:
        k = about(table, operation, resource_type)
        if k.excluded_by:
            excluded += 1
            continue
        if not k.techniques:
            continue
        ids = ", ".join(str(f.value) for f in k.techniques)
        tier = f" [{k.tier}]" if k.tier else ""
        lines.append(f"  {operation} -> {ids}{tier}")
    if not lines:
        return ""
    head = (f"Operations this table records for {resource_type}, with the "
            f"technique each was mapped to and where ATT&CK places it in the "
            f"kill chain. `early` is reconnaissance or discovery: real, and "
            f"rarely what you alert on. `late` is impact, exfiltration or "
            f"credential access.")
    tail = (f"\n  ({excluded} further operations are deliberately excluded with "
            f"a written rule and are not attack vectors.)" if excluded else "")
    return "<technique_map>\n" + head + "\n" + "\n".join(lines) + tail + "\n</technique_map>"


def gaps(table: str, resource_type: str) -> dict[str, list[str]]:
    """The three states, counted. `unaccounted` is the only one that is a gap."""
    from .services import operation_vocabulary

    try:
        vocab = sorted(operation_vocabulary(resource_type, table))
    except Exception:
        return {"mapped": [], "excluded": [], "unaccounted": []}
    out: dict[str, list[str]] = {"mapped": [], "excluded": [], "unaccounted": []}
    for operation in vocab:
        k = about(table, operation, resource_type)
        key = "mapped" if k.techniques else ("excluded" if k.excluded_by else "unaccounted")
        out[key].append(operation)
    return out


@functools.lru_cache(maxsize=1)
def _entra_sections() -> dict[str, dict]:
    """{category: {activity: ...}} from the vendored Entra activity reference."""
    import gzip

    raw = (resources.files("pylon.catalog") / "entra-audit-activities.json.gz")
    return json.loads(gzip.decompress(raw.read_bytes()))["activities"]


def activities(category: str = "") -> frozenset[str]:
    """Every Entra audit activity in one category, or all of them.

    PUBLISHED: Microsoft's own activity reference, vendored. Lives here rather
    than in whichever module wants it, because a second reader of a catalogue is
    a second place for its shape to be assumed wrongly.
    """
    sections = _entra_sections()
    if not category:
        return frozenset(a for acts in sections.values() for a in acts)
    return frozenset(sections.get(category) or {})


def excluded(table: str, *, category: str = "", resource_type: str = "") -> list[Fact]:
    """What was deliberately NOT detected here, and the written reason.

    Every entry is DECIDED -- a recorded human judgement -- and each carries its
    reason rather than an assertion. "This is noisy" is an opinion; "this is
    noisy because every portal view issues it" is the catalogue's judgement, and
    a reader can disagree with the second.

    Three shapes, because exclusions are recorded three ways and reading only
    one of them is how a gap of 284 was reported when 345 of those operations
    already had written reasons:

      AuditLogs      a NAMED rule applied to many activities, scoped here to
                     one category's activities
      AzureActivity  an inline reason per operation, per resource provider
      data plane     an inline reason per operation

    `Fact.value` is the rule name or the operation; `Fact.detail` is the reason.
    """
    block = _table_techniques().get(table) or {}
    rules = block.get("rejection_rules") or {}

    if table == "AuditLogs":
        scope = activities(category)
        hit = [r for a, r in (block.get("rejected") or {}).items() if a in scope]
        counts: dict[str, int] = {}
        for rule in hit:
            counts[rule] = counts.get(rule, 0) + 1
        return [
            Fact(rule, DECIDED,
                 f"{n} of {len(scope)} activities. "
                 + " ".join(str(rules.get(rule, "")).split()))
            for rule, n in sorted(counts.items(), key=lambda kv: -kv[1])
        ]

    per_service = block.get("rejected_by_service") or {}
    if resource_type and per_service:
        entries = next((v for k, v in per_service.items()
                        if k.lower() == resource_type.lower()), {}) or {}
        return [Fact(op, DECIDED, " ".join(str(why).split()))
                for op, why in entries.items()]

    return [Fact(op, DECIDED, " ".join(str(why).split()))
            for op, why in (block.get("rejected") or {}).items()]


def excluded_names(table: str, *, category: str = "") -> dict[str, list[str]]:
    """{rule: the activity names it excludes}, for the named-rule shape only.

    A rule row covers many operations and prints one sentence about all of
    them. "Request and approval bookkeeping around an act that is mapped in its
    completed form" is that sentence, and a reader who has not seen the names
    cannot tell what it is describing -- while

        Add member to role in PIM requested (permanent)
        Add member to role in PIM completed (permanent)

    side by side needs no sentence at all. So the names come out of the
    catalogue with the count that was already being taken from them.

    Empty for the other two shapes, where `Fact.value` IS the operation name
    and the row already prints it.
    """
    block = _table_techniques().get(table) or {}
    if table != "AuditLogs":
        return {}
    scope = activities(category)
    out: dict[str, list[str]] = {}
    for activity, rule in (block.get("rejected") or {}).items():
        if activity in scope:
            out.setdefault(rule, []).append(activity)
    return {rule: sorted(names) for rule, names in out.items()}


def detected_names(table: str, *, category: str = "",
                   resource_type: str = "") -> list[str]:
    """Every operation on this target that a technique is mapped to.

    The other half of the same question. A section that lists what is NOT
    detected and never says what IS leaves the reader to assume the answer is
    "nothing much", when for `RoleManagement` it is 33 of 82 operations.
    """
    block = _table_techniques().get(table) or {}
    scope = activities(category) if table == "AuditLogs" else frozenset()
    out: set[str] = set()
    for entry in (block.get("techniques") or []):
        for op in (entry.get("operations") or []):
            if table == "AuditLogs" and scope and op not in scope:
                continue
            if resource_type and table == "AzureActivity" \
                    and not str(op).lower().startswith(resource_type.lower()):
                continue
            out.add(str(op))
    return sorted(out)


def mapped_tiers(table: str, *, category: str = "",
                 resource_type: str = "") -> dict[str, int]:
    """{kill-chain tier: how many mapped techniques sit there} for one target.

    PUBLISHED, through ATT&CK's own tactics. Not a grade anyone assigned: a
    technique is `early` because MITRE places it in discovery, which is what
    lets a recon operation be mapped AND deprioritised rather than deleted.
    """
    block = _table_techniques().get(table) or {}
    scope = activities(category) if table == "AuditLogs" else frozenset()
    tiers: dict[str, int] = {}
    for entry in (block.get("techniques") or []):
        ops = entry.get("operations") or []
        if not ops:
            continue
        if table == "AuditLogs" and scope and not any(o in scope for o in ops):
            continue
        if resource_type and table == "AzureActivity":
            if not any(str(o).lower().startswith(resource_type.lower()) for o in ops):
                continue
        tier = about(table, ops[0]).tier or "unmapped"
        tiers[tier] = tiers.get(tier, 0) + 1
    return tiers


def platform_exception(table: str, technique: str) -> str:
    """The written reason a technique on this table departs from the cloud
    matrix, or "" when there is none.

    DECIDED. A host-platform technique on a cloud operation is normally wrong,
    and the one documented case is PaaS compute: App Service runs on a Windows
    or Linux host, so a file written into its site is a web shell in exactly the
    sense ATT&CK means, and the log source being a cloud log does not change
    which platform's techniques apply to what ran there.

    Recorded per mapping rather than granted per table, so relying on it is a
    visible choice in the catalogue rather than a silent one.
    """
    parts = (technique or "").split()
    tid = parts[0].strip() if parts else ""
    block = _table_techniques().get(table) or {}
    for entry in (block.get("techniques") or []):
        if entry.get("id") == tid:
            return " ".join(str(entry.get("platform_exception", "")).split())
    return ""
