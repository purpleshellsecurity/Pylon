"""The saved list — a reviewed, committed set of detections per target.

Slice 1: storage + save + read-only compare. Does NOT touch generation.

A run produces detections that get worded differently every time. To tell
whether a run's detection is "the same" as one already saved, we match on a
stable key — the MITRE technique + log table + a normalized operation — NOT the
wording. The human reviews the resulting buckets, so an imperfect key is safe:
worst case a reworded detection shows as "new" and you skip it.

Files live under a committed directory (default ./detection-library), one YAML
per target, so changes are diffable and reviewable like code. Per-client lists
are a later addition (a subdirectory per client); this keeps a flat layout.
"""

from dataclasses import dataclass
from pathlib import Path

import yaml

from .models import ValidatedDetection
from .scoring import normalize_technique_id
from .text import slug

# Re-exported so the existing importers (rules, catalog) keep working;
# the transform itself lives in text.py, which is the only copy.
_slug = slug


def target_slug(subject: str) -> str:
    """Filename stem for a target (resource type, table, or 'Entra')."""
    return _slug(subject) or "unnamed"


def detection_key(mitre_technique: str, log_table: str, operation: str, vector_name: str = "") -> str:
    """Stable identity for matching across runs. Operation is the strongest
    anchor (e.g. MICROSOFT.KEYVAULT/VAULTS/DELETE, SecretGet); fall back to the
    vector name when no operation is present."""
    tech = normalize_technique_id(mitre_technique)
    anchor = _slug(operation) or _slug(vector_name)
    return f"{tech}|{log_table}|{anchor}"


def entry_from(d: ValidatedDetection) -> dict:
    """A saved-list entry from a run detection (only valid, generated ones)."""
    return {
        "key": detection_key(
            d.detection.mitre_technique, d.log_table, d.operation, d.detection.vector_name
        ),
        "name": d.detection.vector_name,
        "mitre_technique": d.detection.mitre_technique,
        "log_table": d.log_table,
        "operation": d.operation,
        "prerequisite": d.prerequisite,
        "kql": d.detection.kql,
        "tuning": d.detection.tuning_guidance,
        "false_positives": d.detection.false_positive_notes,
        # Born unmeasured. Nothing has run this against real data yet, and saying
        # so is the point: a fresh generation must not be indistinguishable from
        # a detection that has been proven.
        "status": EXPERIMENTAL,
        "evidence": {},
    }



# ── Maturity ──────────────────────────────────────────────────────────────────
# A library of machine-generated detections is only trustworthy if a reader can
# tell a fresh model output from something that has been measured. That is what
# these two fields carry.
#
# `status` uses the Sigma specification's vocabulary rather than words invented
# here, so the library stays legible to anyone who reads detection content. The
# field is optional in Sigma, and only three of its five values are reachable
# from this ladder: `deprecated` and `unsupported` describe rules replaced or
# unusable, which nothing in this pipeline produces.
# https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html
#
# `status` is DERIVED from `evidence`, never set by hand. A detection cannot
# claim a maturity it has not earned, and the claim is recomputable from the
# record at any time — the same rule the rest of the tool applies to detections
# is applied here to their metadata.
EXPERIMENTAL = "experimental"  # Sigma: "could lead to false positives ... but
#                                could also identify interesting events" — a
#                                generated detection nothing has measured yet.
TEST = "test"                  # Sigma: "a mostly stable rule that could require
#                                some slight adjustments depending on the
#                                environment" — calibrated against THIS tenant's
#                                real data, by --tune or a retrohunt.
STABLE = "stable"              # Sigma: "considered as stable and may be used in
#                                production systems" — observed to fire on the
#                                attack and stay quiet on the benign baseline.

# Evidence keys. Each records what was measured, so a status can be re-derived.
TUNED = "tuned"          # --tune: real hit volume and allowlist candidates
RETROHUNT = "retrohunt"  # the query run over historical telemetry: what it WOULD have alerted on
LAB_PROVEN = "lab_proven"  # emulated attack fired in a lab tenant; detection caught it


def derive_status(entry: dict) -> str:
    """The Sigma status this entry's recorded evidence earns.

    Deliberately conservative at every step: absent or malformed evidence yields
    the lower status rather than the higher one. A lab run only reaches `stable`
    when it recorded BOTH halves — the detection fired on the attack and stayed
    quiet on the benign baseline. A detection that fires on everything is not
    proven, it is broken, and reporting it as production-ready would be the exact
    failure this ladder exists to prevent.
    """
    evidence = entry.get("evidence") or {}
    if not isinstance(evidence, dict):
        return EXPERIMENTAL

    lab = evidence.get(LAB_PROVEN)
    if isinstance(lab, dict) and lab.get("fired") is True and lab.get("benign_quiet") is True:
        return STABLE

    # ANY recorded measurement earns `test`, including a lab run that fired but
    # did not clear the benign baseline. The distinction that matters is measured
    # vs unmeasured: an incomplete lab result is inconclusive, not absent, and
    # grading it the same as a fresh generation would discard real information.
    if any(isinstance(v, dict) and v for v in evidence.values()):
        return TEST

    return EXPERIMENTAL


def with_evidence(entry: dict, kind: str, record: dict) -> dict:
    """`entry` with one evidence record added and its status re-derived.

    Returns a new dict; the caller decides whether to persist it. Re-deriving on
    every write is what keeps status and evidence from drifting apart — status is
    a view of the record, not a second source of truth.
    """
    updated = dict(entry)
    evidence = dict(updated.get("evidence") or {})
    evidence[kind] = record
    updated["evidence"] = evidence
    updated["status"] = derive_status(updated)
    return updated


def with_derived_status(entry: dict) -> dict:
    """`entry` with `status` recomputed from whatever evidence it carries.

    Applied on load, so an entry committed before this field existed gains an
    honest `experimental` rather than reading as unrated — and a hand-edited
    status is corrected back to what the evidence supports.
    """
    updated = dict(entry)
    updated["status"] = derive_status(updated)
    return updated


# ── Storage ───────────────────────────────────────────────────────────────────


def _str_representer(dumper, data):
    """PyYAML str representer that dumps multi-line strings in block ('|') style."""
    # Multi-line strings (KQL) use block style '|' so they read cleanly in git.
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


yaml.add_representer(str, _str_representer)


def list_path(list_dir: Path, subject: str) -> Path:
    """Path to the saved-list YAML for `subject` under `list_dir` (one file per target)."""
    return Path(list_dir) / f"{target_slug(subject)}.yaml"


def load(list_dir: Path, subject: str) -> list[dict]:
    """The saved detection entries for `subject`, or [] if no list file exists yet."""
    path = list_path(list_dir, subject)
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = data.get("detections", [])
    # Re-derive rather than trust what is on disk: an entry written before these
    # fields existed has no status, and one edited by hand may claim more than
    # its evidence supports. Both come back as what the record actually earns.
    return [with_derived_status(e) for e in entries]


def save(list_dir: Path, subject: str, detections: list[ValidatedDetection]) -> Path:
    """Write the run's valid detections as the saved list for this target
    (seed/overwrite). Skipped/invalid ones are not saved."""
    path = list_path(list_dir, subject)
    path.parent.mkdir(parents=True, exist_ok=True)
    entries = [entry_from(d) for d in detections if d.valid and d.detection.kql]
    doc = {"target": subject, "detections": entries}
    path.write_text(yaml.dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


# ── Compare ───────────────────────────────────────────────────────────────────


@dataclass
class Diff:
    """A run compared to the saved list: which detections are new, same, or missing."""

    new: list[ValidatedDetection]     # in this run, not in the saved list
    same: list[ValidatedDetection]    # already saved
    missing: list[dict]               # saved, but this run didn't produce it


def append(list_dir: Path, subject: str, run: list[ValidatedDetection]) -> tuple[Path, int]:
    """Add a run's NEW valid detections to the saved list, keeping existing
    entries untouched (their reviewed KQL wins). Append-only; never deletes."""
    existing = load(list_dir, subject)
    keys = {e["key"] for e in existing}
    added = 0
    for d in run:
        if not (d.valid and d.detection.kql):
            continue
        e = entry_from(d)
        if e["key"] in keys:
            continue
        existing.append(e)
        keys.add(e["key"])
        added += 1
    path = list_path(list_dir, subject)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"target": subject, "detections": existing}
    path.write_text(yaml.dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path, added


def seed_context(saved: list[dict]) -> str:
    """Phase 1 prompt block that anchors the run to the saved list — the model
    reproduces these known attacks (so the core set stays stable every run) and
    only adds genuinely new ones on top. Empty when there's no saved list."""
    if not saved:
        return ""
    lines = [
        "\n<known_detections>",
        "These detections already exist for this target. Include an attack vector",
        "for EACH of them (keep this coverage — use the same operation and table),",
        "then add any NEW attack vectors you identify that are not listed:",
    ]
    for e in saved:
        lines.append(
            f"- {e['name']} ({e['mitre_technique']}, {e['log_table']}, op: {e['operation']})"
        )
    lines.append("</known_detections>")
    return "\n".join(lines)


def diff(saved: list[dict], run: list[ValidatedDetection]) -> Diff:
    """Compare a run's valid detections to the saved list by stable key, returning a
    Diff of new / same / missing. Skipped and invalid detections don't participate."""
    saved_keys = {e["key"] for e in saved}
    run_by_key: dict[str, ValidatedDetection] = {}
    new, same = [], []
    for d in run:
        if not (d.valid and d.detection.kql):
            continue  # skipped/invalid detections don't participate
        k = detection_key(
            d.detection.mitre_technique, d.log_table, d.operation, d.detection.vector_name
        )
        run_by_key[k] = d
        (same if k in saved_keys else new).append(d)
    missing = [e for e in saved if e["key"] not in run_by_key]
    return Diff(new=new, same=same, missing=missing)


def record_evidence(list_dir: Path, subject: str, key: str, kind: str, record: dict) -> bool:
    """Attach one evidence record to the saved entry `key` and re-derive its status.

    The write half of the maturity ladder, which was missing entirely: `save` and
    `append` both take ValidatedDetection and rewrite a whole run, so there was no
    way to update ONE entry with what was learned about it afterwards. Without
    this, `with_evidence` had no production caller and every entry stayed
    `experimental` no matter what a lab proved.

    Returns False when the key is not in the list — a proof about a detection that
    was never saved is not silently dropped into a new entry, because the caller
    needs to know the two are out of sync.
    """
    path = list_path(list_dir, subject)
    if not path.is_file():
        return False
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = data.get("detections", [])
    for i, entry in enumerate(entries):
        if entry.get("key") == key:
            entries[i] = with_evidence(entry, kind, record)
            data["detections"] = entries
            path.write_text(
                yaml.dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8"
            )
            return True
    return False
