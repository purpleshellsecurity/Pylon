"""Coverage scoring — full port of lib/scoring.ts.

Score is measured in MITRE ATT&CK technique coverage, not resource count.
Two numbers matter to a CISO: the overall program score (0-100) and the
critical gaps — high-weight techniques with no detection.
"""

import re
from dataclasses import dataclass

# Models sometimes embellish technique IDs ("T1485 - Data Destruction");
# coverage comparison must match on the bare ID.
_TECHNIQUE_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def normalize_technique_id(value: str) -> str:
    """The bare, CURRENT MITRE technique ID for `value`.

    Two normalisations, and the second was missing. A model returns
    "T1003.001 - OS Credential Dumping: LSASS Memory (Enterprise)" and the bare
    id has to be extracted. And MITRE revokes ids, so `T1562.008` and its
    replacement `T1685.002` are the same technique wearing two names.

    Leaving the second out split the tool against itself. Generation was taught
    to relabel a revoked id onto its replacement; the vendored catalogues still
    spoke the old one -- `table-techniques.yaml` carries T1562.008 twelve times
    and T1685.002 not once. So a run relabelled a technique, then flagged its
    own relabel as disagreeing with the catalogue, then reported 0 of 101
    techniques covered because the two sides could not match a single id.

    Fixed HERE rather than by rewriting the catalogues, for three reasons. The
    catalogues are vendored from Microsoft and MITRE and a refresh would undo
    any edit. `builtin-alerts.json` records Microsoft's own claims, which are
    not ours to rewrite. And every consumer already funnels through this
    function, including `catalog/table_techniques.py` itself -- so one change
    puts both sides in one vocabulary.
    """
    m = _TECHNIQUE_ID_RE.search(value)
    bare = m.group(0) if m else value.strip()
    try:
        from .mitre import current

        return current(bare)[0]
    except Exception:  # noqa: BLE001 - a missing index narrows this, never raises
        return bare


# Techniques a CISO will ask about by name. Higher weight = more important.
TECHNIQUE_WEIGHTS: dict[str, int] = {
    "T1078.004": 10,  # Valid cloud accounts
    # Keyed by the CURRENT id. `normalize_technique_id` resolves the revoked
    # spelling onto it, so a weight written for T1562.008 would never be found.
    "T1685.002": 10,  # Disable or modify cloud logs (was T1562.008)
    "T1530": 9,       # Data from cloud storage
    "T1552.001": 9,   # Credentials in cloud storage
    "T1098.001": 9,   # Additional cloud credentials
    "T1098.003": 8,   # Additional cloud roles
    "T1087.004": 7,   # Cloud account discovery
    "T1528": 7,       # Steal application access token
    "T1114.002": 8,   # Remote email collection
    "T1485": 8,       # Data destruction
    "T1070.004": 7,   # File deletion (evidence removal)
    "T1136.003": 7,   # Create cloud account
}


# Default weight for a technique not in the high-value list, so every catalog
# attack still counts toward coverage — the named high-value ones just count more.
DEFAULT_TECHNIQUE_WEIGHT = 5


def technique_weight(mitre: str) -> int:
    """MITRE-weight for a technique id (high-value list, else the base weight)."""
    return TECHNIQUE_WEIGHTS.get(normalize_technique_id(mitre), DEFAULT_TECHNIQUE_WEIGHT)


@dataclass
class ProgramScore:
    """Program-level metrics. Two DIFFERENT numbers, deliberately not conflated:

    - ``generation_yield`` — of the techniques Phase 1 enumerated, the weighted
      share that received a valid detection. This measures whether generation did
      its job; it is NOT coverage, because the denominator is the model's own list
      (three trivial vectors, all detected, still score 100).
    - ``catalog_coverage`` — the weighted share of the platform's ATT&CK cloud
      catalog (an EXTERNAL denominator) covered by this run's detections. This is
      the honest coverage number. ``None`` when no catalog is available. A
      single-service run legitimately covers only a slice of the whole matrix.
    """

    # 0-100, weighted, over DISTINCT TECHNIQUE IDS -- not over vectors. Two
    # vectors sharing a technique are one item here, and a weight-10 technique
    # counts for more than a weight-3. The docstring said "enumerated vectors ->
    # valid detection", which is what a reader assumed and is not what it
    # measures: a run of two vectors on one technique with one valid detection
    # scores 100.
    generation_yield: int
    catalog_coverage: int | None   # 0-100, weighted, vs external ATT&CK catalog; None if absent
    catalog_covered: int           # count of catalog techniques covered
    catalog_total: int             # count of catalog techniques (the denominator)
    critical_gaps: list[dict]


def _weighted_pct(ids: set[str], covered: set[str]) -> int:
    """Weighted percent of `ids` that appear in `covered` (0 when `ids` empty)."""
    denom = sum(technique_weight(t) for t in ids)
    if not denom:
        return 0
    num = sum(technique_weight(t) for t in ids if t in covered)
    return round(100 * num / denom)


def score_program(
    *,
    threats_in_scope: list[str],
    threats_covered: list[str],
    catalog_ids: list[str] | None = None,
) -> ProgramScore:
    """Compute both program metrics (see ProgramScore).

    ``generation_yield`` is weighted by technique importance — missing a weight-10
    technique costs more than a weight-7. ``catalog_coverage`` is computed only when
    ``catalog_ids`` (the platform's ATT&CK technique IDs) is given. Critical gaps
    are high-weight (>=8) uncovered techniques, drawn from the catalog when present
    (the external truth) and otherwise from the enumerated list.
    """
    in_scope = {normalize_technique_id(t) for t in threats_in_scope}
    covered = {normalize_technique_id(t) for t in threats_covered}
    generation_yield = _weighted_pct(in_scope, covered) if in_scope else 0

    catalog = {normalize_technique_id(t) for t in (catalog_ids or [])}
    catalog_coverage = _weighted_pct(catalog, covered) if catalog else None
    catalog_covered = len(catalog & covered)

    # Gaps come from the external catalog when we have it; else from what was enumerated.
    gap_source = catalog if catalog else in_scope
    critical_gaps = sorted(
        (
            {"mitre_id": t, "weight": TECHNIQUE_WEIGHTS.get(t, 0)}
            for t in gap_source
            if t not in covered and TECHNIQUE_WEIGHTS.get(t, 0) >= 8
        ),
        key=lambda g: -g["weight"],
    )

    return ProgramScore(
        generation_yield=generation_yield,
        catalog_coverage=catalog_coverage,
        catalog_covered=catalog_covered,
        catalog_total=len(catalog),
        critical_gaps=critical_gaps,
    )
