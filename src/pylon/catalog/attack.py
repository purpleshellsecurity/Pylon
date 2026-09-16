"""Vendored attack catalog — the external denominator for coverage scoring.

The denominator is MITRE ATT&CK, derived from the enterprise-attack STIX bundle
(see scripts/refresh-attack-catalog.py): the **cloud techniques** (platforms IaaS /
Identity Provider / Office Suite / SaaS) for the cloud tracks, and the
**endpoint techniques** (host-tagged, under the synthetic "Endpoint" platform)
for the Defender endpoint track. Coverage is measured against these — the
authoritative, maintained list of what matters — not the model's own per-run
enumeration (which would be circular).

Scoring is at TECHNIQUE level: a technique is covered if a detection (this run)
or an existing rule carries it. Coarser than per-operation, but honest and needs
no hand-fabricated operation strings. Operation-level grounding (from the Sentinel
rule templates) is a later refinement; this reuses ATT&CK data the tool already
ingests for verification.
"""

from dataclasses import dataclass
from importlib import resources

import yaml

from ..scoring import normalize_technique_id

_CATALOG_DIR = "attacks"

# A run's platform (EngineReport.platform / CLI args) -> ATT&CK platform. Cloud
# tracks map to a cloud platform; endpoint tracks map to the synthetic "Endpoint"
# platform (host-tagged techniques — Windows/Linux/macOS — in the catalog).
_TOOL_TO_ATTACK = {
    "arm": "IaaS",
    "resource": "IaaS",
    "dataplane": "IaaS",
    "entra": "Identity Provider",
    "m365": "Office Suite",
    "defender-endpoint": "Endpoint",
}


def attack_platform_for(tool_platform: str) -> str:
    """The ATT&CK platform for a run's platform ('' if unmapped)."""
    return _TOOL_TO_ATTACK.get(tool_platform, "")


@dataclass(frozen=True)
class AttackTechnique:
    """One ATT&CK cloud technique in the denominator."""

    mitre: str
    name: str
    platforms: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()

    def id_norm(self) -> str:
        """The normalized ATT&CK technique ID token (e.g. T1078 or T1078.004)."""
        return normalize_technique_id(self.mitre)


def _parse(text: str) -> list[AttackTechnique]:
    """Parse one catalog YAML's `techniques` list into AttackTechnique records."""
    doc = yaml.safe_load(text) or {}
    return [
        AttackTechnique(
            mitre=e["id"],
            name=e["name"],
            platforms=tuple(e.get("platforms", [])),
            tactics=tuple(e.get("tactics", [])),
        )
        for e in doc.get("techniques", [])
    ]


def load_catalog(attack_platform: str | None = None) -> list[AttackTechnique]:
    """All vendored ATT&CK cloud techniques, optionally filtered to one ATT&CK
    platform (e.g. 'IaaS'). Returns [] if the catalog dir is absent."""
    techniques: list[AttackTechnique] = []
    root = resources.files("pylon.catalog").joinpath(_CATALOG_DIR)
    if not root.is_dir():
        return techniques
    for entry in root.iterdir():
        if entry.name.endswith(".yaml"):
            techniques += _parse(entry.read_text(encoding="utf-8"))
    if attack_platform:
        techniques = [t for t in techniques if attack_platform in t.platforms]
    return techniques


def catalog_seed_context(techniques: list[AttackTechnique]) -> str:
    """A Phase-1 anchor block listing the ATT&CK cloud techniques for the
    platform so the run enumerates to COVER the ones that apply. Empty when the
    catalog is."""
    if not techniques:
        return ""
    lines = [
        "\n<known_attacks>",
        "These are the MITRE ATT&CK techniques for this platform. Map each",
        "attack vector you produce to its technique ID, and cover as many of these",
        "as genuinely apply to this service before adding any others:",
    ]
    lines += [f"- {t.mitre} {t.name}" for t in techniques]
    lines.append("</known_attacks>")
    return "\n".join(lines)
