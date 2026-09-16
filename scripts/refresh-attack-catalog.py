#!/usr/bin/env python3
"""Regenerate the vendored ATT&CK coverage denominator.

Extracts every non-deprecated technique/sub-technique from the enterprise-attack
STIX bundle that is tagged with a CLOUD platform (IaaS / Identity Provider /
Office Suite / SaaS) OR a HOST platform (Windows / Linux / macOS), into a single
catalog/attacks/mitre-attack.yaml. Each technique keeps its cloud platform tags
and, if it is host-observable, gets a synthetic "Endpoint" platform so the
endpoint tracks can filter on it. One entry per technique id (no duplicates), so
a technique that is both cloud- and host-relevant counts in both denominators.

    python scripts/refresh-attack-catalog.py [path-to-enterprise-attack.json]

With no argument the bundle is downloaded; pass a local file to avoid the ~54 MB
fetch. Bump ATTACK_VERSION and re-run when ATT&CK ships a new release; commit the
regenerated file.

NOTE: we pin to a specific ATT&CK release, NOT `master`. The `master` bundle is a
moving target that can differ from the stable numbered release (in one build
environment `master` returned a mis-numbered draft that revoked T1562 "Impair
Defenses" and invented "stealth"/"defense-impairment" tactics — pinning avoids
that class of surprise and keeps the vendored denominator reproducible).
"""

import json
import sys
import urllib.request
from pathlib import Path

# Pinned ATT&CK release — bump deliberately, then commit the regenerated catalog.
ATTACK_VERSION = "16.1"
URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
CLOUD = {"IaaS", "SaaS", "Identity Provider", "Office Suite"}
HOST = {"Windows", "Linux", "macOS"}
OUT = Path(__file__).resolve().parent.parent / (
    "src/pylon/catalog/attacks/mitre-attack.yaml"
)


def _tactics(obj):
    return sorted(
        {
            p["phase_name"].replace("-", " ").title()
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        }
    )


def _load_bundle(argv) -> dict:
    if len(argv) > 1:
        return json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    return json.loads(urllib.request.urlopen(URL, timeout=120).read())


def main():
    bundle = _load_bundle(sys.argv)
    version = next(
        (o.get("x_mitre_version", "") for o in bundle["objects"] if o.get("type") == "x-mitre-collection"),
        "",
    )
    rows = []
    for o in bundle["objects"]:
        if o.get("type") != "attack-pattern" or o.get("x_mitre_deprecated") or o.get("revoked"):
            continue
        real = set(o.get("x_mitre_platforms") or [])
        plats = set(real & CLOUD)
        if real & HOST:
            plats.add("Endpoint")  # synthetic tag: the endpoint denominator
        if not plats:
            continue
        tid = next(
            (r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if tid:
            rows.append((tid, o["name"], sorted(plats), _tactics(o)))
    rows.sort(key=lambda r: r[0])

    lines = [
        "# MITRE ATT&CK coverage DENOMINATOR (generated, do not hand-edit). Derived",
        "# from the enterprise-attack STIX bundle: every technique/sub-technique tagged",
        "# with a cloud platform (IaaS / Identity Provider / Office Suite / SaaS) or a",
        '# host platform (Windows / Linux / macOS -> synthetic "Endpoint" tag).',
        "# Regenerate with scripts/refresh-attack-catalog.py.",
        'source: "MITRE ATT&CK (enterprise-attack STIX)"',
        'reference: "https://github.com/mitre-attack/attack-stix-data"',
        f'attack_version: "{version}"',
        "techniques:",
    ]
    for tid, name, plats, tacs in rows:
        lines.append(f"  - id: {tid}")
        lines.append(f'    name: "{name.replace(chr(34), chr(92) + chr(34))}"')
        lines.append(f'    platforms: [{", ".join(plats)}]')
        lines.append(f'    tactics: [{", ".join(tacs)}]')
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    endpoint = sum(1 for r in rows if "Endpoint" in r[2])
    print(f"wrote {len(rows)} techniques (ATT&CK v{version}) — {endpoint} endpoint -> {OUT}")


if __name__ == "__main__":
    main()
