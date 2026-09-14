#!/usr/bin/env python3
"""Rebuild mitre_index.json from MITRE's published STIX bundles.

Run when ATT&CK publishes a version. The bundles total about 60MB, which is
why the scan reads a distilled index instead of fetching them.
"""

import json
import os
import urllib.request

BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
MATRICES = ("enterprise", "ics", "mobile")


def attribution(bundle: dict, ext_id) -> dict[str, dict]:
    """{technique id: who has been observed using it}.

    ATT&CK states this as `uses` relationships from an intrusion-set, a
    campaign, or a piece of malware or tooling to a technique. It is the only
    half of "does a real adversary do this" that can be answered offline; the
    other half -- whether it happened HERE -- is an observation, and the two
    are kept apart because merging them would let the report claim attribution
    it does not have.

    This is reporting bias, not a base rate. Cloud intrusions are published
    less often than endpoint ones, so a technique with no groups may be
    under-reported rather than unused. It is carried to RANK a candidate and
    must never filter one out.
    """
    named = {o["id"]: o for o in bundle["objects"]
             if o.get("type") in ("intrusion-set", "campaign", "malware", "tool")}
    by_ref = {o["id"]: o for o in bundle["objects"]
              if o.get("type") == "attack-pattern"}

    out: dict[str, dict] = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        target = by_ref.get(obj.get("target_ref"))
        source = named.get(obj.get("source_ref"))
        if not target or not source:
            continue
        tid = ext_id(target)
        if not tid:
            continue
        rec = out.setdefault(tid, {"groups": set(), "campaigns": set(),
                                   "software": set()})
        bucket = {"intrusion-set": "groups", "campaign": "campaigns"}.get(
            source["type"], "software")
        rec[bucket].add(source.get("name", ""))
    return {tid: {k: sorted(v) for k, v in rec.items()} for tid, rec in out.items()}


def mitigations(bundle: dict, ext_id) -> dict[str, list[str]]:
    """{technique id: the countermeasures ATT&CK publishes for it}.

    ATT&CK states these as `mitigates` relationships from a course-of-action to
    a technique. They are CATEGORIES, not controls -- T1485 yields "Data
    Backup", "Multi-factor Authentication", "User Account Management", and none
    of those is a thing anyone can go and configure. That is the point of
    carrying them: the category is the published half of a prevention
    recommendation and the Azure specifics are Pylon's half, so the playbook
    can say which is which instead of presenting both as one opinion.

    Deprecated and revoked countermeasures are dropped. ATT&CK retires a
    course-of-action when it stops being advice, and recommending one is worse
    than recommending nothing.
    """
    named = {o["id"]: o for o in bundle["objects"]
             if o.get("type") == "course-of-action"
             and not o.get("revoked")
             and not o.get("x_mitre_deprecated")}
    by_ref = {o["id"]: o for o in bundle["objects"]
              if o.get("type") == "attack-pattern"}

    out: dict[str, set[str]] = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "mitigates":
            continue
        target = by_ref.get(obj.get("target_ref"))
        source = named.get(obj.get("source_ref"))
        if not target or not source:
            continue
        tid = ext_id(target)
        if not tid:
            continue
        # The same countermeasure reaches a technique more than once -- ATT&CK
        # carries one relationship per rationale. A set, or the playbook prints
        # "Operating System Configuration" twice, which it did on T1098.
        out.setdefault(tid, set()).add(source.get("name", ""))
    return {tid: sorted(n for n in names if n) for tid, names in out.items()}


def distill(bundles: dict) -> tuple[dict, dict]:
    """(techniques, versions) from {matrix: parsed STIX bundle}."""
    techniques, versions = {}, {}
    for matrix, bundle in bundles.items():
        # A revoked technique is only actionable with its replacement, and
        # MITRE states that as a relationship rather than on the object.
        by_ref = {o["id"]: o for o in bundle["objects"]
                  if o.get("type") == "attack-pattern"}

        def ext_id(obj):
            ref = next((r for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            return ref.get("external_id") if ref else None

        replaced_by = {}
        for obj in bundle["objects"]:
            if obj.get("type") != "relationship" or obj.get("relationship_type") != "revoked-by":
                continue
            src, tgt = by_ref.get(obj["source_ref"]), by_ref.get(obj["target_ref"])
            if src and tgt and ext_id(src) and ext_id(tgt):
                replaced_by[ext_id(src)] = ext_id(tgt)

        for obj in bundle["objects"]:
            if obj.get("type") == "x-mitre-collection":
                versions[matrix] = obj.get("x_mitre_version")
            if obj.get("type") != "attack-pattern":
                continue
            tid = ext_id(obj)
            if not tid:
                continue
            # Enterprise wins a collision: an id in more than one matrix is
            # reported against the matrix a Sentinel workspace actually uses.
            if tid in techniques and matrix != "enterprise":
                continue
            techniques[tid] = {
                "name": obj.get("name", ""),
                "matrix": matrix,
                "deprecated": bool(obj.get("x_mitre_deprecated")),
                "revoked": bool(obj.get("revoked")),
                "tactics": sorted({p["phase_name"]
                                   for p in obj.get("kill_chain_phases", [])}),
                "sub_technique": bool(obj.get("x_mitre_is_subtechnique")),
                "revoked_by": replaced_by.get(tid),
                # The platforms a technique applies to. Without this the only
                # available denominator is "techniques the installed templates
                # mention", which measures Content Hub against itself.
                "platforms": sorted(obj.get("x_mitre_platforms") or []),
                # Filled below. Empty lists mean "nobody publicly attributed",
                # which is a real answer; a missing key would mean "not asked".
                "groups": [],
                "campaigns": [],
                "software": [],
                # Filled below. Empty means ATT&CK publishes no countermeasure
                # for this technique, which is a real answer and the reason the
                # Prevention section has to be able to render without one.
                "mitigations": [],
            }

        for tid, who in attribution(bundle, ext_id).items():
            if tid in techniques and techniques[tid]["matrix"] == matrix:
                techniques[tid].update(who)

        for tid, names in mitigations(bundle, ext_id).items():
            if tid in techniques and techniques[tid]["matrix"] == matrix:
                techniques[tid]["mitigations"] = names
    return techniques, versions


def main() -> None:
    bundles = {}
    for matrix in MATRICES:
        url = f"{BASE}/{matrix}-attack/{matrix}-attack.json"
        print(f"fetching {url}")
        with urllib.request.urlopen(url) as response:
            bundles[matrix] = json.load(response)
    techniques, versions = distill(bundles)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "catalog", "mitre_index.json")
    with open(out, "w", encoding="utf-8") as handle:
        json.dump({"attack_versions": versions, "techniques": techniques},
                  handle, indent=0, sort_keys=True)
    print(f"wrote {out} -- {len(techniques)} technique(s); versions {versions}")


if __name__ == "__main__":
    main()
