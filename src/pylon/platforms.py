"""Which ATT&CK platforms this tenant actually runs, and what that makes the
denominator.

The problem this exists to fix: the candidate set of techniques used to be
"every technique an installed Content Hub template mentions". That measures
Content Hub against itself. Install a solution and both the numerator and the
denominator move without anything changing in the tenant; uninstall one and
coverage improves. A percentage over that set answers no question anyone asked.

So the denominator comes from ATT&CK instead, narrowed to the platforms this
tenant demonstrably runs. Every platform must be earned by something the scan
measured -- a resource, a table with data, an onboarded device -- and the
evidence is carried so a reader can dispute the set rather than take it.

What that costs: the coverage number gets much worse, and it starts including
techniques no template mentions at all. Both are the point. A gap nothing in
Content Hub addresses is the most important row in the report and the old
denominator could not represent it.

Deliberately NOT included:
  PRE             reconnaissance conducted against the organisation from
                  outside it. Real, and invisible to tenant telemetry -- no
                  diagnostic setting or rule would ever see it, so counting it
                  as an uncovered gap would inflate the denominator with work
                  nobody can do here.
  a platform with no evidence. SaaS is the live example: Office Suite is
                  earned by OfficeActivity, but a Salesforce or a Slack this
                  scan cannot see is not assumed.
"""

from __future__ import annotations

from . import mitre

# Each platform, and what in the scan earns it. Every rule is a measurement,
# never an assumption about what a tenant "probably" has.
#   IaaS              Azure resources exist at all
#   Identity Provider Entra ID is the tenant's directory, measured at tenant scope
#   Office Suite      OfficeActivity holds data, so M365 audit reaches the SIEM
#   Windows / Linux   an onboarded device or a VM reports that OS
#   Containers        an AKS cluster or a container registry exists
CONTAINER_TYPES = ("microsoft.containerservice/managedclusters",
                   "microsoft.containerregistry/registries",
                   "microsoft.redhatopenshift/openshiftclusters")


def detect(resources: list[dict], live_tables: set[str], vm_os: dict[str, int],
           endpoint_os: dict[str, int] | None) -> tuple[set[str], list[dict]]:
    """(platforms, evidence rows).

    `vm_os` counts VM operating systems from the inventory; `endpoint_os`
    counts onboarded Defender devices. Either can earn Windows or Linux, and
    which one did is recorded -- a tenant with Windows VMs and no sensor is a
    different statement from one with a sensor.
    """
    types = {(r.get("resource_type") or "").lower() for r in resources}
    found, evidence = set(), []

    def earn(platform: str, ok, why: str):
        evidence.append({"platform": platform, "present": bool(ok), "basis": why})
        if ok:
            found.add(platform)

    azure = [t for t in types if t.startswith("microsoft.")]
    earn("IaaS", azure,
         f"{len(resources)} Azure resource(s) across {len(azure)} type(s)")
    earn("Identity Provider",
         any(r.get("scope") == "tenant" for r in resources),
         "Entra ID measured at tenant scope")
    earn("Office Suite", "OfficeActivity" in live_tables,
         "OfficeActivity holds data, so Microsoft 365 audit reaches this workspace")

    for platform, keys in (("Windows", ("windows",)), ("Linux", ("linux", "ubuntu"))):
        vms = sum(n for os_name, n in (vm_os or {}).items()
                  if any(k in os_name.lower() for k in keys))
        eps = sum(n for os_name, n in (endpoint_os or {}).items()
                  if any(k in os_name.lower() for k in keys))
        bits = ([f"{vms} VM(s)"] if vms else []) + ([f"{eps} onboarded device(s)"] if eps else [])
        earn(platform, vms or eps,
             ", ".join(bits) if bits else "no VM or onboarded device reports this OS")

    clusters = [t for t in types if t in CONTAINER_TYPES]
    earn("Containers", clusters,
         f"{len(clusters)} cluster or registry type(s)" if clusters
         else "no AKS cluster, OpenShift cluster or container registry")
    return found, evidence


def universe(found: set[str]) -> dict[str, dict]:
    """Every live Enterprise technique that applies to these platforms.

    Top-level techniques only, matching what Sentinel templates claim -- none
    of the 477 templates in the tenant this was measured against references a
    sub-technique, and mixing
    the two would produce a denominator no numerator could reach.
    """
    return {
        tid: rec for tid, rec in mitre.TECHNIQUES.items()
        if rec["matrix"] == "enterprise"
        and not rec["revoked"] and not rec["deprecated"]
        and not rec["sub_technique"]
        and set(rec.get("platforms") or []) & found
    }


def read_state(found: set[str], evidence: list[dict], size: int) -> dict:
    off = [e["platform"] for e in evidence if not e["present"]]
    return {"ran": True, "detail": (
        f"platforms measured in this tenant: {', '.join(sorted(found))}"
        + (f"; not present: {', '.join(off)}" if off else "")
        + f". {size} live Enterprise technique(s) apply to them, and that is the "
          "denominator. It comes from ATT&CK narrowed by measured platforms, not "
          "from the installed template set -- a technique no template mentions is "
          "a gap, and the old candidate set could not say so. PRE is excluded: "
          "reconnaissance against the organisation leaves no trace in tenant "
          "telemetry.")}
