"""Defender plans, crossed with the resources they would protect.

An earlier read of this was too narrow. Deciding which TECHNIQUES a plan
covers is genuinely not scannable -- a plan that is off produces no alerts,
and the published mapping is tactic-level and pinned to ATT&CK v9. But that
is not the only question worth asking, and the useful one needs neither:

    Defender for Key Vault is off. This tenant has 1 key vault.

Both halves are already measured -- the plan's tier from Microsoft.Security,
the resource types from Resource Graph -- so the finding is scanned rather
than asserted, and it does not depend on any mapping that can go stale.

What IS authored here is which ARM types each plan protects. That is a small,
stable structural fact rather than a claim about detection, but it is still
this file's opinion, so a plan whose types are unknown reports `None` and is
carried as unmapped rather than being silently treated as protecting nothing.
"""

from __future__ import annotations

# Plan name (as Microsoft.Security/pricings reports it) -> the ARM types it
# protects. None means this file does not know, which must read differently
# from a plan that protects nothing in this tenant.
PLAN_TYPES: dict[str, list[str] | None] = {
    "VirtualMachines": ["microsoft.compute/virtualmachines",
                        "microsoft.hybridcompute/machines"],
    "StorageAccounts": ["microsoft.storage/storageaccounts"],
    "KeyVaults": ["microsoft.keyvault/vaults"],
    "AppServices": ["microsoft.web/sites"],
    "SqlServers": ["microsoft.sql/servers"],
    "SqlServerVirtualMachines": ["microsoft.sqlvirtualmachine/sqlvirtualmachines"],
    "KubernetesService": ["microsoft.containerservice/managedclusters"],
    "Containers": ["microsoft.containerservice/managedclusters",
                   "microsoft.containerregistry/registries"],
    "ContainerRegistry": ["microsoft.containerregistry/registries"],
    "CosmosDbs": ["microsoft.documentdb/databaseaccounts"],
    "OpenSourceRelationalDatabases": ["microsoft.dbforpostgresql/servers",
                                      "microsoft.dbforpostgresql/flexibleservers",
                                      "microsoft.dbformysql/servers",
                                      "microsoft.dbformysql/flexibleservers",
                                      "microsoft.dbformariadb/servers"],
    "Api": ["microsoft.apimanagement/service"],
    "AI": ["microsoft.cognitiveservices/accounts"],
    # Subscription-wide rather than tied to a resource type: Arm watches the
    # control plane, Dns watches resolution, and the posture plans assess
    # everything. Empty list, not None -- these are known to have no type.
    "Arm": [],
    "Dns": [],
    "CloudPosture": [],
    "FoundationalCspm": [],
    "Discovery": [],
}

# What each plan actually does, from Microsoft's plan documentation. Carried
# because the answer changes what a reader should do: Defender for Storage
# analyses storage telemetry directly and needs no diagnostic setting, so a
# dark storage account has two independent fixes rather than one.
PLAN_NOTES: dict[str, str] = {
    "StorageAccounts":
        "Analyses data-plane and control-plane telemetry from Blob, Files and "
        "Data Lake directly. Needs no diagnostic setting, so this is a second "
        "and independent fix for a storage account that is not logging.",
    "VirtualMachines":
        "Defender for Servers. Covers Windows and Linux machines on Azure, AWS, "
        "GCP and on-premises via Arc. Defender for Endpoint is onboarded "
        "automatically in BOTH Plan 1 and Plan 2, so enabling either gives EDR "
        "on every supported machine. Plan 2 adds agentless scanning, DNS "
        "alerts, just-in-time access and file integrity monitoring.",
    "KeyVaults": "Detects unusual attempts to access or exploit a key vault.",
    "AppServices": "Identifies attacks targeting applications on App Service.",
    "Arm": "Defender for Resource Manager. Monitors control-plane operations "
           "across the subscription, so it has no resource type of its own.",
    "Dns": "Standalone only for subscriptions that already had it. For new "
           "subscriptions these alerts come with Defender for Servers Plan 2, "
           "so this being off is not independently meaningful.",
    "Containers": "Hardening, vulnerability assessment and runtime protection "
                  "for Kubernetes clusters and registries.",
    "KubernetesService": "Superseded by the Containers plan.",
    "CloudPosture": "Defender CSPM. Attack path analysis, the security graph "
                    "and data-aware posture across everything.",
    "FoundationalCspm": "The free posture baseline: secure score and "
                        "recommendations.",
    "Api": "Visibility and threat detection for APIs published through API "
           "Management.",
    "AI": "Threat protection for generative AI workloads.",
    # Defender for Databases is an umbrella in the documentation but four
    # separately priced plans in the API, which is why they appear as four rows.
    "SqlServers": "Defender for Azure SQL Databases. One of the four separately "
                  "priced database plans.",
    "SqlServerVirtualMachines":
        "Defender for SQL Servers on Machines: SQL on VMs or physical servers. "
        "Can also be enabled on a Log Analytics workspace.",
    "CosmosDbs": "Defender for Azure Cosmos DB.",
    "OpenSourceRelationalDatabases":
        "Defender for Open-Source Relational Databases: PostgreSQL and MySQL. "
        "MariaDB is included in this scan's type mapping but is not named on "
        "the plan page, so that part is unconfirmed.",
    "ContainerRegistry": "Superseded by the Containers plan.",
    "Discovery": "Asset discovery across connected environments.",
}


# Always on at no cost, so `pricingTier: Standard` on these does not mean
# anyone bought protection. Reporting them beside a paid plan inflates the
# count of what is actually defended.
FREE_BASELINE = frozenset({"FoundationalCspm", "Discovery"})


def _duration_is_live(value) -> bool:
    """Whether a freeTrialRemainingTime represents time still on the clock."""
    text = str(value or "").strip()
    return bool(text) and text not in ("0:00:00", "None", "0")


def assess(plans_on: list[str], plans_off: list[str],
           resource_types: dict[str, int],
           raw: list[dict] | None = None) -> tuple[list[dict], dict]:
    """(per-plan rows, read state).

    `resource_types` is {arm type: count} from the inventory, lowercased.
    `raw` is the pricing objects, which carry what the tier alone cannot say.
    """
    detail_by_name = {p.get("name"): p for p in (raw or [])}
    rows, unmapped = [], []
    for name in sorted(set(plans_on) | set(plans_off)):
        enabled = name in plans_on
        info = detail_by_name.get(name, {})
        # A plan someone deliberately turned on carries a timestamp; the free
        # baseline does not. That is the only signal separating the two, since
        # both report Standard.
        foundational = name in FREE_BASELINE
        deliberately_on = bool(info.get("enablementTime"))
        trial_left = _duration_is_live(info.get("freeTrialRemainingTime"))
        types = PLAN_TYPES.get(name, None)
        if types is None:
            unmapped.append(name)
            protects, matched = None, None
        else:
            matched = {t: resource_types[t] for t in types if t in resource_types}
            protects = sum(matched.values())
        rows.append({"plan": name, "enabled": enabled,
                     "foundational": foundational,
                     "paid_protection": enabled and not foundational,
                     "enabled_on": info.get("enablementTime"),
                     "deliberately_on": deliberately_on,
                     "free_trial_available": trial_left and not enabled,
                     "deprecated": bool(info.get("deprecated")),
                     "replaced_by": info.get("replacedBy"),
                     "arm_types": types, "matching_resources": matched,
                     "protects": protects, "note": PLAN_NOTES.get(name),
                     # P1 vs P2 changes what a plan actually delivers, and is
                     # only populated once a plan is on.
                     "sub_plan": info.get("subPlan")})

    # The rows that matter: off, and there is something here it would cover.
    exposed = [r for r in rows if not r["enabled"] and (r["protects"] or 0) > 0]
    exposed.sort(key=lambda r: -r["protects"])

    paid = [r["plan"] for r in rows if r["paid_protection"]]
    trials = [r["plan"] for r in rows if r["free_trial_available"] and (r["protects"] or 0) > 0]
    bits = [f"{len(paid)} paid workload plan(s) on ({', '.join(paid) or 'none'}); "
            f"{len([r for r in rows if r['foundational'] and r['enabled']])} "
            "foundational plan(s) on at no cost"]
    if trials:
        bits.append("free trial unused, with resources present: " + ", ".join(trials))
    if exposed:
        bits.append("off with resources present: " + ", ".join(
            f"{r['plan']} ({r['protects']})" for r in exposed))
    subscription_wide = [r["plan"] for r in rows
                         if not r["enabled"] and r["arm_types"] == []]
    if subscription_wide:
        bits.append("off and subscription-wide, so no resource count applies: "
                    + ", ".join(subscription_wide))
    if unmapped:
        bits.append(f"{len(unmapped)} plan(s) this scan cannot map to a resource "
                    f"type: {', '.join(unmapped)}")
    return rows, {"ran": True, "detail": "; ".join(bits), "exposed": exposed}
