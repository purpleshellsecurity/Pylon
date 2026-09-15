"""What each Defender plan actually detects, from Microsoft's alert reference.

Tying a plan to its detections answers "what would I gain" without needing a
plan-to-technique map -- the thing that cannot be established, because the
published mapping is tactic-level and pinned to ATT&CK v9 while everything
else here grounds against v19.

The alert reference is NOT uniformly structured, and that shapes this file.
Some plans enumerate every alert with an id, MITRE tactic and severity
(Storage, Key Vault). Others describe detection categories in prose and
enumerate nothing (App Service, rewritten in 2026). A count is therefore
available for some plans and genuinely absent for others, so `alert_types` is
None rather than zero where the page does not enumerate -- a blank must not
read as "this plan detects less".

This is a DOCS snapshot, not a live read. `SAMPLED` is when it was taken, and
it will drift. It is used to describe what a plan offers, never to suppress a
gap, so drift here costs accuracy in a sentence rather than a missed finding.
"""

from __future__ import annotations

SAMPLED = "2026-08-30"
BASE = "https://learn.microsoft.com/en-us/azure/defender-for-cloud/"

PLAN_DETECTIONS: dict[str, dict] = {
    "StorageAccounts": {
        "alert_types": 28,
        "tactics": ["Initial Access", "Pre-Attack", "Collection", "Discovery",
                    "Execution", "Exfiltration", "Lateral Movement",
                    "Credential Access", "Impact"],
        "examples": [
            "Authenticated access from a Tor exit node",
            "Unusual amount of data extracted from a storage account",
            "Malicious blob uploaded (malware scanning)",
            "Overly permissive SAS token used from a public IP",
            "Container access level changed to allow anonymous public access",
        ],
        "doc": BASE + "alerts-azure-storage",
    },
    "KeyVaults": {
        "alert_types": 14,
        "tactics": ["Credential Access", "Discovery", "Initial Access"],
        "examples": [
            "Suspicious secret listing and query (secret dumping)",
            "Suspicious policy change followed by secret query",
            "Access from a TOR exit node to a key vault",
            "User accessed a high volume of key vaults",
        ],
        "doc": BASE + "alerts-azure-key-vault",
    },
    "AppServices": {
        # The page was rewritten and no longer enumerates alerts, so there is
        # no count to give. None, not zero.
        "alert_types": None,
        "tactics": [],
        "examples": [
            "Remote code execution attempts in web request logs",
            "Injection attempts against application logic",
            "Web shell activity on running containers",
            "Crypto mining activity",
            "Reconnaissance tooling",
        ],
        "doc": BASE + "alerts-azure-app-service",
    },
    "VirtualMachines": {
        # Servers alerts are split across Windows, Linux, DNS, VM extensions
        # and network-layer pages. No single count is published, and inventing
        # one by adding pages would be a number nobody can check.
        "alert_types": None,
        "tactics": [],
        "examples": [
            "Defender for Endpoint EDR detections on the machine",
            "Suspicious process execution and fileless attack techniques",
            "Anomalous DNS resolution (Plan 2)",
            "Azure network layer threat detection (Plan 2)",
        ],
        "doc": BASE + "alerts-reference",
    },
    "Arm": {
        "alert_types": None,
        "tactics": [],
        "examples": [
            "Suspicious control-plane operations from a risky IP",
            "Use of an exploitation toolkit against Resource Manager",
            "Privilege escalation through role assignment",
        ],
        "doc": BASE + "alerts-resource-manager",
    },
    "Containers": {
        "alert_types": None,
        "tactics": [],
        "examples": [
            "Kubernetes cluster hardening and runtime protection",
            "Privileged container creation",
            "Suspicious kubectl activity",
        ],
        "doc": BASE + "alerts-containers",
    },
}


def for_plan(name: str) -> dict | None:
    return PLAN_DETECTIONS.get(name)
