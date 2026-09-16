"""An exclusion whose opposite direction IS detected has to be deliberate.

A detection engineer reviewing the taxonomy found `Offboarded resource from PIM`
filed as provisioning-job mechanics while `Onboarded resource to PIM` was
mapped: the constructive direction detected and the destructive one called
noise. Six more of the same mistake were behind it.

The class is worth a gate and cannot be caught by reading prose. What CAN be
caught is the appearance of a NEW one: this file lists every asymmetry that
exists today, each having been read and either fixed or kept on purpose. A pair
that is not on the list fails, and the fix is to decide about it and then add
it -- which is the review step the PIM entries never got.

Two shapes, because the catalogue records exclusions two ways:

    ARM            the same resource path with the opposite verb, WRITE/DELETE
    Entra          the same act with the direction word swapped

Adding a line here is not a rubber stamp. It is a record that somebody looked.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path

import pytest

CATALOGUE = (Path(__file__).resolve().parents[1]
             / "src" / "pylon" / "catalog" / "table-techniques.yaml")

# ── ARM: reviewed, and kept excluded on a directional argument ──────────────
# Every one of these says, in its own reason, that the excluded direction takes
# capability away rather than granting it: "grants nobody anything", "ends the
# copying rather than starting it", "stops jobs rather than running them",
# "Ordinary provisioning". The deployment-slot twins defer to their parent
# entry, which carries the argument once.
ARM_REVIEWED = {
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/CERTIFICATES/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/CONFIGURATIONS/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/CONNECTIONS/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/CREDENTIALS/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/HYBRIDRUNBOOKWORKERGROUPS/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/HYBRIDRUNBOOKWORKERGROUPS/"
    "HYBRIDRUNBOOKWORKERS/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/JOBSCHEDULES/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/MODULES/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/NODECONFIGURATIONS/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/NODES/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/PYTHON2PACKAGES/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/PYTHON3PACKAGES/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/SCHEDULES/DELETE",
    # Kept, and its rate claim struck: the exposure is indirect, and how often
    # this is ordinary lifecycle has not been measured.
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/SOFTWAREUPDATECONFIGURATIONS/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/VARIABLES/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WATCHERS/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WATCHERS/WATCHERACTIONS/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/DELETE",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/DIAGNOSTICRUNCOMMANDS/DELETE",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/DELETE",
    "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/WRITE",
    "MICROSOFT.SQL/SERVERS/DATABASES/WRITE",
    "MICROSOFT.SQL/SERVERS/DATABASES/SCHEMAS/TABLES/COLUMNS/SENSITIVITYLABELS/WRITE",
    "MICROSOFT.SQL/SERVERS/DATABASES/SYNCGROUPS/DELETE",
    "MICROSOFT.SQL/SERVERS/DATABASES/SYNCGROUPS/SYNCMEMBERS/DELETE",
    "MICROSOFT.SQL/SERVERS/ELASTICPOOLS/WRITE",
    "MICROSOFT.SQL/SERVERS/JOBAGENTS/DELETE",
    "MICROSOFT.SQL/SERVERS/JOBAGENTS/CREDENTIALS/DELETE",
    "MICROSOFT.SQL/SERVERS/JOBAGENTS/JOBS/DELETE",
    "MICROSOFT.SQL/SERVERS/JOBAGENTS/JOBS/STEPS/DELETE",
    "MICROSOFT.SQL/SERVERS/JOBAGENTS/TARGETGROUPS/DELETE",
    "MICROSOFT.SQL/SERVERS/NETWORKSECURITYPERIMETERASSOCIATIONPROXIES/WRITE",
    "MICROSOFT.SQL/SERVERS/SYNCAGENTS/DELETE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/"
    "IMMUTABILITYPOLICIES/WRITE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/DATASHAREPOLICIES/DELETE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/DATASHARES/DELETE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/FILESERVICES/SHARES/WRITE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/LOCALUSERS/DELETE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/OBJECTREPLICATIONPOLICIES/DELETE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/QUEUESERVICES/QUEUES/WRITE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/TABLESERVICES/TABLES/WRITE",
    "MICROSOFT.WEB/SITES/CONFIG/DELETE",
    "MICROSOFT.WEB/SITES/CONFIG/WEB/APPSETTINGS/DELETE",
    "MICROSOFT.WEB/SITES/CONFIG/WEB/CONNECTIONSTRINGS/DELETE",
    "MICROSOFT.WEB/SITES/EVENTGRIDFILTERS/DELETE",
    "MICROSOFT.WEB/SITES/EXTENSIONS/DELETE",
    "MICROSOFT.WEB/SITES/FUNCTIONS/DELETE",
    "MICROSOFT.WEB/SITES/FUNCTIONS/KEYS/DELETE",
    "MICROSOFT.WEB/SITES/HOST/FUNCTIONKEYS/DELETE",
    "MICROSOFT.WEB/SITES/HOST/SYSTEMKEYS/DELETE",
    "MICROSOFT.WEB/SITES/NETWORKSECURITYPERIMETERASSOCIATIONPROXIES/WRITE",
    "MICROSOFT.WEB/SITES/SITECONTAINERS/DELETE",
    "MICROSOFT.WEB/SITES/SITEEXTENSIONS/DELETE",
    "MICROSOFT.WEB/SITES/SLOTS/CONFIG/DELETE",
    "MICROSOFT.WEB/SITES/SLOTS/CONFIG/WEB/CONNECTIONSTRINGS/DELETE",
    "MICROSOFT.WEB/SITES/SLOTS/FUNCTIONS/KEYS/DELETE",
    "MICROSOFT.WEB/SITES/SLOTS/HOST/FUNCTIONKEYS/DELETE",
    "MICROSOFT.WEB/SITES/SLOTS/HOST/SYSTEMKEYS/DELETE",
    "MICROSOFT.WEB/SITES/SLOTS/SITECONTAINERS/DELETE",
    "MICROSOFT.WEB/SITES/SLOTS/SITEEXTENSIONS/DELETE",
    "MICROSOFT.WEB/SITES/SLOTS/SOURCECONTROLS/DELETE",
    "MICROSOFT.WEB/SITES/SOURCECONTROLS/DELETE",
}

# ── Entra: reviewed, and kept excluded ──────────────────────────────────────
# The `R-undo` rows restore an object without restoring a way in -- an
# administrative unit, a kerberos domain, a policy key. `Restore service
# principal` is NOT here: it returns credentials and is mapped under T1098.001.
# The `R-workflow` rows are request/cancel paperwork that the matcher pairs with
# an unrelated completed operation of the opposite direction.
ENTRA_REVIEWED = {
    "Add eligible member to role in PIM canceled (permanent)",
    "Add eligible member to role in PIM canceled (timebound)",
    "Add eligible member to role in PIM requested (permanent)",
    "Add eligible member to role in PIM requested (timebound)",
    "Delete PendingExternalUserProfile",
    "Delete access package assignment policy",
    "Delete rollout policy of feature",
    "Enable PIM alert",
    "Enable account",
    "Hard Delete PendingExternalUserProfile",
    "Remove a group from feature rollout",
    "Remove eligible member from role in PIM requested (permanent)",
    "Remove eligible member from role in PIM requested (timebound)",
    "Remove member from role requested (PIM deactivate)",
    "Restore CertificateAuthorityEntity",
    "Restore PublicKeyInfrastructure",
    "Restore administrative unit",
    "Restore application",
    "Restore kerberos domain",
    "Restore policy key",
}

OPPOSITE = {"WRITE": "DELETE", "DELETE": "WRITE"}
DIRECTIONS = [("onboard", "offboard"), ("add ", "remove "), ("enable", "disable"),
              ("create", "delete"), ("restore", "delete"), ("allow", "block"),
              ("activate", "deactivate"), ("opt-in", "opt-out")]


@pytest.fixture(scope="module")
def catalogue() -> str:
    return CATALOGUE.read_text(encoding="utf-8")


def _arm(catalogue):
    az = catalogue[catalogue.index("\n  AzureActivity:"):
                   catalogue.index("\n  AZKVAuditLogs:")]
    mapped = set(re.findall(r"^          - (MICROSOFT\.[^\n]+)$", az, re.M))
    for inline in re.findall(r"operations: \[(.+?)\]", az):
        mapped.update(x.strip() for x in inline.split(","))
    excluded = set(re.findall(r"^        (MICROSOFT\.[^\n:]+): >-$", az, re.M))
    return mapped, excluded


def _entra(catalogue):
    block = catalogue[catalogue.index("\n  AuditLogs:"):]
    mapped = set(re.findall(r"^          - (.+)$", block, re.M))
    excluded = set(re.findall(r"^      (.+?): R-[a-z-]+$", block, re.M))
    return mapped, excluded


def _flips(a: str, b: str) -> bool:
    la, lb = a.lower(), b.lower()
    return any((x in la and y in lb) or (y in la and x in lb)
               for x, y in DIRECTIONS)


def test_no_new_arm_asymmetry(catalogue):
    """Same resource path, opposite verb, one detected and one excluded."""
    mapped, excluded = _arm(catalogue)
    found = set()
    for op in excluded:
        path, _, verb = op.rpartition("/")
        other = OPPOSITE.get(verb)
        if other and f"{path}/{other}" in mapped:
            found.add(op)
    new = found - ARM_REVIEWED
    assert not new, (
        "an ARM operation is excluded while the opposite direction on the same "
        "resource is detected, and nobody has recorded a decision about it:\n  "
        + "\n  ".join(sorted(new))
        + "\n\nDecide: map it, or keep it excluded on an argument its reason "
          "states. Then add it to ARM_REVIEWED.")


def test_no_new_entra_asymmetry(catalogue):
    """The same act with its direction word swapped."""
    mapped, excluded = _entra(catalogue)
    found = set()
    for op in excluded:
        for m in mapped:
            if op.startswith(m) or m.startswith(op):
                continue
            if difflib.SequenceMatcher(None, op.lower(), m.lower()).ratio() >= 0.80 \
                    and _flips(op, m):
                found.add(op)
                break
    new = found - ENTRA_REVIEWED
    assert not new, (
        "an Entra activity is excluded while its opposite direction is "
        "detected, and nobody has recorded a decision about it:\n  "
        + "\n  ".join(sorted(new))
        + "\n\nThis is how `Offboarded resource from PIM` shipped. Decide, then "
          "add it to ENTRA_REVIEWED.")


def test_the_reviewed_lists_hold_no_stale_entries(catalogue):
    """A name that no longer exists, or that has since been mapped, must leave
    the list -- otherwise it grows into a place where dead entries hide."""
    arm_mapped, arm_excluded = _arm(catalogue)
    entra_mapped, entra_excluded = _entra(catalogue)
    stale_arm = ARM_REVIEWED - arm_excluded
    stale_entra = ENTRA_REVIEWED - entra_excluded
    assert not stale_arm, f"no longer excluded, drop from ARM_REVIEWED: {stale_arm}"
    assert not stale_entra, \
        f"no longer excluded, drop from ENTRA_REVIEWED: {stale_entra}"


def test_the_seven_pim_operations_stay_mapped(catalogue):
    """The findings this gate was written for. A regression here is the exact
    bug coming back."""
    block = catalogue[catalogue.index("\n  AuditLogs:"):]
    mapped = set(re.findall(r"^          - (.+)$", block, re.M))
    for op in ("Offboarded resource from PIM", "Tenant offboarded from PIM",
               "Tenant opt-out", "PIM policy removed", "Disable PIM alert",
               "Deactivate PIM alert", "Restore service principal"):
        assert op in mapped, f"{op} fell back out of the detected set"


def test_a_permanent_assignment_is_not_temporary_elevation(catalogue):
    """MITRE's own carve-out: T1548.005 is temporary elevated access, and
    permanent role assignment is T1098.003."""
    block = catalogue[catalogue.index("\n  AuditLogs:"):]
    m = re.search(r"- id: T1548\.005\n        operations:\n"
                  r"((?:          - .+\n)+)", block)
    assert "Add member to role outside of PIM (permanent)" not in m.group(1)
