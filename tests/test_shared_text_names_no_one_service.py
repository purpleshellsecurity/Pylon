"""ADVICE about the reader's own resource must not be written in one service's
vocabulary.

Round nine generated blob-storage playbooks and found Key Vault wording in all
five, byte-identical: a containment block commented "Key Vault RBAC example", a
manual fallback pointing at "Access policies" -- a thing blob storage does not
have -- and a prevention bullet saying "rather than the vault/account", under a
heading reading "Also, specific to this plane".

Scoped to the slots that give ADVICE, deliberately. A first version of this test
scanned whole assets and failed on `context.md`'s service-to-table lookup table
and on "storage account keys, Key Vault access policies" in a list of credential
types to check. Naming several services in an enumeration is correct; telling a
responder their resource has a feature it does not have is the bug.
"""
import re
from pathlib import Path

import pytest

ASSETS = Path(__file__).resolve().parent.parent / "src/pylon/prompts/assets"

# The slots that INSTRUCT about the reader's resource. `eradication` and
# `recovery` are excluded on purpose: they are checklists, and an entry reading
# "storage account keys, Key Vault access policies, connection strings" is a
# list of credential types to go and review, which is correct. The line between
# them is whether the text enumerates possibilities or tells you what YOUR
# resource has -- and the latter is what was wrong for nine tables in ten.
ADVICE_SLOTS = ("containment", "prevention")

# One service's access model named as though it were every service's.
ONE_SERVICE = [r"\bvaults?\b", r"\bKey Vault\b", r"\bblob\b", r"\bApp Service\b"]


def _advice_text(path: Path) -> str:
    """The advice slots of one asset, concatenated."""
    from pylon.prompts import parse_slots

    slots = parse_slots(path.read_text(encoding="utf-8"))
    return "\n".join(slots.get(k, "") for k in ADVICE_SLOTS)


def _shared_assets():
    return sorted(ASSETS.glob("dataplane/playbook.md")) + sorted(ASSETS.glob("arm/playbook.md"))


@pytest.mark.parametrize("path", _shared_assets(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_advice_slots_name_no_single_service(path):
    body = _advice_text(path)
    if not body.strip():
        pytest.skip(f"{path.parent.name}/{path.name} defines none of {ADVICE_SLOTS}")
    hits = sorted({m.group(0) for t in ONE_SERVICE
                   for m in re.finditer(t, body, re.IGNORECASE)})
    assert hits == [], (
        f"{path.parent.name}/{path.name} advises in the vocabulary of {hits}. This text "
        f"reaches every service on the plane, so a responder handling a different one "
        f"is told their resource has something it does not.")


def test_the_mitigation_advice_is_service_neutral():
    """`prevention()` maps a MITRE mitigation to one line of advice, and the same
    line reaches every service. One of them said "vault-wide"."""
    from pylon import playbook

    body = Path(playbook.__file__).read_text(encoding="utf-8")
    advice = re.findall(r'^\s+"[^"]+": \(\n?\s+"([^"]+)"', body, re.MULTILINE)
    assert advice, "found no mitigation advice strings to check"
    bad = [a for a in advice if re.search(r"\bvaults?\b", a, re.IGNORECASE)]
    assert bad == [], f"mitigation advice names one service: {bad}"


# ── the catalogue ─────────────────────────────────────────────────────────────

# `basis` is printed to a responder as "why this technique", under the vector
# they are looking at. The gate above watches the playbook assets and missed
# this file entirely, which is how a blob container ACL came to be explained
# with prose about deleting network security groups.
MAINTAINER_NOTES = [
    r"listed separately",
    r"absent on purpose",
    r"sections? below",
    r"is judged once",
    r"\bin this table\b",
    r"the noisiest entry",
]


def _technique_entries():
    """(table, technique id, basis, providers) for every mapping with prose.

    Yields the entry's OWN operations alongside its OWN basis. A technique id is
    not unique within a table -- AzureActivity carries four T1686.001 entries,
    one per service -- so anything that looks operations up by id pairs one
    entry's prose with another's operations. The first version of the test below
    did exactly that and reported two offenders that did not exist.
    """
    import yaml

    path = (Path(__file__).resolve().parent.parent
            / "src/pylon/catalog/table-techniques.yaml")
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    for table, block in (doc.get("tables") or {}).items():
        for entry in (block.get("techniques") or []):
            basis = " ".join(str(entry.get("basis", "")).split())
            if not basis:
                continue
            ops = [str(o).upper() for o in (entry.get("operations") or [])]
            providers = {o.split("/")[0] for o in ops if "/" in o}
            yield table, str(entry.get("id", "")), basis, providers


def test_basis_does_not_explain_the_catalogue_to_the_reader():
    """A responder reading "why this technique" is not maintaining this file.

    "Key Vault and SQL are absent on purpose -- their own sections below carry
    the same two deletes" is a true and useful note FOR A MAINTAINER, and it was
    printed under a blob container-delete vector. Notes like that belong in a
    YAML comment, which no renderer reads.
    """
    import re

    bad = [(t, tid, note) for t, tid, basis, _p in _technique_entries()
           for note in MAINTAINER_NOTES if re.search(note, basis, re.IGNORECASE)]
    assert bad == [], (
        "these `basis` entries explain the catalogue rather than the technique, "
        f"and are printed to a responder as \"why this technique\": {bad}")


def test_a_basis_spanning_providers_does_not_speak_for_only_one():
    """T1686.001 lists ten operations across Network and Storage and opened
    "NSG rule and firewall writes are the cloud-firewall modification surface",
    so a blob container ACL was explained with security-group prose.

    Checked only for the one-sided case that actually occurred -- naming a
    network-only noun while listing storage operations. Whether prose "covers"
    every provider is not mechanically decidable, so this catches the shape that
    was wrong rather than proving the general case right.
    """
    import re

    NETWORK_ONLY = r"\b(NSG|security group|securityRules|firewall)\b"
    offenders = []
    for _table, tid, basis, providers in _technique_entries():
        if not re.search(NETWORK_ONLY, basis, re.IGNORECASE):
            continue
        # Genuinely SPANNING: network operations and others in ONE entry. A
        # Key Vault-only or Network-only entry saying "firewall" is correct --
        # both have one.
        if "MICROSOFT.NETWORK" not in providers or not (
                providers - {"MICROSOFT.NETWORK"}):
            continue
        if not re.search(r"storage|container|resource layer", basis, re.IGNORECASE):
            offenders.append((tid, sorted(providers)))
    assert offenders == [], (
        f"these use network-only vocabulary while listing non-network "
        f"operations: {offenders}")
