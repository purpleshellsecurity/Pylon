"""One accessor in front of four sources, and nothing goes round it.

Four things are known about a detection surface and they live apart for good
reasons: operations come from the ARM manifest, techniques and tactics from the
ATT&CK bundle, column and parse facts from measuring a live workspace, and
exclusions from a recorded human decision. Different owners, different refresh
paths, different kinds of claim.

Merging the FILES would not have prevented the failure this guards against. The
drift that cost three regenerations happened INSIDE one YAML file: a fact the
checker read and the prompt never stated. Co-location is not the fix. One way in
is, plus a test that says so.

Every answer carries its provenance, because "counted in one tenant last
Tuesday" and "published by MITRE" are not the same claim and a reader has to be
able to tell which they are being given.
"""

import pytest

from pylon import knowledge as k

_VM = "Microsoft.Compute/virtualMachines"
_RUN = "Microsoft.Compute/virtualMachines/runCommand/action"


def test_an_answer_carries_where_each_fact_came_from():
    a = k.about("AzureActivity", _RUN, _VM)
    assert a.techniques and a.techniques[0].source == k.DECIDED, (
        "a person put that operation under that technique; say so")
    assert a.tactics and a.tactics[0].source == k.PUBLISHED, (
        "the tactic is ATT&CK's, not ours")
    assert a.contract and a.contract.source == k.MEASURED, (
        "the contract was counted in a workspace and must not read as published")


def test_the_three_states_are_distinguishable():
    """Mapped, excluded and unaccounted. Collapsing the middle into the last is
    what turned a 284-operation gap into a 1,465 one."""
    mapped = k.about("AzureActivity", _RUN, _VM)
    excluded = k.about("AuditLogs", "GroupsODataV4_Get")
    # `assessPatches` was my example of an unaccounted operation and it is not
    # one: AzureActivity records its exclusions under `rejected_by_service`,
    # which the accessor originally did not read. That miss is what made a gap
    # of zero look like 284, and before that 1,465.
    inline = k.about("AzureActivity", f"{_VM}/assessPatches/action", _VM)
    unaccounted = k.about("AzureActivity", f"{_VM}/notARealOperation/action", _VM)

    assert mapped.accounted and mapped.techniques and not mapped.excluded_by
    assert excluded.accounted and excluded.excluded_by and not excluded.techniques
    assert inline.accounted and inline.excluded_by, (
        "an inline per-service exclusion is a decision and must count as one")
    assert not unaccounted.accounted


def test_both_exclusion_shapes_are_read():
    """Entra names a rule and defines it once; AzureActivity writes the reason
    inline per service. Reading only the first reported 284 operations as
    missing when every one of them was already excluded with a written reason."""
    named = k.about("AuditLogs", "GroupsODataV4_Get")
    inline = k.about("AzureActivity", f"{_VM}/assessPatches/action", _VM)
    assert named.excluded_by.value.startswith("R-")
    assert inline.excluded_by.value == "inline"
    assert "read dressed as an action" in inline.excluded_by.detail


def test_an_exclusion_carries_the_rule_that_made_it():
    """An exclusion with no stated reason is indistinguishable from an
    oversight, which is the whole problem it exists to solve."""
    a = k.about("AuditLogs", "GroupsODataV4_Get")
    assert a.excluded_by.value.startswith("R-"), "name the rule"
    assert len(a.excluded_by.detail) > 40, "and carry its written reason"


def test_the_tier_comes_from_attack_not_from_taste():
    """`assessPatches` is discovery because MITRE places T1518 there. That is
    what lets a recon operation be mapped AND deprioritised rather than deleted,
    which is the argument that produced this whole module."""
    assert k.about("AzureActivity", _RUN, _VM).tier == "mid"          # execution
    assert k.about("AzureActivity", f"{_VM}/deallocate/action", _VM).tier == "late"
    empty = k.Knowledge(table="x", operation="y")
    assert empty.tier == "", "no tactics means no tier, not a default"


def test_gaps_counts_the_three_states_separately():
    g = k.gaps("AzureActivity", _VM)
    assert set(g) == {"mapped", "excluded", "unaccounted"}
    assert len(g["mapped"]) + len(g["excluded"]) + len(g["unaccounted"]) == 33


def test_the_technique_block_states_the_tier_it_will_be_judged_on():
    """Same rule as the contract: a fact used downstream must reach the model."""
    text = k.technique_block("AzureActivity", _VM)
    assert "[mid]" in text and "[late]" in text
    assert "early" in text, "the prompt must say what early means, not just tag it"


# Modules BELOW the accessor. `knowledge` is built on these, so they read a
# catalogue by definition and allowing them is not a loophole -- each is the
# thing that owns one source, with nothing downstream of it.
_SOURCE_LAYER = {
    "mitre.py": "reads mitre_index.json; it IS the bundle reader knowledge calls",
    "refresh.py": "rebuilds mitre_index.json from MITRE's STIX; the refresher",
    "knowledge.py": "the accessor itself; everything else asks it",
    "services/__init__.py": "owns the operation vocabulary knowledge asks for",
}

_ACCESS = ('resources.files(', 'Path(__file__)', 'open(')


def test_nothing_above_the_accessor_reads_a_catalogue_directly():
    """The guarantee.

    A consumer that opens `table-techniques.yaml` itself reads a fact the
    accessor would have annotated with its provenance and its tier, and that is
    exactly how the last drift happened -- a value the checker used and the
    prompt never stated. Prose mentioning a catalogue is fine; opening one is
    not.
    """
    import pathlib
    import re

    offenders = []
    for path in sorted(pathlib.Path("src/pylon").rglob("*.py")):
        # as_posix(), not str(): on Windows this is "validation\\kql_rules.py"
        # and the allow-list is written with forward slashes, so every nested
        # module stopped matching and was reported as an offender.
        rel = path.relative_to("src/pylon").as_posix()
        if rel in _SOURCE_LAYER or path.parts[-2] == "catalog":
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            bare = re.sub(r"#.*", "", line)
            if ("table-techniques.yaml" in bare or "mitre_index.json" in bare) \
                    and any(a in bare for a in _ACCESS):
                offenders.append(f"{rel}: {bare.strip()[:60]}")
    assert offenders == [], (
        "these OPEN a catalogue instead of asking `knowledge`:\n  "
        + "\n  ".join(offenders))


def test_the_source_layer_allowance_is_justified_not_just_listed():
    """An allow-list with no reasons becomes the place bypasses hide."""
    for module, why in _SOURCE_LAYER.items():
        assert len(why) > 25, f"{module} is allowed with no stated reason"


# --- the tier floor, and the handful it gets wrong --------------------------
#
# Measured across the catalogue: 41 mapped operations sit in an early tier.
# Lowering them out of critical and high is right for almost all -- ListBlobs
# and GetBlobMetadata are enumeration. It is wrong for the few that read an
# authorization boundary, and wrong in the quiet direction, which is worse: a
# detection nobody is paged for looks identical to one that never fires.

_BLOB = "Microsoft.Storage/storageAccounts/blobServices"


def test_the_floor_applies_to_ordinary_enumeration():
    for op in ("ListBlobs", "GetBlobMetadata", "ListContainers"):
        a = k.about("StorageBlobLogs", op, _BLOB)
        assert a.tier == "early", f"{op} should be early-chain"
        assert a.tier_floor_applies, f"{op} should be lowered"


def test_an_operation_that_reads_an_authorization_boundary_is_exempt():
    """`GetContainerACL` is Permission Groups Discovery, and most of that
    technique is enumeration. This particular read is the step before a
    container is made public."""
    a = k.about("StorageBlobLogs", "GetContainerACL", _BLOB)
    assert a.tier == "early", "the technique is still early-chain"
    assert not a.tier_floor_applies, "but this operation must not be lowered"
    assert a.tier_exception and a.tier_exception.source == k.DECIDED


def test_an_exemption_states_why_this_operation_differs():
    """An override with no argument is just a louder opinion. It has to say what
    separates this operation from the rest of its technique."""
    for op in ("GetContainerACL", "GetPathAccessControl"):
        a = k.about("StorageBlobLogs", op, _BLOB)
        assert len(a.tier_exception.detail) > 60, f"{op} is exempt with no reasoning"


def test_the_exemption_is_narrow():
    """If most of a technique were exempt, the mapping would be wrong rather
    than the tier. Measured: 41 early-chain operations, a handful exempt."""
    from pylon.services import operation_vocabulary

    early = [o for o in operation_vocabulary(_BLOB, "StorageBlobLogs")
             if k.about("StorageBlobLogs", o, _BLOB).tier == "early"]
    exempt = [o for o in early if not k.about("StorageBlobLogs", o, _BLOB).tier_floor_applies]
    assert early, "no early-chain operations found; the fixture has drifted"
    assert len(exempt) < len(early) / 2, (
        f"{len(exempt)} of {len(early)} are exempt -- that is a mapping problem, "
        "not a tiering one")


def test_the_engine_honours_the_exemption():
    import inspect

    from pylon import engine

    source = inspect.getsource(engine)
    assert "known.tier_floor_applies" in source, "the engine ignores the exemption"
    assert "is early-chain but exempt" in source, (
        "an exemption that is applied silently cannot be argued with")
