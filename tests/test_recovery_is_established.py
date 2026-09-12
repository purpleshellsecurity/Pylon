"""Whether an operation can be undone is a fact, not something a model recalls.

`SecretPurge` destroys a secret permanently. The catalogue has always said so --
in free text, inside a description, where nothing could act on it. The playbook's
Recovery Verification section was therefore free to write a hopeful restore step
for an operation that has no restore, which is the worst thing a 3am document can
do: send a responder looking for a command that does not exist while the real work
(replace the secret, update every consumer, say what was lost) goes undone.

Three states, never two:

    recovery: <Operation>   this is what reverses it
    recovery: none          the catalogue establishes that NOTHING reverses it
    absent                  never established -- the playbook must not guess

The third is the one that makes this honest. Silence must not read as "reversible".
"""

import pytest

from pylon import data_plane_operations as dp
from pylon import operation_grounding as og


def _with_recovery() -> list[tuple[str, str, str]]:
    """(table, operation, recovery) for every catalogue entry that states one."""
    out = []
    for table in dp._tables():
        for op in dp.operations(table):
            ref = dp.reference(table, op)
            if ref.get("recovery"):
                out.append((table, op, ref["recovery"]))
    return out


def test_the_catalogue_states_recovery_somewhere():
    assert _with_recovery(), "no operation states a recovery -- this check is inert"


@pytest.mark.parametrize("table,op,recovery", _with_recovery())
def test_a_named_reversal_is_itself_a_real_operation(table, op, recovery):
    """A recovery naming an operation that does not exist is worse than none: the
    playbook prints a command the responder cannot run."""
    if recovery == "none":
        return
    assert dp.reference(table, recovery), (
        f"{table}/{op} says it is reversed by {recovery!r}, which is not an "
        f"operation in {table}")


def test_nothing_calls_itself_its_own_reversal():
    for table, op, recovery in _with_recovery():
        assert recovery != op, f"{table}/{op} names itself as its reversal"


def test_a_purge_is_never_recoverable():
    """Key Vault's purge operations destroy a soft-deleted object permanently. If
    one of these ever says otherwise, the playbook will promise a restore."""
    found = 0
    for table in dp._tables():
        for op in dp.operations(table):
            if not op.lower().endswith("purge"):
                continue
            found += 1
            assert dp.reference(table, op).get("recovery") == "none", (
                f"{table}/{op} is a purge and must state recovery: none")
    assert found, "no purge operation found -- this check is inert"


def test_the_grounding_block_says_which_of_the_three_it_is():
    """The prompt is the only place this fact can act, so it has to reach it --
    and silence has to stay silent rather than becoming a third claim."""
    destroyed = og.grounding_block("AZKVAuditLogs", "SecretPurge")
    assert "Recovery: NONE" in destroyed
    assert "restore" not in destroyed.lower().replace("must say the object", "")

    reversible = og.grounding_block("AZKVAuditLogs", "SecretDelete")
    assert "reversed by SecretRecover" in reversible

    unestablished = og.grounding_block("AZKVAuditLogs", "SecretGet")
    assert "Recovery:" not in unestablished, (
        "an operation with no established recovery must say nothing about it; "
        "a line here would turn 'not established' into a claim")


def test_the_skeleton_tells_the_model_what_to_do_with_each_state():
    """The fact reaching the prompt is worth nothing if no rule acts on it."""
    from pylon.prompts.shared import PLAYBOOK_SKELETON

    section = PLAYBOOK_SKELETON.split("## Recovery Verification", 1)[1]
    section = section.split("---", 1)[0]
    assert "Recovery: NONE" in section
    assert "do NOT write a restore" in section.replace("Do NOT", "do NOT")
    assert "do not assume either way" in section
