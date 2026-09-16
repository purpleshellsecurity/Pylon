"""Grounding technique selection, the one thing generation left to recall.

Found in a live release run: two Exchange inbox-rule detections came back as
T1098.003 "Additional Cloud Roles". An inbox rule is not a cloud role. Nothing
caught it, and nothing could have — verify_mitre_ids confirms an ID EXISTS in the
ATT&CK bundle, not that it fits the behaviour, and T1098.003 is a real ID.

The cause was an asymmetry: the prompts hand the model a fully documented
OPERATION vocabulary, then say only "do not fabricate MITRE mappings" about
techniques — a negative constraint with nothing positive behind it. Meanwhile
table-techniques.yaml had the right answer all along and was imported by
gapscan and inventory only.
"""

from pylon.catalog.table_techniques import candidates, render_for_prompt
from pylon.prompts import build_system_prompt, technique_reference

# --- the block itself ---------------------------------------------------------


def test_the_block_carries_the_exact_operation_literals():
    # Slugs are for matching; a prompt needs the string the log actually holds.
    # Teaching the model "secretget" would have it emit a value no log has.
    block = render_for_prompt("AZKVAuditLogs")
    assert "SecretGet" in block
    assert "secretget" not in block


def test_the_block_carries_the_disambiguation_that_makes_it_worth_injecting():
    # An operation list alone cannot express this: reading a secret and backing
    # one up are the same act at different scale, and the basis says which is
    # which. That prose is the reason a list of IDs would not have been enough.
    block = render_for_prompt("AZKVAuditLogs")
    assert "T1555.006" in block
    assert "secret" in block.lower()


def test_the_block_names_techniques_not_just_ids():
    # "T1555.006" alone asks the model to recall what that is, which is the very
    # failure being fixed.
    assert "Cloud Secrets Management Stores" in render_for_prompt("AZKVAuditLogs")


def test_the_specific_wrong_answer_is_not_offered_for_this_table():
    # T1098.003 (Additional Cloud Roles) is a control-plane technique. It is not
    # among the vault data plane's curated mappings, so a model reading this
    # block has no reason to reach for it.
    assert "T1098.003" not in render_for_prompt("AZKVAuditLogs")


def test_an_unindexed_table_produces_nothing_rather_than_an_empty_section():
    # An empty <technique_reference> would assert the table supports no
    # techniques. The index makes no such claim — it says "no opinion".
    assert render_for_prompt("SomeTableNobodyIndexed") == ""
    assert technique_reference("SomeTableNobodyIndexed", "threat") == ""


def test_a_long_index_is_capped_and_says_so():
    # Silent truncation would read as a complete vocabulary.
    block = render_for_prompt("AZKVAuditLogs", max_techniques=2)
    assert "more not listed" in block


# --- where it is injected -----------------------------------------------------


def test_every_generation_path_gets_the_block():
    for platform, service in (
        ("arm", "Key Vault"),
        ("dataplane", "AZKVAuditLogs"),
        ("graph", "Directory Changes"),
        ("dataplane", "StorageBlobLogs"),
    ):
        prompt = build_system_prompt(platform, service, "threat")
        assert "<technique_reference>" in prompt, f"{platform}/{service}"


def test_only_the_phase_that_picks_the_technique_gets_it():
    """Phase 1 assigns the technique to the attack vector; phase 2 is handed it
    and writes a query around it. Injecting into both cost ~3,150 tokens x 16
    calls on a 15-vector run, against a run whose whole input was 44,000 — paying
    sixteen times for a choice made once."""
    assert "<technique_reference>" in build_system_prompt("arm", "Key Vault", "threat")
    assert "<technique_reference>" not in build_system_prompt("arm", "Key Vault", "detection")


def test_the_playbook_phase_does_not_get_it():
    # A playbook responds to a technique already chosen; it never selects one, so
    # the block would be tokens spent on nothing.
    pb = build_system_prompt("arm", "Key Vault", "playbook", playbook_target="Vault delete")
    assert "<technique_reference>" not in pb


def test_the_arm_path_is_grounded_on_azureactivity_whatever_the_service():
    # Every arm service queries AzureActivity, so the block must not follow the
    # service name — "Key Vault" and "Storage Account" are not tables.
    for service in ("Key Vault", "Storage Account", "Diagnostic Settings"):
        prompt = build_system_prompt("arm", service, "threat")
        assert "<technique_reference>" in prompt, service


def test_a_service_that_is_its_own_table_resolves_to_itself():
    # dataplane and sign-in services ARE table names, so the fallback has to be
    # the service rather than a per-chain constant.
    assert "<technique_reference>" in build_system_prompt("dataplane", "AZKVAuditLogs", "threat")


def test_the_block_does_not_displace_the_operation_vocabulary():
    # Both groundings have to survive: operations tell the model what to filter
    # on, techniques what to call it.
    prompt = build_system_prompt("dataplane", "StorageBlobLogs", "threat")
    assert "GetBlob" in prompt                    # operation vocabulary
    assert "<technique_reference>" in prompt      # technique vocabulary
    assert "<schema_reference>" in prompt


# --- the index is still self-consistent --------------------------------------


def test_a_secret_read_maps_only_to_the_credential_technique():
    ids = {c.technique for c in candidates("AZKVAuditLogs")
           if "secretget" in c.operations}
    assert ids == {"T1555.006"}


def test_the_instruction_forbids_substituting_a_broader_technique():
    """The first phrasing said "use a different verified ID only when the
    behaviour genuinely is not one of these", and a live run took that latitude
    twice — swapping T1070.008 (Clear Mailbox Data) for T1485 (Data Destruction)
    and T1534 (Internal Spearphishing) for T1566.003. Both times it reached for a
    broader technique over the specific one the index named, which is the failure
    mode the block exists to prevent."""
    block = render_for_prompt("AZKVAuditLogs")
    assert "parent technique" in block
    assert "sounds close" in block
    # And it must still leave a door open for an operation genuinely not listed,
    # or a thin index would force a wrong answer rather than allow a right one.
    assert "appears nowhere below" in block
