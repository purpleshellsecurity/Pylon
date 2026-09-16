"""`chain` stamps downstream rows with the upstream break that causes them.
Only measured breaks propagate; idle-but-configured and unreadable do not."""

import pytest

from pylon import chain

STG = {"resource_id": "/s/rg/stg1", "expected_table": "StorageBlobLogs"}


def gap(reason, table="StorageBlobLogs", name="stg1"):
    return {"resource_id": f"/s/rg/{name}", "expected_table": table,
            "dark_reason": reason}


# ── which reasons block ──────────────────────────────────────────────────────

@pytest.mark.parametrize("reason", sorted(chain.BLOCKING_REASONS))
def test_a_measured_break_blocks(reason):
    assert "StorageBlobLogs" in chain.table_blocks([gap(reason)])


def test_a_configured_idle_resource_blocks_nothing():
    """A resource that is configured and quiet blocks nothing downstream."""
    assert chain.table_blocks([gap("configured here — idle in the window")]) == {}


def test_an_unreadable_setting_blocks_nothing():
    """A setting the scan could not read blocks nothing, and is reported as
    unreadable."""
    gaps = [gap("settings unreadable")]
    assert chain.table_blocks(gaps) == {}
    assert chain.unreadable_tables(gaps) == {"StorageBlobLogs"}


def test_unreadable_is_not_the_same_as_clean():
    """Unreadable and idle both block nothing; only unreadable is an open
    question."""
    assert chain.unreadable_tables([gap("configured here — idle in the window")]) == set()


# ── one cause, counted ───────────────────────────────────────────────────────

def test_ten_resources_behind_one_table_are_one_cause():
    gaps = [gap("no diagnostic setting", name=f"stg{i}") for i in range(10)]
    block = chain.table_blocks(gaps)["StorageBlobLogs"]
    assert block.step == 1
    assert len(block.resources) == 10
    assert "10 resources feeding StorageBlobLogs" in block.reason


def test_mixed_reasons_keep_every_resource_in_the_count():
    """Two reasons behind one table still count every resource, and the
    majority reason leads."""
    gaps = ([gap("no diagnostic setting", name=f"a{i}") for i in range(3)]
            + [gap("category not enabled", name="b1")])
    block = chain.table_blocks(gaps)["StorageBlobLogs"]
    assert len(block.resources) == 4
    assert "no diagnostic setting" in block.reason, "the majority reason leads"


# ── rules ────────────────────────────────────────────────────────────────────

BLOCKS = {"StorageBlobLogs": chain.Blocked(1, "StorageBlobLogs", "no setting", ["stg1"])}


def test_a_rule_reading_only_a_blocked_table_is_blocked():
    rules = [{"name": "Blob rule", "tables_referenced": ["StorageBlobLogs"]}]
    assert "Blob rule" in chain.rule_blocks(rules, set(), BLOCKS)


def test_a_rule_with_one_live_table_is_not_blocked():
    """A rule with one live table can fire, so it is not blocked."""
    rules = [{"name": "Mixed", "tables_referenced": ["StorageBlobLogs", "SigninLogs"]}]
    assert chain.rule_blocks(rules, {"SigninLogs"}, BLOCKS) == {}


def test_a_rule_whose_tables_were_never_resolved_is_not_blocked():
    """A rule whose tables could not be resolved is not blocked by anything."""
    rules = [{"name": "ASIM", "tables_referenced": []}]
    assert chain.rule_blocks(rules, set(), BLOCKS) == {}


def test_an_empty_table_with_no_measured_cause_does_not_block_a_rule():
    """An empty table with no measured cause blocks nothing."""
    rules = [{"name": "R", "tables_referenced": ["AWSCloudTrail"]}]
    assert chain.rule_blocks(rules, set(), BLOCKS) == {}


# ── techniques ───────────────────────────────────────────────────────────────

def test_a_technique_is_blocked_only_when_every_claiming_rule_is():
    rules = [{"name": "Dead", "tables_referenced": ["StorageBlobLogs"],
              "_techniques": ["T1530"]},
             {"name": "Live", "tables_referenced": ["SigninLogs"],
              "_techniques": ["T1078"]}]
    rb = chain.rule_blocks(rules, {"SigninLogs"}, BLOCKS)
    tb = chain.technique_blocks([{"technique_id": "T1530"}, {"technique_id": "T1078"}],
                                rules, rb)
    assert "T1530" in tb
    assert "T1078" not in tb


def test_a_technique_points_at_the_root_not_the_rule():
    """A blocked technique names the root cause, not the rule in between."""
    rules = [{"name": "Dead", "tables_referenced": ["StorageBlobLogs"],
              "_techniques": ["T1530"]}]
    rb = chain.rule_blocks(rules, set(), BLOCKS)
    block = chain.technique_blocks([{"technique_id": "T1530"}], rules, rb)["T1530"]
    assert block.step == 1
    assert block.subject == "StorageBlobLogs"


def test_a_technique_no_rule_claims_is_not_blocked():
    """A technique no rule claims is uncovered, not blocked."""
    assert chain.technique_blocks([{"technique_id": "T1490"}], [], {}) == {}


# ── solutions ────────────────────────────────────────────────────────────────

def test_a_solution_on_a_dead_source_is_blocked():
    sols = [{"solution_id": "azure-storage", "data_types": ["StorageBlobLogs"]}]
    assert "azure-storage" in chain.solution_blocks(sols, BLOCKS)


def test_a_solution_with_one_live_data_type_is_not():
    sols = [{"solution_id": "mixed", "data_types": ["StorageBlobLogs", "SigninLogs"]}]
    assert chain.solution_blocks(sols, BLOCKS) == {}


# ── the document carries it ──────────────────────────────────────────────────

def test_the_model_carries_blocked_by_on_rules_and_techniques():
    from pylon.analysis_model import BlockedBy, Gap, RuleHealth

    b = BlockedBy(step=1, subject="StorageBlobLogs", reason="no setting",
                  resources=["stg1"])
    assert RuleHealth(name="R", blocked_by=b).blocked_by.step == 1
    assert Gap(technique_id="T1530", technique_name="x", gap_type="data_no_rule",
               basis="y", blocked_by=b).blocked_by.subject == "StorageBlobLogs"


def test_a_rule_now_says_whether_it_is_switched_on():
    """`_enabled` was stripped on the way into the document, so the analysis
    could not tell an enabled rule from a disabled one and the report had to go
    and read the sidecar."""
    from pylon.analysis_model import RuleHealth

    assert RuleHealth(name="R", enabled=False).enabled is False
    assert RuleHealth(name="R").enabled is None, "unknown is not False"
