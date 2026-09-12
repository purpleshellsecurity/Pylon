"""The four sentences before any table.

A summary is the part a client reads and the part they quote back. So the rule
this holds is not "is it well written" but "was every sentence earned": each
one is built from a figure computed for a section below, and a figure that is
missing produces no sentence rather than a confident guess.
"""

from pylon.report import headline

RG = "/subscriptions/S/resourceGroups/RG/providers"


def res(name, kind, status, assessment="assessed"):
    return {"resource_id": f"{RG}/{kind}/{name}", "resource_type": kind,
            "scope": "resource", "logging_status": status,
            "assessment_status": assessment}


def group(total, off=0, partial=0, on=0, unknown=0):
    return {"total": total, "off": off, "partial": partial, "on": on,
            "unknown": unknown, "names": []}


STORAGE = "microsoft.storage/storageaccounts"


def test_nothing_measured_says_nothing():
    """An empty document must produce an empty summary, not a sentence about
    zero resources. There is a difference between a clean tenant and a scan
    that did not run, and the summary is the worst place to blur it."""
    out = headline([], {}, [], None, 0)
    assert not out["lead"] and not out["second"]
    assert out["actions"] == [] and not out["caveat"]


def test_a_tenant_with_no_gaps_gets_no_gap_sentence():
    rows = [res("kv", "microsoft.keyvault/vaults", "fully-enabled")]
    out = headline(rows, {"microsoft.keyvault/vaults": group(1, on=1)}, [], None, 5)
    assert not out["lead"]
    assert out["actions"] == []


def test_the_gap_count_covers_partial_as_well_as_off():
    """"Sends no logs" would be wrong for a resource sending half of what it
    can, so the sentence says both — the number has to match the table below,
    which counts both."""
    rows = [res("a", STORAGE, "not-enabled"), res("b", STORAGE, "partial-enabled")]
    out = headline(rows, {STORAGE: group(2, off=1, partial=1)}, [], None, 5)
    assert out["lead"] == ("2 of 2 resources have no diagnostic setting "
                           "sending to this workspace.")


def test_the_largest_group_is_named_in_plain_english():
    """"storageaccounts" is the machine's name for the thing. A summary is
    read aloud in meetings."""
    rows = [res(f"s{i}", STORAGE, "not-enabled") for i in range(10)]
    out = headline(rows, {STORAGE: group(10, off=10)}, [], None, 5)
    assert out["actions"][0]["count"] == 10
    assert out["actions"][0]["what"] == "storage accounts"


def test_a_healthy_type_never_appears_in_where_to_start():
    """The list is work to do. A type with nothing wrong is not work."""
    rows = [res("a", STORAGE, "not-enabled"),
            res("b", "microsoft.keyvault/vaults", "fully-enabled")]
    out = headline(rows, {STORAGE: group(1, off=1),
                          "microsoft.keyvault/vaults": group(1, on=1)}, [], None, 5)
    assert [a["what"] for a in out["actions"]] == ["storage account"]


def test_where_to_start_stops_at_three():
    """Thirteen numbered items is the table below it with extra steps."""
    rows, groups = [], {}
    for i in range(6):
        kind = f"microsoft.test/type{i}"
        rows.append(res(f"r{i}", kind, "not-enabled"))
        groups[kind] = group(1, off=1)
    assert len(headline(rows, groups, [], None, 5)["actions"]) == 3


def test_rules_that_cannot_fire_are_named():
    rules = ([{"rule_health_status": "fires"}] * 23
             + [{"rule_health_status": "never-fires"}] * 3)
    out = headline([], {}, rules, None, 5)
    assert "3 of 26 analytics rules" in out["second"]


def test_a_rule_the_scan_could_not_test_is_not_counted_as_unable_to_fire():
    """`unreadable` means the scan could not look. Counting it here would put
    a false accusation in the one paragraph everybody reads."""
    rules = [{"rule_health_status": "unreadable"}] * 26
    assert headline([], {}, rules, None, 5)["second"] == ""


def test_a_disabled_defender_plan_is_offered_beside_the_group_it_covers():
    """Attached to the step it applies to, not stated as a loose fact — the
    reader is choosing what to do about storage accounts right there."""
    rows = [res(f"s{i}", STORAGE, "not-enabled") for i in range(10)]
    plans = [{"plan": "StorageAccounts", "enabled": False, "protects": 10,
              "matching_resources": {STORAGE: 10}}]
    out = headline(rows, {STORAGE: group(10, off=10)}, [], plans, 5)
    assert "Defender" in out["actions"][0]["alt"]


def test_an_enabled_plan_is_not_offered_as_a_fix():
    rows = [res(f"s{i}", STORAGE, "not-enabled") for i in range(10)]
    plans = [{"plan": "StorageAccounts", "enabled": True, "protects": 10,
              "matching_resources": {STORAGE: 10}}]
    out = headline(rows, {STORAGE: group(10, off=10)}, [], plans, 5)
    assert out["actions"][0]["alt"] == ""


def test_an_unmeasured_table_leg_is_stated_not_omitted():
    """The one sentence that must appear when a figure is missing. A reader who
    does not know half the document is absent reads the other half as the whole
    picture."""
    assert "Table activity was not measured" in headline([], {}, [], None, None)["caveat"]


def test_a_measured_table_leg_adds_no_such_warning():
    assert headline([], {}, [], None, 34)["caveat"] == ""


def test_one_resource_is_named_in_the_singular():
    """"1 key vaults" reads as a typo, and a summary is where a reader looks
    for signs the tool is careless."""
    rows = [res("kv", "microsoft.keyvault/vaults", "not-enabled")]
    out = headline(rows, {"microsoft.keyvault/vaults": group(1, off=1)}, [], None, 5)
    assert out["actions"][0]["what"] == "key vault"


def test_more_than_one_stays_plural():
    rows = [res(f"kv{i}", "microsoft.keyvault/vaults", "not-enabled") for i in range(2)]
    out = headline(rows, {"microsoft.keyvault/vaults": group(2, off=2)}, [], None, 5)
    assert out["actions"][0]["what"] == "key vaults"


# ── ordering by what the gap costs ───────────────────────────────────────────

def facts(rules=(), cats=(), tables=()):
    return {"rules": set(rules), "cats": set(cats), "tables": set(tables)}


def test_a_gap_blocking_rules_outranks_a_bigger_gap_that_blocks_none():
    """The whole point of the ordering. Ten dead storage accounts nobody has
    written a rule against matter less than one gap stopping three deployed
    detections, and sorting by count says the opposite."""
    VAULTS = "microsoft.keyvault/vaults"
    rows = ([res(f"s{i}", STORAGE, "not-enabled") for i in range(10)]
            + [res("kv", VAULTS, "not-enabled")])
    out = headline(rows, {STORAGE: group(10, off=10), VAULTS: group(1, off=1)},
                   [], None, 5,
                   {VAULTS: facts(rules=["Rule A", "Rule B", "Rule C"]),
                    STORAGE: facts()})
    assert out["actions"][0]["what"] == "key vault"
    assert out["actions"][0]["blocks"] == ["Rule A", "Rule B", "Rule C"]


def test_size_breaks_a_tie():
    """Among gaps costing the same, the bigger group is the better first move."""
    OTHER = "microsoft.network/networksecuritygroups"
    rows = ([res(f"s{i}", STORAGE, "not-enabled") for i in range(5)]
            + [res("n", OTHER, "not-enabled")])
    out = headline(rows, {STORAGE: group(5, off=5), OTHER: group(1, off=1)},
                   [], None, 5,
                   {STORAGE: facts(rules=["R"]), OTHER: facts(rules=["R"])})
    assert out["actions"][0]["what"] == "storage accounts"


def test_a_rule_read_by_two_gaps_of_one_type_counts_once():
    """Ten storage accounts feeding one table that one rule reads blocks ONE
    rule. Counting per gap would report ten and make the ordering meaningless."""
    rows = [res(f"s{i}", STORAGE, "not-enabled") for i in range(10)]
    out = headline(rows, {STORAGE: group(10, off=10)}, [], None, 5,
                   {STORAGE: facts(rules=["Only Rule"])})
    assert out["actions"][0]["blocks"] == ["Only Rule"]


def test_the_step_says_what_to_switch_on():
    """"10 storage accounts" is a finding. It becomes a next step only when it
    names the categories and where they land."""
    rows = [res(f"s{i}", STORAGE, "not-enabled") for i in range(10)]
    out = headline(rows, {STORAGE: group(10, off=10)}, [], None, 5,
                   {STORAGE: facts(cats=["StorageRead", "StorageWrite"],
                                   tables=["StorageBlobLogs"])})
    assert out["actions"][0]["how"] == ("Enable StorageRead, StorageWrite "
                                        "→ StorageBlobLogs")


def test_every_category_to_switch_on_is_named():
    """It used to stop at four and say "+5 more". Somebody following this step
    has to tick every one of them, so every one is named."""
    rows = [res("s", STORAGE, "not-enabled")]
    out = headline(rows, {STORAGE: group(1, off=1)}, [], None, 5,
                   {STORAGE: facts(cats=[f"Cat{i}" for i in range(9)])})
    how = out["actions"][0]["how"]
    assert "more" not in how
    for i in range(9):
        assert f"Cat{i}" in how


def test_two_possible_tables_are_not_claimed_as_one():
    """A gap feeding either of two tables cannot say "→ X". Saying nothing
    beats naming the wrong one."""
    rows = [res("s", STORAGE, "not-enabled")]
    out = headline(rows, {STORAGE: group(1, off=1)}, [], None, 5,
                   {STORAGE: facts(cats=["Audit"], tables=["A", "B"])})
    assert "→" not in out["actions"][0]["how"]


def test_no_gap_facts_still_produces_a_step():
    """The join can be empty — coverage_gaps is its own leg and may not have
    run. The census still knows how many are dark, so the step stands, and it
    says it cannot name a fix rather than trailing off."""
    rows = [res("s", STORAGE, "not-enabled")]
    out = headline(rows, {STORAGE: group(1, off=1)}, [], None, 5, {})
    assert out["actions"][0]["count"] == 1
    assert out["actions"][0]["blocks"] == []
    assert "Not enough detail to name a fix" in out["actions"][0]["how"]


def test_a_step_with_no_mapped_fix_still_says_why_it_is_dark():
    """A real report ended on "5 datacollectionrules" with nothing under it —
    it read as the section having run out mid-sentence. The reason IS known;
    only the fix is not."""
    rows = [res("d", "microsoft.insights/datacollectionrules", "not-enabled")]
    out = headline(rows, {"microsoft.insights/datacollectionrules": group(1, off=1)},
                   [], None, 5,
                   {"microsoft.insights/datacollectionrules": {
                       "rules": set(), "cats": set(), "tables": set(),
                       "assumed": True, "reasons": {"no diagnostic setting"}}})
    assert out["actions"][0]["what"] == "data collection rule"
    assert "No diagnostic setting" in out["actions"][0]["how"]
    assert "No categories mapped" in out["actions"][0]["how"]


def test_a_step_you_can_act_on_outranks_a_bigger_one_you_cannot():
    """However many resources are in it, a step nobody can act on is not a
    place to start."""
    DCR = "microsoft.insights/datacollectionrules"
    rows = ([res(f"d{i}", DCR, "not-enabled") for i in range(9)]
            + [res("s", STORAGE, "not-enabled")])
    out = headline(rows, {DCR: group(9, off=9), STORAGE: group(1, off=1)},
                   [], None, 5,
                   {DCR: {"rules": set(), "cats": set(), "tables": set(),
                          "assumed": True, "reasons": set()},
                    STORAGE: {"rules": set(), "cats": {"StorageRead"},
                              "tables": {"StorageBlobLogs"}, "assumed": True,
                              "reasons": set()}})
    assert out["actions"][0]["what"] == "storage account"


def test_a_default_table_name_says_so():
    """Which table a category fills depends on a setting the dark resource does
    not have. The name is still the best answer and worth printing — it just
    must not print in the same voice as a measured figure."""
    rows = [res("kv", "microsoft.keyvault/vaults", "not-enabled")]
    out = headline(rows, {"microsoft.keyvault/vaults": group(1, off=1)}, [], None, 5,
                   {"microsoft.keyvault/vaults": {
                       "rules": set(), "cats": {"AuditEvent"},
                       "tables": {"AZKVAuditLogs"}, "assumed": True}})
    assert "→ AZKVAuditLogs" in out["actions"][0]["how"]
    assert "(assumed)" in out["actions"][0]["how"]


def test_a_measured_table_name_carries_no_such_note():
    """Marking everything is the same as marking nothing."""
    rows = [res("kv", "microsoft.keyvault/vaults", "partial-enabled")]
    out = headline(rows, {"microsoft.keyvault/vaults": group(1, partial=1)}, [], None, 5,
                   {"microsoft.keyvault/vaults": {
                       "rules": set(), "cats": {"AuditEvent"},
                       "tables": {"AZKVAuditLogs"}, "assumed": False}})
    assert "(assumed)" not in out["actions"][0]["how"]


def test_one_assumed_gap_marks_the_whole_step():
    """Marking only when every gap is assumed would let a single measured
    resource vouch for nine that were not."""
    from pylon.report import gap_facts
    rows = [res(f"s{i}", STORAGE, "not-enabled") for i in range(2)]
    gaps = [{"resource_id": rows[0]["resource_id"], "expected_table": "T",
             "categories_to_enable": ["C"], "mode_basis": "measured"},
            {"resource_id": rows[1]["resource_id"], "expected_table": "T",
             "categories_to_enable": ["C"], "mode_basis": "assumed"}]
    assert gap_facts(rows, gaps, {})[STORAGE]["assumed"] is True


def test_a_gap_with_no_basis_recorded_counts_as_assumed():
    """A gap that does not say it measured the mode did not measure it."""
    from pylon.report import gap_facts
    rows = [res("s", STORAGE, "not-enabled")]
    gaps = [{"resource_id": rows[0]["resource_id"], "expected_table": "T",
             "categories_to_enable": ["C"]}]
    assert gap_facts(rows, gaps, {})[STORAGE]["assumed"] is True
