"""The furniture the layout is built from, and the rules it follows.

The page had the chain order and the chain's causes before this file existed,
and it rendered them in a stylesheet written two designs earlier: no rail, no
"fix this first", and every cause a grey sentence in a table cell beside the
row it explains. The design was agreed as an artifact and only half of it --
the information architecture -- ever reached `report.py`.

What is held here is the half that is easy to lose again, because none of it
is visible from any single section:

    THE RAIL        six steps, in order, each showing the state the section
                    below it stated. A step nobody measured is not clean.
    FIX THIS FIRST  one gap as the heading, what it costs under it, what to
                    tick in the box. Not four sentences of equal weight.
    ONE CAUSE       a break is named in the section where its effect lands,
                    in its own colour, saying which step to go to.
    NOT CHECKED     "could not check" has its own state everywhere, and is
                    never drawn as a fault.
"""

import re

from pylon import report

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
STG = f"{SUB}/resourceGroups/rg/providers/microsoft.storage/storageaccounts/s1"


def _res(rid=STG, kind="microsoft.storage/storageaccounts",
         status="not-enabled", assessment="assessed"):
    return {"resource_id": rid, "resource_type": kind, "scope": "resource",
            "logging_status": status, "assessment_status": assessment,
            "surfaces": [], "expected_tables": [], "unmapped_categories": [],
            "basis": "synthetic", "privileged_role_assignments": [],
            "exposure": "unknown", "exposure_source": "unrated"}


def _gap(rid=STG, table="StorageBlobLogs", reason="no diagnostic setting"):
    return {"resource_id": rid, "expected_table": table, "is_logging": False,
            "days_since_last_log": None, "dark_reason": reason,
            "categories_to_enable": ["StorageRead", "StorageWrite"],
            "mode_basis": "measured"}


def _rule(name="Blob deletion", tables=("StorageBlobLogs",), blocked=None):
    row = {"name": name, "tables_referenced": list(tables), "techniques": [],
           "rule_id": name}
    if blocked:
        row["blocked_by"] = blocked
    return row


def _detail(name="Blob deletion", tables=("StorageBlobLogs",),
            health="never-fires"):
    return {"name": name, "tables_referenced": list(tables),
            "rule_health_status": health, "health_detail": "", "_query": "T",
            "_template": False, "_enabled": True, "_auto_disabled": False,
            "techniques": [], "rule_id": name}


def _doc(**over):
    doc = {
        "generated_at": "2026-09-12T00:00:00Z", "scope": SUB, "window_days": 30,
        "workspace": "example-workspace",
        "reads": {k: {"ran": True, "detail": ""} for k in report.READ_LABEL},
        "summary": {"resources": 1, "resource_types": 1, "dark_resources": 1,
                    "loggable_resources": 1, "rules_total": 1,
                    "tables_checked": 1},
        "resources": [_res()], "rules": [], "coverage_gaps": [], "gaps": [],
        "tables": [{"table_name": "AuditLogs", "table_tier": "Analytics",
                    "last_ingest": "2026-09-12T00:00:00Z", "megabytes": 4.0,
                    "billable_megabytes": 4.0, "billable": True}],
        "workspace_plan": {"sku": "PerGB2018", "commitment_gb_per_day": None,
                           "retention_days": 30},
    }
    doc.update(over)
    return doc


def _body(*args, **over):
    """The page with its stylesheet removed.

    Every class the rail and the stages use is also named in the CSS, so
    counting a class over the whole document counts the rule that styles it
    too -- which is how a swatch that drew nothing passed inspection once.
    """
    doc = args[0] if args else _doc(**over)
    return report.build(doc, None, None, None, over.pop("rules_detail", None),
                        over.pop("rec", None)).split("</style>", 1)[1]


def _section(body, label):
    """One stage, from its eyebrow to the end of its section."""
    found = re.search(rf'<div class="eyebrow">{re.escape(label)}</div>.*?</section>',
                      body, re.S)
    return found.group(0) if found else ""


def _steps(body):
    """[(number, name, state, the words under it)] from the rail."""
    return [(int(n), name, state, words) for state, n, name, words in
            re.findall(r'<div class="step step--(\w+)">'
                       r'<div class="step__bar"></div>'
                       r'<div class="step__n">(\d)</div>'
                       r'<div class="step__name">([^<]*)</div>'
                       r'<div class="step__state">([^<]*)</div>', body)]


# ── the rail ─────────────────────────────────────────────────────────────────

def test_the_rail_names_six_steps_in_the_order_the_data_moves():
    steps = _steps(_body())
    assert [n for n, _, _, _ in steps] == [1, 2, 3, 4, 5, 6]
    assert [name for _, name, _, _ in steps] == list(report.STEP_NAME.values())


def test_a_step_nobody_measured_is_not_drawn_as_working():
    """Table activity did not run, so step 2 has no answer. The one thing it
    must not render as is a pass."""
    doc = _doc()
    doc["summary"]["tables_checked"] = None
    state = {n: (s, w) for n, _, s, w in _steps(_body(doc))}[2]
    assert state == ("void", "not checked")


def test_the_rail_repeats_the_section_and_does_not_recount_it():
    """Step 2's rail entry and step 2's heading are the same measurement. A
    rail computing its own would be a second source of truth for the number a
    reader sees twice."""
    body = _body(_doc(coverage_gaps=[_gap(), _gap(table="StorageQueueLogs")]))
    words = {n: w for n, _, _, w in _steps(body)}[2]
    heading = re.search(r'<span class="t-none">([^<]*)</span>',
                        _section(body, "Step 2 · Data arriving")).group(1)
    assert words == "2 with no ingestion"
    assert heading == "2 tables with no ingestion"


def test_the_key_names_only_the_states_the_rail_is_using():
    """A key entry for a state nothing on the page is in is a legend for a
    colour that is not there. `bar()` drops empty segments for the same
    reason."""
    body = _body()
    states = {s for _, _, s, _ in _steps(body)}
    key = re.findall(r'<i class="key--(\w+)"></i>', body)
    assert set(key) == states, (key, states)


def test_every_key_swatch_carries_a_colour_of_its_own():
    """The swatch reused the rail's `.step--none .step__bar`, which is a
    descendant selector on one element: the key rendered four blank gaps."""
    css = report.build(_doc(), None, None, None, None).split("</style>")[0]
    for state in ("ok", "none", "partial", "void"):
        assert f".steps__key i.key--{state} {{ background:" in css


# ── fix this first ───────────────────────────────────────────────────────────

def test_the_largest_gap_is_the_heading_and_not_an_item_in_a_list():
    body = _body(_doc(coverage_gaps=[_gap()], rules=[_rule()]))
    fix = re.search(r'<div class="fix">.*?</div>\s*</div>', body, re.S).group(0)
    assert "Fix this first" in fix
    assert "1 storage account has no diagnostic setting." in fix
    # What it costs, and what to tick, in that order.
    assert "<code>StorageBlobLogs</code>" in fix
    assert "1 analytics rule" in fix
    assert "What to switch on" in fix
    assert "Enable StorageRead, StorageWrite" in fix


def test_a_mixed_group_claims_no_single_reason():
    """Half with no setting and half shipping elsewhere is two pieces of work.
    Naming either over the heading would be false about the other half."""
    other = f"{SUB}/resourceGroups/rg/providers/microsoft.storage/storageaccounts/s2"
    body = _body(_doc(
        resources=[_res(), _res(rid=other)],
        coverage_gaps=[_gap(), _gap(rid=other, reason="ships elsewhere")]))
    fix = re.search(r'<div class="fix">.*?</div>\s*</div>', body, re.S).group(0)
    assert "have no diagnostic setting." not in fix
    assert "not sending everything they can to this workspace" in fix


# ── one cause, said once ─────────────────────────────────────────────────────

def test_a_blocked_rule_points_at_the_step_that_broke_it():
    blocked = {"step": 1, "subject": "StorageBlobLogs",
               "reason": "1 resource feeding StorageBlobLogs: no diagnostic setting",
               "resources": ["s1"]}
    body = _body(_doc(coverage_gaps=[_gap()],
                      rules=[_rule(blocked=blocked)]),
                 rules_detail=[_detail()])
    box = re.search(r'<div class="why why--partial">.*?</div>',
                    _section(body, "Step 4 · Analytics rules"), re.S)
    assert box, "a rule blocked upstream rendered no cause"
    assert "caused by step 1" in box.group(0)
    assert "StorageBlobLogs" in box.group(0)
    # The obvious response to a dead rule is to retune or delete it, and that
    # is the wrong move when the query is fine and the table is empty.
    assert "Do not retune them" in box.group(0)


def test_a_cause_is_amber_and_a_fault_is_red():
    """Waiting on an earlier fix is not a fault at this step. Drawing it as one
    sends a reader to look for a bug in a rule that has none."""
    blocked = {"step": 1, "subject": "StorageBlobLogs", "reason": "r",
               "resources": ["s1"]}
    body = _body(_doc(coverage_gaps=[_gap()], rules=[_rule(blocked=blocked)]),
                 rules_detail=[_detail()])
    assert 'why why--none">' not in _section(body, "Step 4 · Analytics rules")


# ── could not check ──────────────────────────────────────────────────────────

def test_a_resource_nobody_assessed_is_named_and_held_out_of_the_figure():
    body = _body(_doc(
        resources=[_res(), _res(rid=f"{STG}2", status=None,
                                assessment="not_assessed")]))
    box = re.search(r'<div class="why why--void">.*?</div>', body, re.S).group(0)
    assert "could not check" in box
    assert "held out of" in box
    # One dark resource of one that could be judged, not one of two.
    assert '<span class="t-none">1 of 1 resources</span>' in body


def test_a_question_nobody_answered_is_a_panel_and_not_a_footnote():
    """A section resting on an unanswered read is incomplete rather than empty,
    and a reader who misses that reads half a document as the whole picture."""
    doc = _doc()
    doc["reads"]["table_activity"] = {"ran": False, "detail": "query timed out"}
    body = _body(doc)
    panel = re.search(r'<div class="panel">.*?</div>\s*</div>', body, re.S)
    assert panel, "an unanswered read rendered no panel"
    assert "Not checked on this run" in panel.group(0)
    assert "Which tables hold data" in panel.group(0)
    assert "query timed out" in panel.group(0)


def test_nothing_unanswered_renders_no_panel():
    assert 'class="panel"' not in _body()


# ── the stages ───────────────────────────────────────────────────────────────

def test_every_stage_says_what_it_was_asked():
    body = _body(_doc(coverage_gaps=[_gap()]))
    heads = re.findall(r'<div class="stage__top">'
                       r'<span class="stage__num">([^<]*)</span>'
                       r'<div class="eyebrow">([^<]*)</div>'
                       r'(?:<span class="stage__q">([^<]*)</span>)?', body)
    assert heads, "no stage heads rendered"
    for num, label, question in heads:
        assert question, f"{label} carries no question"
        assert question == report.STEP_QUESTION[label]
        # Numbered where it is a step of the chain, `+` where it is not.
        assert num == "+" or label.startswith(f"Step {num} ")


def test_a_stage_is_demoted_only_when_its_findings_are_consequences():
    """`stage--dim` says "everything here is somebody else's fault". A step
    with a fault of its own must not carry it."""
    body = _body(_doc(coverage_gaps=[_gap()]),
                 rules_detail=[_detail(health="broken")])
    assert "stage--dim" not in body


# ── the document's own voice ─────────────────────────────────────────────────

def test_the_renderers_count_nothing_with_a_machine_plural():
    """`(s)` is honest and unmistakably machine output, which is why `plural`
    exists.

    Scoped to the renderers, because their strings ARE the page. The sentences
    the scan stores in `analysis.json` — a technique's basis, a rule's health
    detail, a solution's action — are held by the tests over the modules that
    write them, and a stored string cannot be fixed by re-rendering.

    Docstrings and comments are exempt: this file and `text.plural` both have
    to be able to name the habit they are refusing.
    """
    import ast
    import pathlib

    src = pathlib.Path(report.__file__).parent
    for name in ("report.py", "report_design.py", "reportkit.py"):
        tree = ast.parse((src / name).read_text(encoding="utf-8"))
        # A bare string statement is a docstring, whatever it is attached to.
        prose = {id(n.value) for n in ast.walk(tree)
                 if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in prose):
                for habit in ("(s)", "(es)", "(ies)"):
                    assert habit not in node.value, \
                        f"{name}:{node.lineno} counts with {habit}: {node.value[:70]}"
