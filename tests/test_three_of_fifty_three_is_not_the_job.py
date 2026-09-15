"""The advice named three categories out of however many the service has.

A solution whose tables hold no data gets `action: connect`, and the row tells
the operator what to switch on. It read:

    Switch on accounts, Apps, BrickStoreHttpGateway and point the diagnostic
    setting at this workspace.

`cats` is every diagnostic category the resource type offers, sorted
alphabetically, and `cats[:3]` took the first three. Azure Databricks has 53.
Twenty-four of the 48 catalogue entries have more than three, so the sentence
was an instruction naming an arbitrary prefix of the alphabet on half of them,
with the rest appearing nowhere in the document.

The sibling decision in `report.headline` is explicit -- see
`test_every_category_to_switch_on_is_named`: somebody following a step has to
tick every one. That sentence carries the FULL list because the headline has at
most three steps; this one is a table cell on every installed solution, so the
count is the headline, three are an example labelled as one, and the whole list
goes on the row as data.
"""

import pylon.solutions as solutions
from pylon.analysis_model import Solution


def _entries_with_many_categories():
    return {k: v for k, v in solutions.load().items()
            if len(v.get("categories") or []) > 3}


def test_the_catalogue_really_does_carry_more_than_three():
    """A guard on the premise. If the catalogue ever held at most three
    everywhere, this whole file would be testing nothing."""
    wide = _entries_with_many_categories()
    assert len(wide) >= 10, f"only {len(wide)} entries have more than three"


def test_the_row_can_carry_every_category():
    """The structured half. Prose cannot hold 53 names; the row can."""
    cats = [f"cat{i:02d}" for i in range(53)]
    row = Solution(solution_id="x", display_name="Azure Databricks",
                   installed=True, alignment="unfed", basis="b",
                   action="connect", action_detail="d",
                   categories_to_enable=cats)
    assert row.categories_to_enable == cats


def test_the_field_defaults_to_empty_for_rows_with_no_advice():
    row = Solution(solution_id="x", display_name="y", installed=True,
                   alignment="fed", basis="b", action="none", action_detail="d")
    assert row.categories_to_enable == []


# ── the sentence itself ──────────────────────────────────────────────────────

from pylon.contenthub import CATEGORIES_IN_A_SENTENCE, switch_on


def test_a_short_list_is_still_named_in_full():
    assert switch_on(["AuditEvent", "AllMetrics"]) == (
        "Switch on AuditEvent, AllMetrics, and point the diagnostic setting at "
        "this workspace.")


def test_a_long_list_says_how_many_there_are():
    cats = [f"cat{i:02d}" for i in range(53)]
    out = switch_on(cats)
    assert "the 53 diagnostic categories it offers" in out, out
    assert "including cat00, cat01, cat02" in out, out


def test_the_sentence_does_not_pass_off_a_prefix_as_the_whole_job():
    """The defect. Three names and no count reads as the complete instruction."""
    out = switch_on([f"cat{i:02d}" for i in range(53)])
    assert not out.startswith("Switch on cat00, cat01, cat02,"), out


def test_the_boundary_is_where_it_says_it_is():
    exact = [f"c{i}" for i in range(CATEGORIES_IN_A_SENTENCE)]
    assert "diagnostic categories it offers" not in switch_on(exact)
    assert "diagnostic categories it offers" in switch_on(exact + ["one more"])


def test_every_real_catalogue_entry_produces_a_sentence():
    """No entry, however wide or narrow, renders a ragged one."""
    for name, entry in solutions.load().items():
        cats = entry.get("categories") or []
        if not cats:
            continue
        out = switch_on(cats)
        assert out.startswith("Switch on ") and out.endswith("workspace."), (name, out)
        assert ",," not in out and "  " not in out, (name, out)
