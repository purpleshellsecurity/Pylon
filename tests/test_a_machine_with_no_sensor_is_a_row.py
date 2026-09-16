"""A machine Defender has never heard of gets a row, not a footnote.

The endpoint section listed onboarded devices in a table with four columns --
what the machine is, what it runs, what state its sensor is in, what its
exposure is -- and then put the machines with NO sensor in a sentence
underneath: a count and a run-on list of names.

That is backwards. An onboarded device with a stale sensor is a broken agent on
a machine Defender is watching; a machine with no sensor is not being watched
at all, and it was the only one a reader could not scan.

Everything in those rows is read from a row already in the document: the OS
from the Azure inventory, the diagnostic setting from step 1. Nothing is asked
of Defender, because a machine with no sensor has nothing to ask.
"""

import html
import re

import pytest

from pylon import report

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
RG = f"{SUB}/resourceGroups/rg-lab/providers/Microsoft.Compute/virtualMachines"
ONBOARDED = f"{RG}/win-01"
DARK = f"{RG}/ubuntu-01"


def _vm(rid, os_type=None, logging="not-enabled"):
    row = {"resource_id": rid, "resource_type": "microsoft.compute/virtualmachines",
           "scope": "resource", "logging_status": logging,
           "assessment_status": "assessed", "surfaces": [], "expected_tables": [],
           "unmapped_categories": [], "basis": "", "privileged_role_assignments": [],
           "exposure": "unknown", "exposure_source": "unrated"}
    if os_type:
        row["os_type"] = os_type
    return row


def _doc(**over):
    doc = {
        "generated_at": "2026-09-12T00:00:00Z", "scope": SUB, "window_days": 30,
        "workspace": "ws",
        "reads": {k: {"ran": True, "detail": ""} for k in report.READ_LABEL},
        "summary": {"resources": 2, "resource_types": 1, "dark_resources": 1,
                    "loggable_resources": 2, "rules_total": 0, "tables_checked": 0},
        "resources": [_vm(ONBOARDED, "Windows", "fully-enabled"),
                      _vm(DARK, "Linux")],
        "rules": [], "coverage_gaps": [], "gaps": [], "tables": [],
    }
    doc.update(over)
    return doc


def _eps(**over):
    eps = {
        "devices": [{"name": "win-01", "os": "Windows11", "os_version": "24H2",
                     "type": "Server", "onboarded": True,
                     "onboarding_status": "Onboarded", "sensor": "Active",
                     "exposure": "Low", "azure_resource_id": ONBOARDED,
                     "mitigation": "{}"}],
        "inventory": {"with_sensor": [ONBOARDED], "without_sensor": [DARK],
                      "not_in_inventory": []},
        "families": {}, "streams": {}, "silent_streams": [],
    }
    eps.update(over)
    return eps


def _section(doc=None, eps=None):
    html_out = report.build(doc or _doc(), None, eps or _eps(), None, None, None)
    found = re.search(r"Also watching · Defender for Endpoint.*?</section>",
                      html_out, re.S)
    return found.group(0) if found else ""


def _cells(section, name):
    row = re.search(rf"<tr>\s*<td><code>{name}</code>.*?</tr>", section, re.S)
    assert row, f"no row for {name}"
    return [html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", c))).strip()
            for c in re.findall(r"<td[^>]*>(.*?)</td>", row.group(0), re.S)]


def test_the_machine_with_no_sensor_has_a_row_of_its_own():
    cells = _cells(_section(), "ubuntu-01")
    assert len(cells) == 4, cells
    assert "rg-lab" in cells[0]


def test_its_row_says_what_the_machine_runs():
    """From the Azure inventory. Defender cannot say: nothing is onboarded."""
    assert "Linux" in _cells(_section(), "ubuntu-01")[1]


def test_an_os_the_scan_never_recorded_is_not_guessed():
    """A scan from before `os_type` was carried says so, and must not render as
    an OS nobody recognised."""
    doc = _doc(resources=[_vm(ONBOARDED, "Windows", "fully-enabled"), _vm(DARK)])
    cell = _cells(_section(doc), "ubuntu-01")[1]
    assert "not known" in cell and "Linux" not in cell


def test_it_is_never_onboarded_and_not_merely_unhealthy():
    state = _cells(_section(), "ubuntu-01")[2]
    assert "Never onboarded" in state
    assert "chip--none" in _section()


def test_its_row_carries_its_other_gap():
    """No sensor AND no diagnostic setting is dark twice, and they are separate
    jobs. The second one is already measured at step 1."""
    assert "diagnostic setting: not enabled" in _cells(_section(), "ubuntu-01")[3]


def test_a_machine_defender_knows_that_azure_does_not_says_so():
    eps = _eps(inventory={"with_sensor": [ONBOARDED],
                          "without_sensor": [f"{RG}/ghost-01"],
                          "not_in_inventory": []})
    assert "not in the Azure inventory" in _cells(_section(eps=eps), "ghost-01")[3]


def test_the_two_kinds_of_row_are_never_one_list():
    section = _section()
    heads = re.findall(r'<tr class="grouprow"><th colspan="4">([^<]*)', section)
    assert heads == ["Onboarded", "No sensor"], heads


def test_the_heading_counts_the_machines_with_nothing_on_them():
    assert "1 machine with none" in _section()


def test_a_broken_agent_and_a_missing_one_are_named_as_different_work():
    eps = _eps(devices=[{**_eps()["devices"][0], "sensor": "Inactive"}])
    box = re.search(r'<div class="why why--none">(.*?)</div>', _section(eps=eps), re.S)
    assert box, "no cause box rendered"
    assert "broken agent" in box.group(1)
    assert "deployment gap" in box.group(1)


def test_every_machine_onboarded_renders_no_second_group():
    eps = _eps(inventory={"with_sensor": [ONBOARDED], "without_sensor": [],
                          "not_in_inventory": []})
    section = _section(eps=eps)
    assert "grouprow" not in section
    assert "with none" not in section
    assert 'why why--' not in section


@pytest.mark.parametrize("field", ["os_type"])
def test_the_os_reaches_the_document(field):
    """It is selected by the Resource Graph query and was dropped before the
    verdict, so the scan knew every VM's OS and could not say it afterwards."""
    from pylon.analysis_model import Resource
    assert field in Resource.model_fields
