"""`design detections` refuses without a scan. The free steps before it must say
so, while it is still free.

Round nine followed the documented sequence 1-8. Step 2 (`plan`) and step 3
(`survey`) both succeeded -- survey measured the workspace and reported 8
gradable vectors -- and step 4 stopped dead with "refusing to build: no scan
confirms these tables exist". The only prior hint was one header line reading
`tables  no scan document at ...` among five other status lines.

The refusal itself is RIGHT and stays where it is. Writing a plan for a service
you have not deployed is a normal thing to do, and gating it would be wrong; the
money is spent at step 4, so that is where the stop belongs. What was missing is
that the free steps let a success imply the next step would work.
"""


from pylon import cli


def test_the_helper_is_quiet_when_the_scan_confirms_the_tables(monkeypatch):
    monkeypatch.setattr("pylon.deployed.from_analysis",
                        lambda *a, **k: (frozenset({"StorageBlobLogs"}), "scan ok"))
    assert cli._scan_will_block(["StorageBlobLogs"]) == ""


def test_the_helper_names_analyze_when_no_scan_exists(monkeypatch):
    monkeypatch.setattr("pylon.deployed.from_analysis", lambda *a, **k: (None, "no scan"))
    out = cli._scan_will_block(["StorageBlobLogs"])
    assert "will refuse" in out, out
    assert "pylon analyze" in out, out
    # The escape hatch is named too. Being told only to run a scan, when the
    # thing you want is to build for a service you have not deployed yet, sends
    # you to collect evidence that cannot exist.
    assert "--unconfirmed-tables" in out, out


def test_the_helper_speaks_up_when_the_scan_found_no_data(monkeypatch):
    """The other half of `_unconfirmed`: a scan ran and found none of these
    tables holding rows. Same remedy line, so it must not be silent here."""
    monkeypatch.setattr("pylon.deployed.from_analysis",
                        lambda *a, **k: (frozenset({"AuditLogs"}), "scan ok"))
    assert cli._scan_will_block(["StorageBlobLogs"]) != ""


def test_survey_hands_over_a_command_that_will_work_or_says_it_will_not():
    """Survey's last line is the exact `design detections` command to run next.
    Handing over a command that refuses, with no note, is the specific shape of
    this bug."""
    import inspect

    src = inspect.getsource(cli._design_survey)
    assert "_scan_will_block" in src, (
        "survey prints the next command; it must also say when that command "
        "will refuse")


def test_the_plan_path_warns_before_the_paid_step():
    import inspect

    src = inspect.getsource(cli._design_detections)
    assert "_scan_will_block" in src, (
        "a plan-only run must say the build step will refuse")
    # And the refusal must still be reachable for a building run.
    assert "refusing to build" in inspect.getsource(cli._unconfirmed)
