"""The detections page has to carry the argument, not just the query.

A design run used to leave a directory of .kql files and a report.json: the
query in one file, the technique it claims in another, and the reason that
technique fits in a YAML catalogue the reader had no cause to open. The only way
to judge a detection was to already know the answer.

So the test that matters is that both rationales reach the page. They answer
different questions -- what the operation does, and why it maps where it does --
and a page carrying one of them cannot be reviewed.
"""

from pylon import report_design


def _report(**over):
    vector = dict(name="Bulk secret read", operation="SecretGet",
                  mitre_technique="T1555.006", log_table="AZKVAuditLogs",
                  priority="critical", alert_condition="More than five secrets in an hour",
                  rationale="Returns the plaintext value of a secret.")
    det = dict(detection=dict(vector_name="Bulk secret read",
                              mitre_technique="T1555.006",
                              kql='AZKVAuditLogs | where OperationName == "SecretGet"',
                              tuning_guidance="- Start at five per hour.",
                              false_positive_notes="A deployment pipeline."),
               log_table="AZKVAuditLogs", valid=True, errors=[], warnings=[],
               retried=False, table_basis="deployed")
    base = dict(platform="dataplane", service="AZKVAuditLogs",
                analysis=dict(attack_vectors=[vector]), detections=[det])
    return {**base, **over}


def test_the_query_is_on_the_page():
    assert "OperationName ==" in report_design.build(_report())


def test_both_rationales_are_on_the_page():
    html = report_design.build(_report())
    assert "why it matters" in html
    assert "Returns the plaintext value" in html
    # And the curated argument for the mapping, which lives in the catalogue and
    # is the half a reader cannot otherwise see.
    assert "why this technique" in html
    assert "Cloud Secrets Management Stores" in html


def test_a_disagreement_is_shown_and_not_corrected():
    """The live case: the run wrote "unmapped" for an operation the catalogue
    pins to T1555.006. The page shows both. Silently substituting the
    catalogue's answer would make the disagreement rate unobservable, and that
    rate is what says whether the model slipped or the mapping is wrong."""
    r = _report()
    r["analysis"]["attack_vectors"][0]["operation"] = "CertificateList"
    r["analysis"]["attack_vectors"][0]["mitre_technique"] = "unmapped"
    r["detections"][0]["detection"]["mitre_technique"] = "unmapped"
    html = report_design.build(r)
    assert "Pylon maps CertificateList to T1555.006" in html
    assert "no technique" in html


def test_the_three_table_states_stay_three():
    """"deployed" is the only one of the three that is a measurement, and the
    other two are different kinds of not-knowing. `deployed.py` is explicit: a
    table with data proves the mode is in use, a table WITHOUT proves nothing --
    an idle vault and one logging to AzureDiagnostics are identical from here --
    and no scan document means nobody looked.

    The page said "the scanned workspace does not hold" for both, which reports
    absence of evidence as evidence of absence on a document meant to be sent to
    other people."""
    r = _report()
    assert "Had data in the scan window." in report_design.build(r)

    r["detections"][0]["table_basis"] = "catalogue"
    quiet = report_design.build(r)
    assert "No data in the scan window." in quiet
    assert "does not hold" not in quiet, "no-data must never be read as absent"

    r["detections"][0]["table_basis"] = "unchecked"
    assert "No scan was run." in report_design.build(r)


def test_an_invalid_detection_is_marked_rather_than_hidden():
    r = _report()
    r["detections"][0]["valid"] = False
    assert "did not validate" in report_design.build(r)


def test_a_run_with_no_detections_still_renders():
    html = report_design.build(dict(platform="dataplane", service="AZKVAuditLogs",
                                    analysis=dict(attack_vectors=[]), detections=[]))
    assert "<title>Detections</title>" in html


def test_the_html_is_written_even_where_no_pdf_renderer_exists(tmp_path, monkeypatch):
    """PDF is an optional extra, so its absence must cost the reader nothing.
    The print stylesheet means Ctrl+P in any browser produces the same document;
    the extra buys headless generation, not a better page."""
    import builtins

    real = builtins.__import__

    def no_weasyprint(name, *a, **k):
        if name == "weasyprint":
            raise ImportError("not installed")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_weasyprint)
    written = report_design.write(_report(), tmp_path)
    assert [p.rsplit("/", 1)[-1] for p in written] == ["detections.html"]
    assert (tmp_path / "detections.html").read_text().startswith("<title>")


class TestTheLeadSaysWhatIsWrongWithThePage:
    """It used to explain how to read the page -- that each block carries a
    query and two arguments, and that disagreeing changes the mapping in one
    line. Both were wrong to print. The first describes what the reader can
    already see, and the second is an instruction about editing a catalogue
    file, which means nothing to anyone who did not build this tool.

    What a reader needs before trusting an exported document is what is wrong
    with it."""

    def test_it_does_not_narrate_its_own_layout(self):
        html = report_design.build(_report())
        for leak in ["two separate arguments", "Each one below carries",
                     "changes in one line"]:
            assert leak not in html, f"the page explains itself: {leak!r}"

    def test_a_disagreement_reaches_the_lead(self):
        r = _report()
        r["analysis"]["attack_vectors"][0]["operation"] = "CertificateList"
        r["analysis"]["attack_vectors"][0]["mitre_technique"] = "unmapped"
        r["detections"][0]["detection"]["mitre_technique"] = "unmapped"
        assert "a different technique than Pylon's own mapping." in report_design.build(r)

    def test_a_quiet_table_reaches_the_lead_without_overclaiming(self):
        r = _report()
        r["detections"][0]["table_basis"] = "catalogue"
        lead = report_design.build(r)
        assert "AZKVAuditLogs had no data in the scan window." in lead

    def test_a_table_nobody_checked_is_counted_separately(self):
        """Merging "no data" with "no scan" was the bug. One is a measurement
        that settles nothing; the other is not a measurement at all."""
        r = _report()
        r["detections"][0]["table_basis"] = "unchecked"
        lead = report_design.build(r)
        assert "No scan was run, so the table is unconfirmed." in lead
        assert "had no data" not in lead

    def test_the_verb_agrees_with_the_number(self):
        """It read "33 detections names a table". plural() agrees the noun with
        the number and the verb was left behind."""
        r = _report()
        r["detections"][0]["table_basis"] = "unchecked"
        r["detections"][0]["detection"]["mitre_technique"] = "unmapped"
        r["analysis"]["attack_vectors"][0]["operation"] = "CertificateList"
        r["analysis"]["attack_vectors"][0]["mitre_technique"] = "unmapped"
        assert "1 detection uses" in report_design.build(r)
        r["detections"].append(dict(r["detections"][0]))
        r["analysis"]["attack_vectors"].append(dict(r["analysis"]["attack_vectors"][0]))
        two = report_design.build(r)
        assert "2 detections use " in two
        assert "detections uses" not in two

    def test_a_failed_detection_reaches_the_lead(self):
        r = _report()
        r["detections"][0]["valid"] = False
        assert "failed the query validator." in report_design.build(r)

    def test_a_clean_run_still_states_the_limit_that_always_applies(self):
        """Silence would read as a page with nothing to say, and "everything
        passed" overstates it: the validator checks the query, never whether the
        rule fires on real data."""
        html = report_design.build(_report())
        assert "not whether a rule fires" in html


def test_a_solution_row_shows_the_name_and_not_its_publisher():
    """The publisher line under every name was Microsoft's own string, printed
    verbatim, and it said almost nothing: "Microsoft Sentinel, Microsoft
    Corporation" on thirty of thirty-two rows. Two words of signal, one line of
    noise per row, on a table read by scanning the first column.

    `not installed` stays. That is a fact about this tenant rather than about
    the publisher, and it is the one thing that separates a row you could act on
    from one you already have.
    """
    from pylon.report_detections import build

    rec = {"generated_at": "2026-09-11T00:00:00", "solutions": [
        {"display_name": "Azure Web Application Firewall",
         "publisher": "Microsoft Sentinel, Microsoft Corporation",
         "installed": True, "version_installed": "3.0.2",
         "version_available": "3.0.2", "analytics_rules": 10,
         "action": "connect", "action_detail": "x"},
        {"display_name": "Microsoft Entra ID Protection",
         "publisher": "Microsoft Sentinel, Microsoft Corporation",
         "installed": False, "version_installed": None,
         "version_available": "3.0.4", "analytics_rules": 0,
         "action": "install", "action_detail": "x"},
    ]}
    html = build({"workspace": "w", "generated_at": "2026-09-11T00:00:00"}, rec)

    assert "Azure Web Application Firewall" in html
    assert "Microsoft Corporation" not in html, "the publisher line is back"
    assert "not installed" in html, "the one marker that is about THIS tenant"


def test_the_content_hub_page_is_named_for_what_it_holds():
    """It shipped as `detection_recommendations.html`, which named the wrong
    thing: the page is the Content Hub work list -- install the solution, then
    create the rules -- and "detections" is what the OTHER report is about.

    The name is load-bearing in four places, which is why it is asserted rather
    than left to a grep: the writer, the README's file table, `.gitignore`, and
    the release scan's must-not-ship list. A rename that misses any one of them
    either fails to ship or lets a scan artifact reach a public repository.
    """
    import pathlib

    from pylon.report_detections import OUT

    assert OUT == "content_hub_recommendations.html", OUT

    root = pathlib.Path(__file__).resolve().parents[1]
    ignore = (root / ".gitignore").read_text(encoding="utf-8")
    assert OUT in ignore, ".gitignore must cover it or a scan output gets committed"
    # The old name stays ignored too: every existing checkout has one on disk,
    # and renaming away from it must not make it committable.
    assert "detection_recommendations.html" in ignore

    readme = (root / "README.md").read_text(encoding="utf-8")
    assert OUT in readme, "the README's file table names what a run leaves behind"
    assert "detection_recommendations.html" not in readme, "the old name is stale"

    # Only where the release script is present. It deletes ITSELF from the tree
    # it builds -- it is a tool for releasing this repo, not part of the tool
    # being released -- so asserting unconditionally makes the published copy of
    # this suite fail on a file that is correctly absent. Caught by running the
    # suite from a fresh clone of the published repo, which is the only place
    # the difference shows.
    release = root / "scripts/make-release.sh"
    if release.exists():
        assert OUT in release.read_text(encoding="utf-8"), (
            "the release scan must refuse to ship it"
        )
