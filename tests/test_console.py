"""Colour is a convenience. Every one of these tests is really asking the same
question: does the output still read correctly when the colour is not there.
"""

from __future__ import annotations

import io

import pytest

from pylon import console


class _Tty(io.StringIO):
    def isatty(self):
        return True


class _Pipe(io.StringIO):
    def isatty(self):
        return False


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    # NOT `console.os.name`: that is the real os module, and setting it
    # process-wide makes pathlib hand out PosixPath on Windows.
    monkeypatch.setattr(console, "_on_windows", lambda: False)


def test_a_terminal_gets_colour():
    assert console.supported(_Tty()) is True
    assert console.heading("MEASURED", _Tty()) == "\033[94mMEASURED\033[0m"


def test_a_redirect_gets_plain_text():
    """`pylon analyze > scan.log` has to produce something readable, and a
    ticket pasted from it must not carry escape codes."""
    assert console.supported(_Pipe()) is False
    assert console.heading("MEASURED", _Pipe()) == "MEASURED"


def test_no_color_is_honoured(monkeypatch):
    """no-color.org: present and non-empty means suppress, whatever the value."""
    monkeypatch.setenv("NO_COLOR", "1")
    assert console.supported(_Tty()) is False


def test_no_color_set_empty_is_not_set(monkeypatch):
    """The convention is explicit that an empty value does NOT count."""
    monkeypatch.setenv("NO_COLOR", "")
    assert console.supported(_Tty()) is True


def test_a_dumb_terminal_gets_plain_text(monkeypatch):
    monkeypatch.setenv("TERM", "dumb")
    assert console.supported(_Tty()) is False


def test_a_stream_that_cannot_say_whether_it_is_a_tty_gets_plain_text():
    """Some wrappers raise on isatty. Guessing yes writes escapes into
    something that may not read them."""
    class _Odd(io.StringIO):
        def isatty(self):
            raise ValueError("no idea")
    assert console.supported(_Odd()) is False


def test_windows_asks_the_console_first(monkeypatch):
    """Windows can interpret escapes only after the console host is asked. An
    unenabled console prints them literally, so a heading would arrive as
    "<-[94mMEASURED" -- worse than no colour."""
    # Same reason as the fixture above: patch the seam, never `os.name`.
    monkeypatch.setattr(console, "_on_windows", lambda: True)
    monkeypatch.setattr(console, "_windows_vt", lambda: False)
    assert console.supported(_Tty()) is False
    monkeypatch.setattr(console, "_windows_vt", lambda: True)
    assert console.supported(_Tty()) is True


def test_enabling_vt_never_raises():
    """It runs where there is no console attached at all. Microsoft's own
    guidance is to treat failure as a system to degrade from.

    Asserts what the name says -- that it RETURNS rather than raising -- not
    that it returns False. False is only the answer off Windows, or on a Windows
    box with no console attached; on a real console host it is True, and a test
    demanding False would fail there for being right.

    The `os.name = "nt"` patch that used to be here did nothing: `_windows_vt`
    never reads it. It also set os.name process-wide, which makes pathlib hand
    out WindowsPath on Linux -- the same fault as the fixture above, pointing
    the other way.
    """
    assert console._windows_vt() in (True, False)


def test_the_text_survives_stripping_the_escapes():
    coloured = console.heading("NOT MEASURED", _Tty())
    assert coloured.replace(console.BLUE, "").replace(console.RESET, "") \
        == "NOT MEASURED"


def test_every_escape_is_ascii():
    """The cp1252 crash was a non-ASCII arrow in the TEXT. Nothing this module
    adds can repeat it."""
    console.heading("MEASURED", _Tty()).encode("ascii")


# ── what a read state is allowed to say ──────────────────────────────────────

def test_a_read_detail_states_findings_not_methodology():
    """A read state's detail is printed on the operator's terminal AND listed
    in the report's unanswered-questions section. In both places it should say
    what was found.

    The Content Hub detail used to append two sentences explaining how
    alignment is measured and why the `enable` verdict exists. True, useful,
    and in the wrong place: on screen it rendered as a paragraph of internal
    reasoning under a heading of counts. Both sentences live in the module
    docstring, which is where a reader who wants them will look.
    """
    import pathlib
    src = pathlib.Path("src/pylon/contenthub.py").read_text(encoding="utf-8")
    detail = src[src.index('"ran": True, "detail"'):]
    detail = detail[:detail.index("\n\n")] if "\n\n" in detail else detail
    for phrase in ("Alignment is measured", "is the finding this leg exists for"):
        assert phrase not in detail, phrase


def test_the_content_hub_detail_agrees_its_noun_with_its_number():
    """"31 solution(s) installed" is honest and unmistakably machine output,
    and it is the first line under a heading somebody reads."""
    import pathlib
    src = pathlib.Path("src/pylon/contenthub.py").read_text(encoding="utf-8")
    assert "solution(s)" not in src


# ── one sentence, punctuated once ────────────────────────────────────────────

def test_a_content_hub_row_is_punctuated_like_a_sentence():
    """`_unfed` returned a clause that ended itself with a full stop, and five of
    the six places it lands embed it mid-sentence or close the sentence
    themselves. A live run printed:

        ... switch on Audit, AuditEvent., so its rule templates sit in the
        library and none of them can fire.

    A full stop inside a subordinate clause, and the same string produced ".."
    on the update and current rows. The clause is the caller's to punctuate.
    """
    from pylon.contenthub import _unfed

    emits = {"AzureDiagnostics": {
        "resources": ["a"] * 11,
        "types": ["Microsoft.Network/applicationGateways",
                  "Microsoft.Network/frontDoors",
                  "Microsoft.Cdn/profiles",
                  "Microsoft.Network/azureFirewalls"],
        "categories": ["Audit", "AuditEvent"],
        "ships_elsewhere": False, "never_configured": True,
    }}
    alignment, evidence = _unfed(["AzureDiagnostics"], emits)
    assert alignment == "unfed"
    assert not evidence.endswith("."), evidence

    # The sentence the reader actually sees, assembled the way `build` does.
    detail = (f"The solution is installed, but {evidence}, so its rule "
              "templates sit in the library and none of them can fire.")
    for wrong in (".,", "..", ". ,"):
        assert wrong not in detail, f"{wrong!r} in: {detail}"
    assert "AuditEvent, so its rule" in detail, detail


def test_no_evidence_clause_punctuates_itself():
    """The rule, not the one instance. Every branch of `_unfed` lands in the same
    six sentences, so any of them ending itself reintroduces the bug."""
    from pylon.contenthub import _unfed

    cases = [
        # nothing measured for this table at all
        (["SomeTable"], {}),
        # produced here, shipped to another workspace
        (["AzureDiagnostics"], {"AzureDiagnostics": {
            "resources": ["a"], "types": ["Microsoft.Network/azureFirewalls"],
            "categories": [], "ships_elsewhere": True, "never_configured": False}}),
        # produced here, nothing switched on
        (["AzureDiagnostics"], {"AzureDiagnostics": {
            "resources": ["a"], "types": ["Microsoft.Network/azureFirewalls"],
            "categories": ["Audit"], "ships_elsewhere": False,
            "never_configured": True}}),
    ]
    for needed, emits in cases:
        _alignment, evidence = _unfed(needed, emits)
        assert evidence, needed
        assert not evidence.rstrip().endswith("."), evidence


def test_a_solution_with_no_presence_test_says_so():
    """`presence` has three answers and two of them printed the same sentence.

    True means the resource was found in this tenant. False means it was looked
    for and is not here -- that row reads "Nothing here to collect from". None
    means this scan has no test for the solution and never looked, and there are
    64 tests against a Content Hub catalogue many times that size.

    Found on Azure Web Application Firewall, which has a test of its own now --
    it said "connect data" and named diagnostic categories on the strength of 11
    resources sharing nothing with a web application firewall except writing to
    AzureDiagnostics. The caveat it exposed is not specific to that solution, so
    this asserts the rule on one that still has no test: Content Hub carries far
    more solutions than the 64 tests here, and it always will.
    """
    from pylon import solutions

    present, why = solutions.presence(
        "Azure Security Benchmark", solutions.load(), {}, set(), set(), set(), 0)
    assert present is None, (present, why)
    assert "no presence test" in why, why


def test_a_solution_whose_presence_was_established_adds_no_caveat():
    """The caveat is empty when the question was answered, so a row that knows
    stays one sentence. Azure Firewall IS in the catalogue: absent from this
    tenant is a measurement, and that row already reads "Nothing here to collect
    from"."""
    from pylon import solutions

    present, why = solutions.presence(
        "Azure Firewall", solutions.load(), {}, set(), set(), set(), 0)
    assert present is False, (present, why)
    assert "no presence test" not in why, why


def test_an_empty_table_is_reported_as_empty_not_as_unmeasured():
    """The scan already knew and was throwing it away.

    `live_tables` is every table the usage meter saw inside the window. By the
    time `_unfed` runs, none of the solution's tables is in it -- the row would
    have resolved as fed otherwise -- so the table received nothing. That is a
    measurement, and it was being reported as "whether this tenant produces it
    was never established" on rows an operator knew perfectly well were off.
    """
    from pylon.contenthub import _unfed

    alignment, evidence = _unfed(
        ["SecurityEvent", "WindowsEvent"], {}, {"AzureActivity", "SigninLogs"})
    assert alignment == "unseen", alignment
    assert "received nothing in the window" in evidence, evidence
    assert "never established" not in evidence, evidence


def test_an_unread_meter_does_not_get_the_stronger_sentence():
    """An empty `live_tables` is a failed read and a workspace with no tables
    wearing the same clothes. Claiming a table is empty on the strength of a set
    that may simply be missing is the mistake the stronger sentence exists to
    avoid making."""
    from pylon.contenthub import _unfed

    alignment, evidence = _unfed(["SecurityEvent"], {}, set())
    assert alignment == "unmeasured", alignment
    assert "never established" in evidence, evidence


def test_the_three_unknowns_are_told_apart_by_value_not_by_prefix():
    """They shared one sentence, then were split by testing
    `evidence.startswith("nothing here was measured")`.

    Rewording the message then silently reassigns rows to the wrong sentence,
    and this codebase already carries that scar in rulehealth, where matching a
    phrase in another module's message decided whether a rule was faulty. Each
    unknown carries its own alignment value now.
    """
    import pathlib

    src = pathlib.Path(__file__).resolve().parents[1] / "src/pylon/contenthub.py"
    # Code, not prose. The comment above the branch quotes the old test verbatim
    # so the next reader knows why it went, and a blunt substring check reads
    # that quote as the thing it is banning.
    code = "\n".join(line for line in src.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))
    assert "evidence.startswith(" not in code, (
        "the sentence is being chosen by matching a prefix of the message again"
    )
    t = src.read_text(encoding="utf-8")
    for value in ('"unseen"', '"unmeasured"', '"unmatched"'):
        assert value in t, value


def test_a_measured_empty_table_is_not_filed_under_unproven():
    """`unseen` is an answer, not a shrug, and it was wearing the same chip as
    two rows where the scan admits it could not look.

    The usage meter RAN and the table received nothing. That is a measurement
    and an instruction -- switch the source on or accept that it is off -- and
    it belongs with "connect data", beside every other row whose tables are
    empty. `unmeasured` and `unmatched` stay unproven, because in those two the
    scan is reporting its own blind spot.

    Splitting the evidence into three sentences and leaving one verdict word
    meant the split changed nothing for a reader scanning the Do column, which
    is the column people read.
    """
    import ast
    import pathlib

    src = pathlib.Path(__file__).resolve().parents[1] / "src/pylon/contenthub.py"
    code = "\n".join(line for line in src.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))
    assert 'action = "connect" if alignment == "unseen" else "review"' in code, (
        "an empty table that was actually measured is being filed as unproven"
    )
    # And the verdict word it lands on is the actionable one.
    from pylon.report_detections import ACTION_WORD

    assert ACTION_WORD["connect"] == "connect data"
    assert ACTION_WORD["review"] == "unproven"
    ast.parse(src.read_text(encoding="utf-8"))


# ── reading a solution's rules from the right API ────────────────────────────

def test_a_template_body_is_read_from_the_content_template_itself():
    """The LIST call strips `mainTemplate`; the query only arrives on a GET.

    Measured against a live tenant: 20 of 20 single GETs returned a populated
    body carrying query, techniques, tactics and requiredDataConnectors.
    """
    from unittest.mock import patch

    from pylon import contenthub

    payload = {"properties": {"mainTemplate": {"resources": [
        {"type": "Microsoft.OperationalInsights/workspaces/providers/metadata"},
        {"type": "Microsoft.SecurityInsights/AlertRuleTemplates",
         "properties": {"query": "AzureActivity | take 1",
                        "techniques": ["T1578"],
                        "requiredDataConnectors": [
                            {"connectorId": "AzureActivity",
                             "dataTypes": ["AzureActivity"]}]}},
    ]}}}
    with patch.object(contenthub, "_az_json", return_value=payload):
        props = contenthub.template_body("/ws", "abc")
    assert props and props["techniques"] == ["T1578"]
    # The resource type is `AlertRuleTemplates`, capital A. Matching on
    # "alertRules" found nothing and sent the first read of this down the
    # wrong branch in silence.
    assert contenthub.template_data_types(props) == {"AzureActivity"}


def test_a_template_that_cannot_be_read_is_absent_not_empty():
    """A failed GET must not look like a rule that needs no tables. Absent from
    the result, and the caller counts what it actually got."""
    from unittest.mock import patch

    from pylon import contenthub

    with patch.object(contenthub, "_az_json", return_value=None):
        assert contenthub.template_bodies("/ws", ["a", "b"]) == {}
        assert contenthub.template_body("/ws", "a") is None


def test_every_installed_template_is_read_not_only_the_unresolved_ones():
    """Fetching on demand was the wrong shape and this is the argument.

    `connector_map` is built from `alertRuleTemplates`, and that gallery holds
    477 templates against 306 installed on a live tenant, overlapping on 161 by
    name. So the path most solutions take -- "its connector resolved" -- rests
    on a list that does not carry most Content Hub content. Falling back to the
    contentTemplates only where the connector failed left the majority resting
    on the bad source, which is the opposite of the fix.
    """
    import pathlib

    src = pathlib.Path(__file__).resolve().parents[1] / "src/pylon/contenthub.py"
    code = "\n".join(line for line in src.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))
    assert "if not types and n_rules:" not in code, (
        "template bodies are being read conditionally again"
    )
    assert "bodies = template_bodies(" in code


def test_a_product_that_runs_on_other_resources_still_gets_a_presence_test():
    """Azure WAF is not a resource type, so a name match against the harvested
    service files could never find it, and the row fell through to a guess.

    Measured on a live tenant: it said "connect data" and named diagnostic
    categories on the strength of 11 resources that share nothing with a web
    application firewall except writing to AzureDiagnostics. Azure Firewall, one
    row above it, correctly said "nothing here to collect from" -- because it IS
    a resource type and had a test.

    Microsoft: "Azure Web Application Firewall can be deployed with these
    Microsoft services: Azure Application Gateway, Azure Application Gateway for
    Containers, Azure Front Door, Azure Content Delivery Network." Four hosts,
    which is why one resource_type could not express it.
    """
    from pylon import solutions

    cat = solutions.load()
    absent, why = solutions.presence(
        "Azure Web Application Firewall", cat, {}, set(), set(), set(), 0)
    assert absent is False, (absent, why)
    assert "no Application Gateway" in why, why

    for host in ("microsoft.network/applicationgateways",
                 "microsoft.cdn/profiles",
                 "microsoft.network/frontdoors",
                 "microsoft.servicenetworking/trafficcontrollers"):
        present, why = solutions.presence(
            "Azure Web Application Firewall", cat, {host: 2}, set(), set(), set(), 0)
        assert present is True, (host, present, why)
        assert why.startswith("2 "), why


def test_a_structural_absence_says_remove_whichever_map_proved_it():
    """"Remove" is reserved for STRUCTURAL absence: no such resource exists, so
    no setting can make the solution useful. That branch tested whether the
    harvested catalogue knew a resource_type, which is now the wrong question --
    a `resources` rule proves the same thing for a product that runs on other
    resources rather than being one.
    """
    import pathlib

    src = pathlib.Path(__file__).resolve().parents[1] / "src/pylon/contenthub.py"
    code = "\n".join(line for line in src.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))
    assert 'NON_RESOURCE.get(name) or {}).get("kind") == "resources"' in code, (
        "a product with no ARM type of its own cannot reach the remove branch"
    )
