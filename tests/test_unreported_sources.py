"""A blind spot must be measured against the connector legs, not assumed.

`unreported` once came from the table list alone: any table in
UNREPORTED_SOURCES holding data was rendered as a source with no configuration
behind it. On the tenant this was written against that put three false
disclosures on the page -- Office365 and MicrosoftCloudAppSecurity were in the
ARM connector list and MicrosoftThreatProtection was reporting health -- so
these pin the suppression rather than the map.
"""

from pylon import crosscheck


def _tables(*names):
    return {n: 1 for n in names}


def test_a_source_a_connector_claims_is_not_a_blind_spot(monkeypatch):
    monkeypatch.setattr(crosscheck, "live_tables",
                        lambda g, d=30: (_tables("OfficeActivity"), None))
    out = crosscheck.check([], "guid", kinds={"Office365"})
    assert out["unreported"] == []


def test_a_source_nothing_claims_is_reported(monkeypatch):
    monkeypatch.setattr(crosscheck, "live_tables",
                        lambda g, d=30: (_tables("OfficeActivity"), None))
    out = crosscheck.check([], "guid", kinds=set())
    assert out["unreported"] == ["Office 365"]


def test_defender_xdr_is_claimed_by_the_health_leg_alone(monkeypatch):
    # The ARM API never lists this connector; SentinelHealth does. Seeing it
    # in either leg is enough, which is the whole point of the union.
    monkeypatch.setattr(crosscheck, "live_tables",
                        lambda g, d=30: (_tables("DeviceProcessEvents",
                                                 "DeviceNetworkEvents"), None))
    assert crosscheck.check([], "guid",
                            kinds={"MicrosoftThreatProtection"})["unreported"] == []
    assert crosscheck.check([], "guid", kinds=set())["unreported"] == [
        "Defender XDR / MDE"]


def test_unknown_connectors_withhold_the_claim(monkeypatch):
    # None means the legs did not run. That cannot be read as "no connectors",
    # which would put every table on the page as a blind spot.
    monkeypatch.setattr(crosscheck, "live_tables",
                        lambda g, d=30: (_tables("OfficeActivity",
                                                 "DeviceEvents"), None))
    assert crosscheck.check([], "guid", kinds=None)["unreported"] == []


def test_every_mapped_table_has_a_claimant():
    # A table in UNREPORTED_SOURCES with no CLAIMED_BY entry can never be
    # suppressed, so it would report a blind spot on every tenant forever.
    missing = set(crosscheck.UNREPORTED_SOURCES) - set(crosscheck.CLAIMED_BY)
    assert not missing, f"no connector kind can ever claim: {sorted(missing)}"


def test_connector_kinds_unions_both_legs(monkeypatch):
    # Patched at `azcli.run`, the module's own door. This used to reach past
    # crosscheck into `subprocess` -- and patching the stdlib is how a test
    # stops noticing that the code under it changed which call it makes.
    monkeypatch.setattr(crosscheck.azcli, "run",
                        lambda *a, **k: type("P", (), {
                            "returncode": 0,
                            "stdout": '{"value":[{"kind":"Office365"}]}'})())
    health = {"connectors": {"MicrosoftThreatProtection-MTPAlerts":
                             {"kind": "MicrosoftThreatProtection"}}}
    assert crosscheck.connector_kinds("/subscriptions/x", health) == {
        "Office365", "MicrosoftThreatProtection"}


def test_connector_kinds_survives_a_dead_arm_call(monkeypatch):
    monkeypatch.setattr(crosscheck.azcli, "run",
                        lambda *a, **k: type("P", (), {
                            "returncode": 1, "stdout": ""})())
    health = {"connectors": {"x": {"kind": "Office365"}}}
    assert crosscheck.connector_kinds("/subscriptions/x", health) == {"Office365"}


def _doc(detail):
    """The smallest document `report.build` will render, plus one detail line."""
    return {
        "generated_at": "2026-01-01T00:00:00Z", "workspace": "w", "scope": "full",
        "window_days": 30, "fresh_days": 3, "schema_version": 1,
        "resources": [], "tables": [], "coverage_gaps": [], "gaps": [],
        "rules": [], "endpoint_os": {},
        "summary": {"resources": 0, "resource_types": 0, "rules_total": 0,
                    "tables_checked": 0, "dark_resources": 0,
                    "loggable_resources": 0},
        "reads": {"differential": {"ran": True, "detail": detail}},
    }


def test_the_limitations_section_is_omitted_when_there_is_nothing_to_say():
    # A heading announcing what the scan cannot see, above nothing, claims a
    # blind spot by implication that the entries no longer support.
    from pylon import report
    html = report.build(_doc("34 table(s) with data in 30d"), None, None, None, None)
    assert "Limitations" not in html
    assert "What this scan cannot see" not in html


def test_the_limitations_section_appears_when_a_source_is_unclaimed():
    from pylon import report
    html = report.build(_doc(
        "34 table(s) with data in 30d; arriving via paths the configuration "
        "APIs do not report: Defender XDR / MDE"), None, None, None, None)
    assert "What this scan cannot see" in html
    assert "Defender XDR / MDE" in html


def test_the_privileged_role_notes_are_not_rendered():
    """Deliberately absent, and this records why rather than leaving the next
    reader to rediscover it.

    Two notes used to sit under the not-logging table. Both were true. Neither
    was usable: the first said three roles are assigned at subscription scope
    and therefore separate none of the rows, and the second said the count is a
    floor. A caveat about a measurement that changes no row is noise in a table
    whose whole job is to say what to go and fix.

    The measurement still happens and is still in analysis.json — this is a
    decision about what the page shows, not about what is checked. If a future
    version makes privilege actually rank the rows, the caveat earns its place
    back and this test should change with it.
    """
    from pylon import report
    doc = _doc("34 table(s) with data in 30d")
    doc["reads"]["role_assignments"] = {
        "ran": True,
        "detail": "79 role assignment(s) over 1 page(s); 30 are Owner/Contributor/"
                  "User Access Administrator, across 8 scope(s). Roles held through "
                  "a group, and custom roles granting the same rights, are not "
                  "counted -- this is a floor.",
    }
    html = report.build(doc, None, None, None, None)
    assert "Not every privileged role is counted" not in html
    assert "this is a floor" not in html
    assert "separates none of these rows" not in html
