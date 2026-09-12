"""Grounding doc parsers — offline unit tests (no network).

Guards the sample-query extractor, which silently returned nothing for every
table because the Azure Monitor query docs fence KQL as ```query (often CRLF),
while the extractor matched only ```kusto with a bare \\n.
"""

from pylon.grounding import _extract_kql_samples


def test_extracts_query_fenced_samples_lf():
    md = "intro\n```query\nAZKVAuditLogs\n| where HttpStatusCode >= 300\n```\nmore"
    assert "AZKVAuditLogs" in _extract_kql_samples(md)


def test_extracts_query_fenced_samples_crlf():
    # The real docs are CRLF — the regression this fixes.
    md = 'intro\r\n```query\r\nSigninLogs\r\n| where ResultType != "0"\r\n```\r\n'
    got = _extract_kql_samples(md)
    assert "SigninLogs" in got and "ResultType" in got


def test_still_extracts_kusto_and_kql_fences():
    assert "TableA" in _extract_kql_samples("```kusto\nTableA\n| take 1\n```")
    assert "TableB" in _extract_kql_samples("```kql\nTableB\n| take 1\n```")


def test_respects_limit():
    md = "".join(f"```query\nQ{i}\n```\n" for i in range(5))
    got = _extract_kql_samples(md, limit=2)
    assert "Q0" in got and "Q1" in got
    assert "Q2" not in got and "Q4" not in got


def test_no_fences_returns_empty():
    assert _extract_kql_samples("just prose, no code fences here") == ""


def test_verify_mitre_ids_records_unavailable_and_keeps_vectors(monkeypatch):
    """F: an unreachable MITRE bundle must fail LOUD, not silently pass. The run
    keeps its vectors (fail open) but records mitre_verification='unavailable'."""
    import asyncio

    from pylon import engine
    from pylon.grounding import MitreBundleUnavailable
    from pylon.models import AttackVector, ThreatAnalysis

    async def boom(_ids):
        raise MitreBundleUnavailable("bundle down")

    monkeypatch.setattr(engine, "mitre_technique_names", boom)
    analysis = ThreatAnalysis(
        service="X", platform="arm", executive_summary="s",
        attack_vectors=[
            AttackVector(
                name="v", priority="high", mitre_technique="T1078",
                operation="op", log_table="AzureActivity",
                alert_condition="c", rationale="r r.",
            )
        ],
    )
    out = asyncio.run(engine.verify_mitre_ids(analysis))
    assert out.mitre_verification == "unavailable"
    assert len(out.attack_vectors) == 1  # fail open — vectors kept
