"""Which build, which model, which run wrote this.

A run writes a plan, then detections, then playbooks, then verdicts, as four
files with no shared key. The only link between a plan's vector and the
detection built from it was a human-readable name the model is free to rewrite,
and it did: a plan asked for `SecretDelete (delete secret)` and the detection
came back `SecretDelete (Key Vault secret deletion)`, which broke the lookup
that finds ground truth.

Nothing said which build wrote any of it. Two SecretPurge detections were
compared and the only way to tell them apart was which directory they sat in.
"""


import pytest

from pylon import provenance
from pylon.models import EngineReport, ThreatAnalysis


@pytest.fixture(autouse=True)
def _fresh_run(monkeypatch):
    monkeypatch.setattr(provenance, "_RUN_ID", None)
    monkeypatch.delenv("PYLON_RUN_ID", raising=False)


def test_the_run_id_is_stable_within_a_process():
    """Everything one invocation writes must share it, or it joins nothing."""
    assert provenance.run_id() == provenance.run_id()


def test_a_second_process_gets_a_different_one(monkeypatch):
    first = provenance.run_id()
    monkeypatch.setattr(provenance, "_RUN_ID", None)
    assert provenance.run_id() != first


def test_the_environment_can_pin_it(monkeypatch):
    """The pipeline is three commands, so a script has to be able to stamp them
    all as one logical run."""
    monkeypatch.setenv("PYLON_RUN_ID", "release-check-42")
    monkeypatch.setattr(provenance, "_RUN_ID", None)
    assert provenance.run_id() == "release-check-42"


def test_a_stamp_carries_what_reproduces_or_discounts_a_run():
    got = provenance.stamp("design plan").model_dump()
    for field in ("run_id", "pylon_version", "generated_at", "provider", "command"):
        assert got[field], f"{field} is empty, so it answers nothing"
    assert got["generated_at"].endswith("Z"), "runs cross machines; use UTC"


def test_the_provider_defaults_to_what_the_client_would_use(monkeypatch):
    """A blank provider records nothing; the wrong one records a lie."""
    monkeypatch.delenv("PYLON_PROVIDER", raising=False)
    assert provenance.stamp("x").provider == "openai"


class TestArtefactsCarryIt:
    def test_a_plan_can(self):
        assert "provenance" in ThreatAnalysis.model_fields

    def test_a_report_can(self):
        assert "provenance" in EngineReport.model_fields

    @pytest.mark.parametrize("model", [ThreatAnalysis, EngineReport])
    def test_an_artefact_written_before_the_field_still_loads(self, model):
        """Defaulted on purpose: a stamp is not worth breaking every saved run."""
        assert model.model_fields["provenance"].default is None
