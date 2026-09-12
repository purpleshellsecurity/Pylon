"""Service-gate refusal must be clean, not a traceback (finding F15).

When the gate blocks an unknown service it short-circuits by setting a
plain-string result, so the agent response reaching run_threat_phase can be a
bare `str`. The old code did `response.value` on it and crashed with
`AttributeError: 'str' object has no attribute 'value'`. These lock in a clean
ServiceGateError instead.
"""

import pytest

from pylon.engine import ServiceGateError, _unwrap_threat_response


class _Resp:
    """Minimal stand-in for an agent response object."""

    def __init__(self, value=None, text=None):
        self.value = value
        self.text = text


def test_unwrap_returns_structured_value():
    sentinel = object()
    assert _unwrap_threat_response(_Resp(value=sentinel)) is sentinel


def test_unwrap_bare_string_raises_clean_gate_error():
    # This is the exact shape that used to crash with AttributeError.
    msg = '"Banana Vault" does not appear to be a valid service for azure-control-plane.'
    with pytest.raises(ServiceGateError) as ei:
        _unwrap_threat_response(msg)
    assert "Banana Vault" in str(ei.value)


def test_unwrap_none_value_falls_back_to_response_text():
    with pytest.raises(ServiceGateError) as ei:
        _unwrap_threat_response(_Resp(value=None, text="unknown service message"))
    assert "unknown service message" in str(ei.value)


def test_unwrap_none_value_no_text_still_clean():
    # No usable message anywhere — still a clean ServiceGateError, never AttributeError.
    with pytest.raises(ServiceGateError):
        _unwrap_threat_response(_Resp(value=None, text=None))
