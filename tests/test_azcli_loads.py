"""Parsing what `az` returned, without reintroducing the crash `run` prevents.

`run` guarantees a CompletedProcess in every case. Callers then checked
`returncode != 0`, found zero, and handed stdout to `json.loads` — so a zero
exit with output that is not JSON became a JSONDecodeError from inside the json
module, killing a twelve-leg scan and naming neither the leg nor the reason.

That is not hypothetical. The first Windows run died exactly this way on
`az graph query`.
"""

import subprocess

from pylon import azcli


def done(rc=0, out="", err=""):
    return subprocess.CompletedProcess(["az"], rc, out, err)


def test_good_json_parses():
    payload, error = azcli.loads(done(out='{"data": [1, 2]}'))
    assert payload == {"data": [1, 2]}
    assert error is None


def test_a_failed_call_reports_its_stderr():
    payload, error = azcli.loads(done(rc=1, err="not logged in"), default={})
    assert payload == {}
    assert error == "not logged in"


def test_a_failed_call_with_no_stderr_still_gives_a_reason():
    """"Something failed" with no explanation is the outcome this codebase
    treats as a bug, not as an acceptable answer."""
    _, error = azcli.loads(done(rc=3))
    assert "exited 3" in error


def test_empty_output_is_not_an_error():
    """az saying nothing is a real answer. Only the caller knows whether that
    means an empty list or an empty object, so `default` decides."""
    payload, error = azcli.loads(done(out="   "), default=[])
    assert payload == []
    assert error is None


def test_non_json_output_with_a_zero_exit_is_reported_not_raised():
    """The Windows failure, in the shape it actually arrived: a notice printed
    ahead of the real payload."""
    noisy = 'The command requires the extension resource-graph.\n{"data": []}'
    payload, error = azcli.loads(done(out=noisy), default={})
    assert payload == {}
    assert error and "not JSON" in error


def test_the_reason_quotes_what_az_actually_said():
    """"Expecting value: line 1 column 1" sends the reader to the json module.
    The first line of az's own output sends them to the cause."""
    _, error = azcli.loads(done(out="The command requires the extension resource-graph.\nmore"))
    assert "resource-graph" in error


def test_a_long_first_line_is_truncated():
    _, error = azcli.loads(done(out="x" * 5000))
    assert len(error) < 500
