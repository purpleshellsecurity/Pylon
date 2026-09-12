"""Which `az` gets handed to subprocess.

The bug this guards against cannot be reproduced on the machine the tests run
on, which is exactly why it needs a test. On Windows `az` is `az.cmd`, and
subprocess runs CreateProcess with no shell — Python's own documentation says
resolving an unqualified name that way is not guaranteed, and recommends
`shutil.which()`. The symptom is confusing rather than obvious: `az --version`
works in the terminal while Pylon reports it could not run az.

So the platform is faked. That is not as good as a Windows machine, but it does
hold the decision still.
"""

import os
import subprocess
from unittest import mock

import pytest

from pylon import azcli


@pytest.fixture(autouse=True)
def _no_cache():
    """`executable()` is cached, and a cache shared between tests would make
    the second one assert whatever the first one happened to resolve."""
    azcli.executable.cache_clear()
    yield
    azcli.executable.cache_clear()


def test_unix_uses_the_bare_name():
    """PATH lookup already works there. Resolving would add a cache to
    invalidate and change nothing."""
    with mock.patch.object(os, "name", "posix"):
        assert azcli.executable() == "az"


def test_windows_resolves_to_a_full_path():
    with mock.patch.object(os, "name", "nt"), \
         mock.patch("shutil.which", return_value=r"C:\Program Files\az.cmd"):
        assert azcli.executable() == r"C:\Program Files\az.cmd"


def test_windows_falls_back_to_the_bare_name_when_az_is_absent():
    """A missing `az` must stay this module's own "could not run az", with the
    reason it already writes. Raising something else somewhere else would move
    the failure out of the path every caller already handles."""
    with mock.patch.object(os, "name", "nt"), \
         mock.patch("shutil.which", return_value=None):
        assert azcli.executable() == "az"


def test_a_missing_az_is_still_a_failed_call_and_not_an_exception():
    """The guarantee `run` makes: a CompletedProcess in every case."""
    with mock.patch("subprocess.run", side_effect=FileNotFoundError("no az")):
        done = azcli.run(["account", "show"], timeout=5)
    assert isinstance(done, subprocess.CompletedProcess)
    assert done.returncode == azcli.COULD_NOT_RUN
    assert "could not run az" in done.stderr


def test_the_resolved_path_is_what_subprocess_receives():
    """The point of the whole change. Asserting `executable()` alone would pass
    even if `run` went on ignoring it."""
    with mock.patch.object(os, "name", "nt"), \
         mock.patch("shutil.which", return_value=r"C:\az.cmd"), \
         mock.patch("subprocess.run") as ran:
        ran.return_value = subprocess.CompletedProcess([], 0, "", "")
        azcli.run(["account", "show"], timeout=5)
    assert ran.call_args[0][0] == [r"C:\az.cmd", "account", "show"]
