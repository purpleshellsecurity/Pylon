"""Every key `pylon config set` accepts must be read by something.

`PYLON_MAX_COST` and `PYLON_MAX_TOKENS` were on the allowlist and nothing ever
read them. `pylon config set PYLON_MAX_COST=1` was accepted, written to the
file, and had no effect on any run: a spend cap someone believed they had set
and did not have. That is the worst shape a config key can take, because it
fails silently in the direction of spending money.

The reverse matters too. `PYLON_VERIFY_WORKSPACE` and `PYLON_KUSTAINER_URL` are
the switches that decide whether a detection is CHECKED or merely well formed,
and they were readable only from the environment -- so the two settings worth
persisting were the two that could not be.
"""

import pathlib
import re

from pylon import config

SRC = pathlib.Path(config.__file__).parent


def _read_anywhere() -> set[str]:
    """Every PYLON_* name the package actually reads, outside config.py itself."""
    found: set[str] = set()
    for path in SRC.rglob("*.py"):
        if path.name == "config.py":
            continue
        found |= set(re.findall(r"PYLON_[A-Z_]+", path.read_text()))
    return found


def test_every_pylon_key_on_the_allowlist_is_read_by_something():
    pylon_keys = {k for k in config._ALLOWED if k.startswith("PYLON_")}
    dead = pylon_keys - _read_anywhere()
    assert dead == set(), (
        f"accepted by `pylon config set` and read by nothing: {sorted(dead)}. "
        "A setting that does nothing is worse than no setting.")


def test_the_two_gate_switches_can_be_stored_not_only_exported():
    assert "PYLON_VERIFY_WORKSPACE" in config._ALLOWED
    assert "PYLON_KUSTAINER_URL" in config._ALLOWED


def test_the_caps_that_were_never_read_are_gone():
    assert "PYLON_MAX_COST" not in config._ALLOWED
    assert "PYLON_MAX_TOKENS" not in config._ALLOWED


def test_the_allowlist_still_refuses_anything_dangerous():
    """The point of the allowlist: a KEY=value file setting PATH or LD_PRELOAD
    is a different and much worse thing than a config file."""
    for hostile in ("PATH", "LD_PRELOAD", "PYTHONPATH", "DYLD_INSERT_LIBRARIES"):
        assert hostile not in config._ALLOWED
