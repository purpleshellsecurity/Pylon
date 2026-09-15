"""Checkpoint files must be written and read as UTF-8, whatever the locale.

agent_framework's `_checkpoint.py` opens its files four times with no encoding
and writes `json.dump(..., ensure_ascii=False)`. The non-ASCII in a checkpoint
-- the box drawing from the attack diagram, the status emoji -- therefore goes
through the locale codec. On Linux and macOS that is UTF-8 and nothing is ever
noticed. On Windows it is cp1252 and saving raises:

    UnicodeEncodeError: 'charmap' codec can't encode character '\\u2502'

which makes `--resume` unusable there. Found by the OS matrix; it was the last
red cell after everything in this repo had been fixed.
"""
import builtins
import importlib

from pylon.engine import _force_utf8_checkpoints

MODULE = "agent_framework._workflows._checkpoint"


def test_the_checkpoint_module_opens_text_as_utf8():
    assert _force_utf8_checkpoints() is True
    mod = importlib.import_module(MODULE)
    assert mod.open is not builtins.open, "still using the locale encoding"


def test_a_checkpoint_round_trips_the_characters_pylon_actually_writes(tmp_path):
    """The premise, with the real characters. If a playbook ever became pure
    ASCII this stops being load-bearing, and the test says so rather than
    passing for free."""
    _force_utf8_checkpoints()
    mod = importlib.import_module(MODULE)

    from pylon.playbook import attack_diagram
    body = attack_diagram("StorageBlobLogs", "GetBlob", "T1619")
    assert any(ord(c) > 127 for c in body), "no non-ASCII left to protect"

    path = tmp_path / "c.json"
    with mod.open(path, "w") as f:
        f.write(body)
    with mod.open(path) as f:
        assert f.read() == body


def test_builtins_open_is_not_touched(tmp_path):
    """The shadow is a module global, so only that module sees it. Patching
    builtins would change every file read in the process, including the
    caller's."""
    _force_utf8_checkpoints()
    assert builtins.open.__name__ == "open"
    # And a binary open through the shadow must not acquire an encoding.
    mod = importlib.import_module(MODULE)
    path = tmp_path / "b.bin"
    with mod.open(path, "wb") as f:
        f.write(b"\xff\xfe")
    assert path.read_bytes() == b"\xff\xfe"


def test_patching_twice_is_harmless():
    assert _force_utf8_checkpoints() is True
    assert _force_utf8_checkpoints() is True
