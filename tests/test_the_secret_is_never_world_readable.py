"""The API key must never exist on disk at a permissive mode, not even briefly.

`config.write` used `Path.write_text`, which creates at `0666 & ~umask` --
measured 0644 -- and then narrowed to 0600 one line later. The docstring said
"readable only by its owner", true of the final file and not of the one that
briefly held the key. On a shared host any local user could read it in that
window.

OWASP's Secrets Management sheet requires the restriction to hold for the
lifetime of the stored secret, not to be applied after the fact.
"""
import os
import stat

import pytest

from pylon import config

pytestmark = pytest.mark.skipif(os.name == "nt",
                                reason="POSIX mode bits; Windows uses the ACL branch")


def test_the_temp_file_is_created_already_restricted(tmp_path, monkeypatch):
    """Watches the mode AT CREATION, not after. Checking the final file is what
    let this pass for as long as it did."""
    seen = {}
    real_open = os.open

    def spy(path, flags, mode=0o777, *a, **k):
        fd = real_open(path, flags, mode, *a, **k)
        if str(path).endswith(".tmp"):
            seen["mode"] = stat.S_IMODE(os.fstat(fd).st_mode)
        return fd

    monkeypatch.setattr(os, "open", spy)
    config.write({"OPENAI_API_KEY": "sk-secret"}, tmp_path / "c.env")

    assert "mode" in seen, "the temp file was not created through os.open"
    assert seen["mode"] == 0o600, (
        f"the secret existed at {oct(seen['mode'])} before being narrowed")


def test_the_final_file_is_owner_only(tmp_path):
    path = config.write({"OPENAI_API_KEY": "sk-secret"}, tmp_path / "c.env")
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH) == 0, oct(mode)


def test_an_existing_temp_file_is_not_silently_written_through(tmp_path):
    """O_EXCL. `config.tmp` is a predictable name, so a pre-created symlink
    there would otherwise be followed and the key written through it."""
    target = tmp_path / "c.env"
    decoy = tmp_path / "c.tmp"
    decoy.write_text("pre-existing", encoding="utf-8")
    with pytest.raises(FileExistsError):
        config.write({"OPENAI_API_KEY": "sk-secret"}, target)
    assert decoy.read_text(encoding="utf-8") == "pre-existing"
    assert not target.exists(), "the real file was written despite the failure"


def test_a_failed_write_leaves_no_half_file_holding_the_key(tmp_path, monkeypatch):
    """If writing raises after the file exists, the partial secret must go."""
    real_fdopen = os.fdopen

    class _Explodes:
        def __init__(self, handle):
            self._handle = handle
        def __enter__(self):
            return self
        def __exit__(self, *a):
            self._handle.close()
            return False
        def write(self, _text):
            raise RuntimeError("disk full")

    monkeypatch.setattr(os, "fdopen",
                        lambda fd, *a, **k: _Explodes(real_fdopen(fd, *a, **k)))
    with pytest.raises(RuntimeError):
        config.write({"OPENAI_API_KEY": "sk-secret"}, tmp_path / "c.env")
    assert list(tmp_path.glob("*.tmp")) == [], "a half-written secret survived"
