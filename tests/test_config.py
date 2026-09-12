"""The config file, which exists because a CLI cannot export into your shell.

`pylon --setup` runs as a child process; anything it exports dies with it. So it
writes a file instead, and these tests pin the two properties that make that
safe: a real environment variable always wins, and the file cannot set arbitrary
variables.
"""

import os
import stat

from pylon import config


def _write(tmp_path, text, name="config.env"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# --- precedence ---------------------------------------------------------------


def test_a_real_environment_variable_always_wins(tmp_path, monkeypatch):
    # Someone exporting a key for one command must not be silently overridden by
    # a file they set up weeks ago, and CI secrets must beat a stray file.
    monkeypatch.setenv("OPENAI_CHAT_MODEL", "from-env")
    path = _write(tmp_path, "OPENAI_CHAT_MODEL=from-file")
    config.apply([path])
    assert os.environ["OPENAI_CHAT_MODEL"] == "from-env"


def test_the_file_fills_only_what_is_unset(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_CHAT_MODEL", "from-env")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    path = _write(tmp_path, "OPENAI_CHAT_MODEL=from-file\nOPENAI_API_KEY=sk-file")
    used, applied = config.apply([path])
    assert used == path
    assert applied == ["OPENAI_API_KEY"]
    assert os.environ["OPENAI_API_KEY"] == "sk-file"


def test_the_first_existing_file_wins_whole(tmp_path, monkeypatch):
    # Not merged. A stale per-user file quietly supplying a key that a
    # per-project file deliberately omitted is a bug nobody can see.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_CHAT_MODEL", raising=False)
    first = _write(tmp_path, "OPENAI_API_KEY=sk-first", "a.env")
    second = _write(tmp_path, "OPENAI_CHAT_MODEL=gpt-5", "b.env")
    config.apply([first, second])
    assert os.environ["OPENAI_API_KEY"] == "sk-first"
    assert not os.environ.get("OPENAI_CHAT_MODEL")


def test_a_missing_file_is_skipped_not_an_error(tmp_path):
    assert config.apply([tmp_path / "nope.env"]) == (None, [])


# --- what a file may set ------------------------------------------------------


def test_a_file_cannot_set_arbitrary_variables(tmp_path, monkeypatch):
    # The reason there is an allowlist. A KEY=value file that can set PATH or
    # LD_PRELOAD is a different and much worse thing than a config file.
    monkeypatch.setenv("PATH", "/original")
    config.apply([_write(tmp_path, "PATH=/evil\nLD_PRELOAD=/evil.so")])
    assert os.environ["PATH"] == "/original"
    assert "LD_PRELOAD" not in os.environ


def test_parsing_tolerates_export_and_quotes(tmp_path):
    # The lines this replaces are shell exports; someone will paste them with the
    # word still attached. Rejecting that would be correct and useless.
    values = config.parse(
        'export OPENAI_API_KEY="sk-x"\n'
        "  OPENAI_CHAT_MODEL = 'gpt-5'  \n"
        "# a comment\n"
        "\n"
        "PYLON_PROVIDER=openai   # trailing comment\n"
    )
    assert values == {
        "OPENAI_API_KEY": "sk-x",
        "OPENAI_CHAT_MODEL": "gpt-5",
        "PYLON_PROVIDER": "openai",
    }


def test_a_hash_inside_a_value_survives():
    # Only " #" is a comment. Some keys genuinely contain a '#'.
    assert config.parse("OPENAI_API_KEY=sk-aa#bb")["OPENAI_API_KEY"] == "sk-aa#bb"


def test_a_malformed_line_is_ignored_not_fatal():
    assert config.parse("this is not a config line\nPYLON_PROVIDER=openai") == {
        "PYLON_PROVIDER": "openai"
    }


# --- writing ------------------------------------------------------------------


def test_the_written_file_is_owner_readable_only(tmp_path):
    # It holds an API key.
    path = config.write({"OPENAI_API_KEY": "sk-secret"}, tmp_path / "c.env")
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode & (stat.S_IRGRP | stat.S_IROTH) == 0, oct(mode)


def test_a_written_file_round_trips(tmp_path):
    values = {"PYLON_PROVIDER": "azure-openai", "OPENAI_CHAT_MODEL": "my-deployment"}
    path = config.write(values, tmp_path / "c.env")
    assert config.parse(path.read_text(encoding="utf-8")) == values


def test_writing_does_not_persist_a_disallowed_key(tmp_path):
    path = config.write({"PATH": "/evil", "PYLON_PROVIDER": "openai"}, tmp_path / "c.env")
    assert "PATH" not in path.read_text(encoding="utf-8")


def test_writing_creates_the_directory(tmp_path):
    path = config.write({"PYLON_PROVIDER": "openai"}, tmp_path / "a" / "b" / "c.env")
    assert path.is_file()


def test_no_half_written_file_is_left_behind(tmp_path):
    # Written to a temp file and renamed, so an interrupted write cannot leave
    # something that parses to a partial config.
    path = config.write({"PYLON_PROVIDER": "openai"}, tmp_path / "c.env")
    assert not list(tmp_path.glob("*.tmp"))
    assert path.is_file()


# ── every script that reads credentials must load the config file ────────────


_CREDENTIAL_MARKERS = (
    "make_chat_client",      # builds a model client
    "EngineRequest",         # drives a run, which builds one
    "DefaultAzureCredential",
    "AZURE_LOG_ANALYTICS_WORKSPACE_ID",
    "workspace_config_from_env",
)


def _scripts_reading_credentials():
    """(path, source) for each script that needs configuration to work."""
    import pathlib

    for path in sorted(pathlib.Path(__file__).resolve().parent.parent.glob("scripts/*.py")):
        source = path.read_text(encoding="utf-8")
        if any(marker in source for marker in _CREDENTIAL_MARKERS):
            yield path, source


def test_every_credential_reading_script_applies_the_config():
    """`config.apply()` is what reads ~/.config/pylon/config.env. A script that
    skips it works only when the variables happen to be exported already, and
    fails in a way that points somewhere else entirely: eval.py died with
    `SettingNotFoundError: Exactly one of 'base_url', 'endpoint' must be
    provided`, which names the model client and says nothing about the config
    file that existed and was never read.

    Two scripts had it and two did not. This exists so the third one cannot.
    """
    missing = [
        path.name
        for path, source in _scripts_reading_credentials()
        if "config.apply()" not in source
    ]
    assert not missing, (
        "these scripts read credentials but never load the config file: "
        + ", ".join(missing)
    )


def test_the_check_is_actually_looking_at_something():
    """A guard that matches no files passes for ever. If the markers stop
    matching — a script renames its imports, say — this fails rather than
    silently protecting nothing.

    Was `len(found) >= 4`, which is a count of how many scripts happened to read
    credentials the day it was written. `audit-table-schemas.py` legitimately
    stopped when its live-capture path went with `sentinel`, and a threshold that
    has to be edited every time a script changes shape does not protect anything
    the emptiness check does not already cover.
    """
    found = [path.name for path, _ in _scripts_reading_credentials()]
    assert found, "the credential markers match nothing — they have gone stale"
    assert "eval.py" in found, "the script whose absence started this must be in scope"
