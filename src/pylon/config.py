"""Persistent configuration, because a CLI cannot export into your shell.

`pylon --setup` runs as a child process. Anything it exports dies with it, so a
setup command can either print lines for you to paste — barely better than
telling you what is missing — or write a file the tool reads on its own. This is
that file.

Precedence, highest first:

    1. a real environment variable
    2. PYLON_CONFIG, if set, pointing at a file
    3. ./pylon.env in the working directory   (per-project)
    4. ~/.config/pylon/config.env             (per-user)

A real environment variable always wins. Someone who exports a key for one
command must not be silently overridden by a file they set up weeks ago, and CI
that sets secrets in the environment must not be affected by a stray file.

The format is `KEY=value`, one per line, `#` for comments — the same shape as
the export lines it replaces, minus the word `export`, so a file can be pasted
from a shell history and mostly work.
"""

from __future__ import annotations

import os
from pathlib import Path

_FILENAME = "config.env"
_PROJECT_FILE = "pylon.env"

# Only these are read from a file. An arbitrary KEY=value file setting PATH or
# LD_PRELOAD is a different and much worse thing than a config file, so the
# loader carries an allowlist rather than trusting whatever it finds.
_ALLOWED = frozenset({
    "PYLON_PROVIDER",
    "OPENAI_API_KEY", "OPENAI_CHAT_MODEL", "OPENAI_MODEL",
    "AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_CHAT_MODEL",
    "ANTHROPIC_API_KEY", "ANTHROPIC_CHAT_MODEL",
    "AZURE_SUBSCRIPTION_ID", "AZURE_SENTINEL_RESOURCE_GROUP",
    "AZURE_SENTINEL_WORKSPACE_NAME", "AZURE_LOG_ANALYTICS_WORKSPACE_ID",
    "PYLON_MAX_CONCURRENCY", "PYLON_MAX_RETRIES",
    "PYLON_CALL_TIMEOUT", "PYLON_CALL_DEADLINE",
    "PYLON_PRICE_INPUT", "PYLON_PRICE_OUTPUT", "PYLON_PRICE_GB",
    # The two gates. They were reachable only by exporting the variable, which
    # meant the switches that decide whether a detection is CHECKED or merely
    # well formed could not be stored anywhere a reader would look.
    "PYLON_VERIFY_WORKSPACE", "PYLON_VERIFY_WINDOW", "PYLON_KUSTAINER_URL",
})
# `PYLON_MAX_COST` and `PYLON_MAX_TOKENS` were on this list and nothing ever read
# them. `pylon config set PYLON_MAX_COST=1` was accepted, stored, and had no
# effect on any run -- a cap someone believed they had set. The caps are
# `--max-cost` and `--max-tokens` on the commands that spend, so the honest fix
# is to stop accepting a key that does nothing rather than to keep it for
# compatibility with a promise that was never kept.


def user_config_path() -> Path:
    """Where `--setup` writes. Honours XDG_CONFIG_HOME."""
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "pylon" / _FILENAME


def candidate_paths() -> list[Path]:
    """Every config file that could apply, in precedence order."""
    paths = []
    explicit = os.environ.get("PYLON_CONFIG")
    if explicit:
        paths.append(Path(explicit))
    paths.append(Path.cwd() / _PROJECT_FILE)
    paths.append(user_config_path())
    return paths


def parse(text: str) -> dict[str, str]:
    """Parse KEY=value lines. Tolerates `export ` and surrounding quotes.

    Tolerant on purpose: the lines this replaces are shell exports, and someone
    will paste them with the word `export` still attached. Rejecting that would
    be technically correct and useless.
    """
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.removeprefix("export ").strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        # Strip a trailing comment only when it is clearly one; a '#' inside a
        # value (some keys contain one) must survive.
        if " #" in value:
            value = value.split(" #", 1)[0].strip()
        if key in _ALLOWED and value:
            values[key] = value
    return values


def load(paths: list[Path] | None = None) -> dict[str, str]:
    """Read the first config file that exists. Later files do NOT merge.

    Merging would make the effective config a function of two files, which is
    the kind of state that is fine until the day it is not: a stale per-user file
    silently supplying a key a per-project file deliberately omitted is a bug
    nobody can see. First file wins, whole.
    """
    for path in paths if paths is not None else candidate_paths():
        try:
            if path.is_file():
                return parse(path.read_text(encoding="utf-8"))
        except OSError:
            continue
    return {}


def apply(paths: list[Path] | None = None) -> tuple[Path | None, list[str]]:
    """Load config into os.environ WITHOUT overriding anything already set.

    Returns (file used, keys actually applied) so `--check` can say where a
    value came from — "it works but I cannot see why" is the failure mode a
    config file introduces, and naming the source is the whole mitigation.
    """
    for path in paths if paths is not None else candidate_paths():
        try:
            if not path.is_file():
                continue
            values = parse(path.read_text(encoding="utf-8"))
        except OSError:
            continue
        applied = []
        for key, value in values.items():
            # A real environment variable always wins.
            if not os.environ.get(key):
                os.environ[key] = value
                applied.append(key)
        return path, applied
    return None, []


def _restrict_to_owner(path: Path) -> bool:
    """Make `path` readable by its owner alone. True when that was achieved.

    `chmod(0o600)` DOES NOT DO THIS ON WINDOWS, and it does not fail either --
    it succeeds and sets only the read-only bit, so the file keeps whatever the
    directory's inherited ACL grants. The previous version caught OSError and
    moved on, which is why a config file holding an API key was written 0o666
    on Windows and the suite never said so: the assertion only ran on Linux.

    Windows is done with `icacls`, which ships with the OS:

        /inheritance:r   drop the inherited ACEs rather than adding to them --
                         granting the owner access while the parent still grants
                         Users would protect nothing
        /grant:r USER:F  replace any existing grant for this user, not append

    Returns False rather than raising when it cannot be done. A config file the
    user asked for is still better than a crash, and `config set` reports it.
    """
    if os.name != "nt":
        try:
            path.chmod(0o600)
            return True
        except OSError:
            return False

    import getpass
    import subprocess

    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no name to grant to; nothing else to try
        return False
    try:
        done = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
            capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def write(values: dict[str, str], path: Path | None = None) -> Path:
    """Write a config file, readable only by its owner.

    It holds an API key, so the mode matters. Written to a temporary file and
    renamed, so an interrupted write cannot leave a half-file that parses.
    """
    target = path or user_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Written by `pylon config set`. Safe to edit by hand.",
        "# A real environment variable always overrides anything here.",
        "",
    ]
    lines += [f"{k}={v}" for k, v in values.items() if k in _ALLOWED and v]

    tmp = target.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _restrict_to_owner(tmp)
    tmp.replace(target)
    return target
