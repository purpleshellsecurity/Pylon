"""The README has to describe the tool that exists.

Two things went wrong on the same day, and each is one of the checks below.

`pylon tabledrift` shipped and the README did not mention it. Nothing was wrong
with either the code or the prose -- they just stopped agreeing, and no test
cared. A verb nobody can find is a verb that does not exist.

And the "Known gaps" section claimed two faults the code does not have: that
`design` has no progress output (`progress.py` has existed for a while), and
that `sentinel.py` and `rules.py` are two competing Sentinel access layers
(`sentinel.py` was deleted with the gap-scan removal). A README that invents
faults is the same defect as one that hides them -- either way the reader cannot
use it to decide anything.

WHAT THESE CHECKS CANNOT DO
---------------------------
They catch a name that has gone stale, not a claim that has. "design has no
progress output" names no file, so nothing here would have caught it; only
reading the sentence against the code does. The lesson worth keeping is the
cheaper half: prose that cites a filename can be checked, so cite filenames.
"""

import pathlib
import re

import pytest

from pylon.cli import build_parser

README = pathlib.Path(__file__).resolve().parents[1] / "README.md"


def _commands() -> list[str]:
    """Every subcommand the CLI offers, read from the parser rather than from
    `--help` text: no subprocess, and it cannot drift from what argparse
    actually dispatches on."""
    import argparse

    for action in build_parser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            return sorted(action.choices)
    raise AssertionError("the CLI has no subparsers — this check is looking at nothing")


def _subcommands() -> list[str]:
    """Every nested verb, as the reader types it: "design playbooks", not
    "playbooks". `_commands` stops at the top level, which is how `design
    playbooks` shipped with the README naming only `list`, `plan` and
    `detections` -- a whole feature nobody reading the page could find."""
    import argparse

    found = []

    def walk(parser, path):
        for action in parser._actions:
            if not isinstance(action, argparse._SubParsersAction):
                continue
            for name, child in action.choices.items():
                found.append(f"{path} {name}".strip())
                walk(child, f"{path} {name}".strip())

    walk(build_parser(), "")
    return sorted(v for v in found if " " in v)


def test_there_are_commands_to_check():
    """A check that enumerates nothing passes for ever."""
    found = _commands()
    assert len(found) >= 5, found


@pytest.mark.parametrize("command", _commands())
def test_every_command_is_in_the_readme(command):
    """`tabledrift` shipped undocumented. A verb nobody can find does not exist
    as far as a reader is concerned.

    Deliberately not "every command has its own `##` section": `analyze`,
    `recommend` and `config` are documented inside other sections and that is a
    reasonable way to write a README. Being mentioned at all is the bar.
    """
    text = README.read_text(encoding="utf-8")
    assert re.search(rf"\bpylon {re.escape(command)}\b", text), (
        f"`pylon {command}` is a real command and the README never mentions it"
    )


@pytest.mark.parametrize("command", _subcommands())
def test_every_nested_verb_is_in_the_readme(command):
    """`design playbooks` is a paid command that produces the tool's second
    artefact, and the README described `list`, `plan` and `detections` while
    never naming it. The top-level check passed the whole time, because
    `pylon design` appears everywhere."""
    text = README.read_text(encoding="utf-8")
    assert re.search(rf"\bpylon {re.escape(command)}\b", text), (
        f"`pylon {command}` is a real command and the README never mentions it"
    )


def test_there_are_nested_verbs_to_check():
    """The same guard as above: a parametrize over an empty list is green for
    ever and says nothing."""
    assert len(_subcommands()) >= 4, _subcommands()


def test_no_command_in_the_readme_is_imaginary():
    """The other direction. A README naming a verb that was renamed or removed
    sends someone to a command that errors."""
    text = README.read_text(encoding="utf-8")
    claimed = set(re.findall(r"\bpylon ([a-z][a-z-]+)\b", text))
    real = set(_commands())
    # `pylon --setup`, `pylon design detections` etc: the second word is a flag
    # or a noun under a verb, not a top-level command.
    nouns = {"design", "config"}
    invented = {c for c in claimed - real
                if not any(f"pylon {v} {c}" in text for v in nouns)}
    assert not invented, (
        "the README names commands that do not exist: " + ", ".join(sorted(invented))
    )


def test_every_module_the_readme_names_exists():
    """`sentinel.py` was deleted and the README kept citing it as half of a
    problem the codebase no longer has.

    This is the cheap half of keeping prose honest: a claim that cites a
    filename can be checked mechanically, so citing filenames is worth doing.
    A claim that cites none -- "design has no progress output" -- cannot be, and
    is why this file's docstring says what these checks do not cover.
    """
    root = README.parent
    text = README.read_text(encoding="utf-8")
    named = set(re.findall(r"`([a-z_][a-z0-9_]*\.py)`", text))
    missing = sorted(
        name for name in named
        if not any(root.rglob(name)) and not (root / name).exists()
    )
    assert not missing, (
        "the README cites modules that are not in the tree: " + ", ".join(missing)
    )


# ── the README against the code, mechanically ────────────────────────────────
# The checks above hold the VERBS to the CLI. These hold everything else a
# reader copies or relies on: a flag in an example, a file path, a version, an
# environment variable. A doc scan run by hand once rots the day after; the
# point of putting it here is that it runs on every commit.

import pathlib
import subprocess

import pylon

_README = pathlib.Path(__file__).resolve().parents[1] / "README.md"
_ROOT = _README.parent


def _examples() -> list[str]:
    """Every `pylon ...` line in a bash block, which is what a reader pastes."""
    out = []
    for block in re.findall(r"```bash\n(.*?)```", _README.read_text(), re.S):
        for line in block.splitlines():
            line = line.strip()
            if line.startswith("pylon ") and not line.startswith("pylon config"):
                out.append(line)
    return sorted(set(out))


def test_there_are_examples_to_check():
    assert len(_examples()) > 5


@pytest.mark.parametrize("example", _examples())
def test_every_flag_in_an_example_exists(example):
    """A flag that does not exist is worse than an undocumented one: the reader
    pastes it, argparse refuses, and the first thing the tool does is fail."""
    parts = example.split()
    verb = []
    for token in parts[1:]:
        if token.startswith("-"):
            break
        verb.append(token)
    if not verb:
        pytest.skip("no verb")
    helptext = subprocess.run(["pylon", *verb, "--help"], capture_output=True,
                              text=True, cwd=_ROOT).stdout
    for flag in {t.split("=")[0] for t in parts if t.startswith("--")}:
        assert flag in helptext, f"{flag} is not a flag of `{' '.join(verb)}`"


def test_every_file_path_the_readme_names_exists():
    paths = set(re.findall(r"`((?:src/|scripts/|docs/|tests/)[\w./-]+)`",
                           _README.read_text()))
    missing = sorted(p for p in paths if not (_ROOT / p).exists())
    assert missing == [], f"named in the README and not on disk: {missing}"


def test_no_stale_version_number():
    """The version gate at the top of this project exists because a stale
    checkout reporting an old version is how a whole session gets spent against
    the wrong code."""
    stale = [v for v in re.findall(r"\bpylon[ -]?(\d+\.\d+\.\d+)\b",
                                   _README.read_text())
             if v != pylon.__version__]
    assert stale == [], f"README names version(s) {stale}; package is {pylon.__version__}"


def _env_vars(text: str) -> set[str]:
    return set(re.findall(r"PYLON_[A-Z_]+", text))


def test_every_environment_variable_the_code_reads_is_documented():
    """Eleven of twelve were undocumented, including the two that decide whether
    a detection is CHECKED or merely well formed. A switch nobody can find is a
    switch nobody uses."""
    read: set[str] = set()
    for path in (_ROOT / "src" / "pylon").rglob("*.py"):
        read |= _env_vars(path.read_text(encoding="utf-8"))
    undocumented = sorted(read - _env_vars(_README.read_text()))
    assert undocumented == [], f"read by the code, absent from the README: {undocumented}"


def test_no_environment_variable_is_documented_but_dead():
    """The other direction, and the one that cost something: PYLON_MAX_COST was
    accepted by `pylon config set`, stored, and read by nothing -- a spend cap
    someone believed they had."""
    read: set[str] = set()
    for path in (_ROOT / "src" / "pylon").rglob("*.py"):
        read |= _env_vars(path.read_text(encoding="utf-8"))
    phantom = sorted(_env_vars(_README.read_text()) - read)
    assert phantom == [], f"documented and read by nothing: {phantom}"
