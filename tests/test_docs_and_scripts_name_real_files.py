"""Prose that cites a path must cite one that exists — in `docs/` and
`scripts/` too, not only the README.

`scripts/release-run.sh` told the reader, twice, to "read
docs/first-release-checklist.md and make the ship / no-ship call". The file did
not exist. A gate with a blank threshold never opens, and nothing failed,
because the only check of this kind read the README alone.

The README check is `test_readme_describes_the_tool.py` and this is the same
idea pointed at the other two places prose lives. It also covers `.md` and
`.sh`, where the README check covers `.py`: the file that was missing was a
markdown one.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# A path-shaped citation: a slashed path in backticks, or a bare docs/... or
# scripts/... reference in prose. Extensions are limited to the kinds of file
# prose actually points a reader at.
_CITED = re.compile(
    r"`?((?:docs|scripts|src|tests)/[A-Za-z0-9_./-]+\.(?:md|sh|py|ya?ml|toml))`?")


def _sources():
    for folder, pattern in (("docs", "*.md"), ("scripts", "*.sh")):
        yield from sorted((ROOT / folder).glob(pattern))


@pytest.mark.parametrize("path", list(_sources()),
                         ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_path_this_file_names_exists(path):
    text = path.read_text(encoding="utf-8")
    missing = sorted({
        cited for cited in _CITED.findall(text)
        if not (ROOT / cited).exists()
    })
    assert missing == [], (
        f"{path.parent.name}/{path.name} points the reader at files that are "
        f"not in the tree: {missing}")


def test_the_release_script_gate_actually_exists():
    """The specific one, named, so deleting the checklist fails loudly rather
    than reverting to a script that cites nothing."""
    script = ROOT / "scripts" / "release-run.sh"
    if not script.is_file():
        pytest.skip("release-run.sh is not shipped in a release tree")
    cited = "docs/first-release-checklist.md"
    assert cited in script.read_text(encoding="utf-8")
    checklist = ROOT / cited
    assert checklist.is_file(), f"{cited} is cited by the release script and missing"
    body = checklist.read_text(encoding="utf-8")
    assert "- [" in body, "the checklist has no boxes to tick"


def test_the_sources_scanned_are_not_empty():
    """A parametrised test over an empty list passes by saying nothing."""
    assert list(_sources()), "found no docs/*.md or scripts/*.sh to check"


# ── a bare module name is a citation too ─────────────────────────────────────
# The check above catches a PATH (`src/pylon/report.py`). It does not catch a
# bare module name (`report.py`), because the pattern requires a directory
# prefix -- and a bare name is how prose in `docs/` usually cites code.
#
# That gap had something in it. `docs/findings.md` pointed R-SEAM-2 at
# `report_detections.py:233-236` as the shape to copy. The module was deleted
# when the Content Hub section moved into `report.py`, and the ranked plan went
# on sending a reader to a file that was not there.
#
# This is the `sentinel.py` failure from `test_readme_describes_the_tool.py`'s
# own docstring, in a different file, caught by nothing -- the README gate reads
# only `README.md`. Same idea, pointed at `docs/` and `scripts/`.

_MODULE = re.compile(r"`([a-z_][a-z0-9_]*\.py)`")

# Where a module may live. NOT an rglob from the repo root: that walks `build/`
# and `.venv/`, so a deleted module answers "present" for as long as a stale
# build tree holds a copy -- which this checkout had, and which made the check
# weaker locally than in CI. See the same note in
# `test_readme_describes_the_tool.py`.
_SOURCE_DIRS = ("src", "tests", "scripts")

# Modules that are GONE and are cited on purpose, because the entry is about
# their deletion. Each needs a reason, and a name that is not on this list fails
# -- the fix being to decide which kind of citation it is rather than to widen
# the pattern. Same shape as the reviewed-asymmetry list in
# `test_a_direction_is_not_a_reason.py`: the exception is written down, so a new
# one cannot arrive quietly.
# Modules that are GONE and are cited on purpose, because the passage is ABOUT
# their deletion. Each maps to the files allowed to name it, and a reason.
#
# SCOPED, not global. The first version keyed on the name alone, which meant one
# legitimate historical mention exempted that name EVERYWHERE -- so a new, wrong,
# present-tense citation in another file passed silently. Proven by putting one
# into `report.py` and watching the check stay green. An exemption that travels
# beyond the passage that earned it is a hole, not an exemption.
_DELETED_ON_PURPOSE = {
    "sentinel.py": (
        {"docs/findings.md", "tests/test_readme_describes_the_tool.py",
         "tests/test_docs_and_scripts_name_real_files.py"},
        "deleted with the gap-scan removal; the original instance of this failure"),
    "report_detections.py": (
        {"docs/findings.md", "tests/test_docs_and_scripts_name_real_files.py",
         "tests/test_report_theme.py"},
        "folded into report.py when the Content Hub section moved"),
    "recommend.py": (
        {"src/pylon/inventory.py", "docs/findings.md"},
        "the Content Hub document envelope, absorbed into the Recommendations "
        "model in 1.0.0; inventory.py names it where it explains the absence"),
    "analysis.py": (
        {"tests/test_docs_and_scripts_name_real_files.py"},
        "the dict-shaping function analysis_model.py replaced"),
    "style.py": (
        {"tests/test_docs_and_scripts_name_real_files.py"},
        "an earlier extraction out of diagnostics.py"),
    "prove.py": (
        {"tests/test_validate.py"},
        "renamed to validate.py; test_validate.py opens by saying so"),
    "services.py": (
        {"tests/test_reachable_from_the_cli.py"},
        "shadowed the day services/ was added -- the silent deletion that "
        "test_reachable_from_the_cli.py exists to prevent"),
    "_checkpoint.py": (
        {"src/pylon/engine.py", "tests/test_checkpoints_are_utf8.py",
         "tests/test_docs_and_scripts_name_real_files.py"},
        "agent_framework's own file, not ours; engine.py patches its encoding"),
}

# Illustrative stand-ins in test prose, never a claim that the file exists.
_ILLUSTRATIVE = {"foo.py", "bar.py", "baz.py"}


def _may_cite(name: str, rel: str) -> bool:
    entry = _DELETED_ON_PURPOSE.get(name)
    return entry is not None and rel in entry[0]


def _code_files():
    for folder in ("src", "tests", "scripts"):
        base = ROOT / folder
        if base.is_dir():
            yield from sorted(base.rglob("*.py"))


def _module_names(text: str) -> set[str]:
    return set(_MODULE.findall(text))


def _exists(name: str) -> bool:
    if (ROOT / name).is_file():
        return True
    return any(any((ROOT / d).rglob(name)) for d in _SOURCE_DIRS)


@pytest.mark.parametrize("path", list(_sources()),
                         ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_module_this_file_names_exists(path):
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(ROOT).as_posix()
    missing = sorted(
        name for name in _module_names(text)
        if not _exists(name) and not _may_cite(name, rel)
    )
    assert missing == [], (
        f"{path.parent.name}/{path.name} cites modules that are not in the "
        f"tree: {missing}. If the entry is ABOUT the deletion, add the name to "
        f"_DELETED_ON_PURPOSE with the reason; otherwise fix the citation."
    )


def test_the_deleted_list_holds_no_module_that_came_back():
    """The other direction. A name readmitted to the tree must leave this list,
    or it exempts a live module from the check for ever."""
    returned = sorted(n for n in _DELETED_ON_PURPOSE if _exists(n))
    assert returned == [], (
        "these are on _DELETED_ON_PURPOSE and exist again, so they are now "
        f"exempt from a check that would pass anyway: {returned}"
    )


# Both checks below are about THIS repo's working list, and every module citation
# in `docs/` currently lives in `docs/findings.md` -- which is on
# `release-excludes.txt` and is not shipped. Written without the guard, they went
# red on a clean clone of the release: 28 citations here, 0 there.
#
# That is the failure `release-excludes.txt`'s own header describes, and
# `test_the_release_script_gate_actually_exists` above already handles it the
# same way. A fork has no findings list, and a check about one must not fail
# there.
def _citation_source_is_shipped() -> bool:
    return (ROOT / "docs" / "findings.md").is_file()


def test_the_deleted_list_is_actually_cited():
    """An entry nobody cites is a stale exemption. It costs nothing to carry and
    that is the problem: it never fails, so it never gets removed."""
    if not _citation_source_is_shipped():
        pytest.skip("docs/findings.md is not shipped in a release tree")
    cited: set[str] = set()
    # Docs AND code: the list covers both now, so a name cited only from a
    # docstring must still count as cited.
    for path in list(_sources()) + list(_code_files()):
        cited |= _module_names(path.read_text(encoding="utf-8"))
    unused = sorted(set(_DELETED_ON_PURPOSE) - cited)
    assert unused == [], (
        "on _DELETED_ON_PURPOSE and cited by no doc or script — remove them: "
        f"{unused}"
    )


def test_there_are_module_citations_to_check():
    """A parametrised check over prose that cites nothing passes by saying
    nothing. `docs/findings.md` alone carries about 28 of these."""
    if not _citation_source_is_shipped():
        pytest.skip("docs/findings.md is not shipped in a release tree")
    total = sum(len(_module_names(p.read_text(encoding="utf-8"))) for p in _sources())
    assert total >= 10, f"found only {total} module citations across docs/ and scripts/"

# ── the same rule, pointed at code comments ──────────────────────────────────
# The checks above read `docs/` and `scripts/`. A docstring is prose too, and it
# rots the same way: `report.py` and `report_design.py` both described
# `report_detections.py` in the PRESENT TENSE months after it was folded into
# `report.py`, `analysis_model.py` opened by describing what `analysis.py` does,
# and `text.py` drew an analogy to a `style.py` that is not in the tree. Four
# modules sending a reader to a file that is not there, none of them caught,
# because prose in code was checked by nothing.



@pytest.mark.parametrize("path", list(_code_files()),
                         ids=lambda p: str(p.relative_to(ROOT)))
def test_every_module_a_comment_names_exists(path):
    """A docstring that cites a module is a promise the module is there."""
    rel = path.relative_to(ROOT).as_posix()
    text = path.read_text(encoding="utf-8")
    missing = sorted(
        name for name in _module_names(text)
        if not _exists(name) and not _may_cite(name, rel)
        and name not in _ILLUSTRATIVE
    )
    assert missing == [], (
        f"{path.relative_to(ROOT)} cites modules that are not in the tree: "
        f"{missing}. Rewrite the sentence so it reads as history, or add the "
        f"name to _DELETED_ON_PURPOSE, scoped to this file, with the reason."
    )


def test_there_are_code_files_to_check():
    assert len(list(_code_files())) > 50
