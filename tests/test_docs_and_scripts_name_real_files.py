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
