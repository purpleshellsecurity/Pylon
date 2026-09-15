"""One version literal, in pyproject.toml. Everything else derives.

`src/pylon/__init__.py` carried a second one. It said 0.1.0 while pyproject
said 0.3.0 -- two minor versions stale, because nothing updates a number that
nothing reads. `pylon --version` was correct only because it went straight to
the package metadata and ignored `__version__` entirely, so the drift was
invisible from the command line and wrong from the library.

"Which build produced this output" is the question the version exists to answer.
A second copy answers it differently.
"""

import re
import tomllib
from pathlib import Path

import pytest

import pylon

ROOT = Path(__file__).resolve().parent.parent
# A release version anywhere in the source: 1.2 or 1.2.3, quoted, on an
# assignment to something version-shaped.
_LITERAL = re.compile(r"""(?:^|\s)(__version__|VERSION|version)\s*=\s*["'](\d+\.\d+(?:\.\d+)?)["']""")


def test_pyproject_is_the_only_place_a_version_is_written():
    offenders = []
    for path in sorted((ROOT / "src").rglob("*.py")):
        for name, number in _LITERAL.findall(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(ROOT)}: {name} = {number!r}")
    assert offenders == [], (
        "a version literal outside pyproject.toml drifts the moment someone "
        "bumps one and not the other: " + "; ".join(offenders))


def test_the_package_reports_what_was_installed():
    """Derived, so a stale install reports the stale number honestly rather
    than a hardcoded one that was never true."""
    assert pylon.__version__, "a version that is empty answers nothing"


@pytest.mark.skipif(not (ROOT / "pyproject.toml").is_file(), reason="no pyproject")
def test_the_installed_version_matches_this_source_tree():
    """Fails on a stale install, which is the condition worth knowing about:
    four playbook runs were once read as evidence about code that was not
    installed, and nothing in the output said so."""
    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    if pylon.__version__.startswith("unknown"):
        pytest.skip("running from a source tree with nothing installed")
    assert pylon.__version__ == declared, (
        f"installed {pylon.__version__}, source tree declares {declared} -- "
        "reinstall before trusting any output this produces")
