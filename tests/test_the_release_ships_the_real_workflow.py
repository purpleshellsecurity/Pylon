"""The released CI must be the CI this repo runs, minus the one job a fork
cannot use.

`make-release.sh` used to write the public `ci.yml` from a heredoc -- a whole
second copy of the workflow, maintained by hand. It went stale exactly as a
second copy of anything does: the dev workflow grew a 3x3 OS/Python matrix and
an install job, the heredoc did not, and the public repo shipped a single-cell
CI with a CHANGELOG beside it describing a matrix. A reviewer reading the
release reasonably concluded the matrix had never been committed. It had; the
release step was dropping it.

That is the THIRD thing this release step silently dropped -- LICENSE, the
workflow, and docs/first-release-checklist.md -- all for the same reason: an
explicit list, or a retyped copy, that nobody updated. These tests hold the
release to the source rather than to a second author.
"""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "make-release.sh"


def _script() -> str:
    if not SCRIPT.is_file():
        pytest.skip("make-release.sh is not shipped in a release tree")
    return SCRIPT.read_text(encoding="utf-8")


def test_the_workflow_is_derived_not_retyped():
    """No heredoc containing a workflow. If `name: CI` appears in the release
    script as literal text, somebody has started keeping a second copy again."""
    body = _script()
    assert "cat > \"$DEST/.github/workflows/ci.yml\"" not in body, (
        "the release writes a workflow from a heredoc; it drifted from the real "
        "one once already")
    assert ".github/workflows/ci.yml" in body, "the release ships no workflow"


def test_the_derivation_keeps_the_matrix_and_drops_only_the_self_hosted_job():
    """Asserted inside the release script itself, so a broken derivation fails
    the build rather than shipping. This checks those assertions exist -- a
    guard that can be deleted without a test noticing is not a guard."""
    body = _script()
    assert "the matrix did not survive into the release" in body
    assert "a self-hosted job survived into the release" in body


def test_the_self_hosted_check_looks_at_runs_on_not_at_the_word():
    """The tests job's comment explains WHY it is hosted rather than
    self-hosted, and that sentence is worth shipping. An earlier version of the
    guard banned the word and failed on its own explanation."""
    body = _script()
    assert 'ln.strip().startswith("runs-on:")' in body, (
        "the guard bans the word rather than the setting")


# NOT here: docs/first-release-checklist.md. It is THIS repo's ship/no-ship
# gate and cites release-run.sh, which is not shipped -- so shipping it put a
# dangling reference in the public tree and turned pytest red on a clean clone.
# A fork has nothing to release.
@pytest.mark.parametrize("required", [
    "LICENSE",                          # nobody can use it without one
    "SECURITY.md",                      # where to report a vulnerability
    "CHANGELOG.md",                     # what changed
])
def test_the_archive_list_carries_what_a_reader_needs(required):
    """The list is explicit, which is why it keeps losing things. Each entry
    here is one a release went out without, or nearly did."""
    body = _script()
    archive = body[body.index("git archive HEAD"):]
    archive = archive[:archive.index("| tar")]
    assert required in archive, (
        f"make-release.sh does not archive {required}, so the public repo ships "
        f"without it")


def test_the_leak_scan_also_checks_the_setting_not_the_word():
    """The release script's own scan made the same mistake, and it cost a
    publish: it grepped for "self-hosted" anywhere in the tree and refused over
    the tests job's comment explaining why it is HOSTED rather than self-hosted,
    plus this file's assertions about the rule.

    Prose about a rule is not a breach of it. Twice in one file is a pattern, so
    both checks look at `runs-on:`.
    """
    body = _script()
    assert 'runs-on:.*self-hosted' in body, (
        "the leak scan bans the word rather than the configured runner")
    assert 'grep -rn "self-hosted" "$DEST"' not in body, (
        "the bare-word scan is back; it refuses to publish over its own "
        "documentation")
