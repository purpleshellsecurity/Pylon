"""Agentic detection engineering for Azure on Microsoft Agent Framework.

A port of adversary-lab-pylon's pipeline — threat analysis →
KQL detections → IR playbook — with the phases restructured as a workflow:
structured Phase 1 output, per-vector fan-out in Phase 2 with validator-driven
self-correction, and a human-in-the-loop playbook target pick before Phase 3.
"""

import warnings

# The functional-workflows API (@step / workflow) is marked experimental by
# agent_framework and emits an ExperimentalWarning at import/decoration time —
# it works fine and we depend on it deliberately. Silence just that one message
# here in the package __init__ so it is installed before .engine is imported
# (and applies to the CLI, tests, and library use alike).
warnings.filterwarnings("ignore", message=r".*FUNCTIONAL_WORKFLOWS.*")

def _installed_version() -> str:
    """The version from package metadata, which is built from pyproject.toml.

    This was a second hardcoded literal and it said 0.1.0 while pyproject said
    0.3.0 -- two minor versions stale, because nothing updates a number that
    nothing reads. `pylon --version` was right only because it went to the
    metadata directly and ignored this.

    One literal, in pyproject.toml. Everything else derives. A source tree with
    nothing installed says so rather than inventing a number, because "which
    build produced this" is the question, and a confident wrong answer is worse
    than an honest unknown.
    """
    try:
        from importlib.metadata import PackageNotFoundError, version
        return version("pylon")
    except PackageNotFoundError:
        return "unknown (not installed)"
    except Exception:                              # noqa: BLE001 - never fatal
        return "unknown"


__version__ = _installed_version()
