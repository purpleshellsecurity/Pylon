"""What produced this artefact, stamped into the artefact.

A run writes a plan, then detections, then playbooks, then verification results,
as four files with no shared key. The only link between a plan's vector and the
detection built from it is a human-readable name the model is free to rewrite --
and it does: a plan asked for `SecretDelete (delete secret)` and the detection
came back `SecretDelete (Key Vault secret deletion)`, which broke the lookup that
finds ground truth.

Nothing in any artefact says which build wrote it, when, against which model, or
as part of which run. Two SecretPurge detections were compared today and the only
way to tell them apart was which directory they sat in.

So every artefact carries a Provenance: a run id shared by everything one
invocation produced, and the facts needed to reproduce or discount it. The run id
is the join key the vector name could not be, because nothing downstream is free
to rewrite it.
"""

from __future__ import annotations

import os
import platform
import uuid
from datetime import datetime, timezone

from .analysis_model import Strict

# One id per process, minted on first use. A run is one invocation of the CLI,
# so everything it writes shares this -- plan, detections, playbooks, verdicts.
_RUN_ID: str | None = None


def run_id() -> str:
    """The id for this run, stable for the life of the process.

    PYLON_RUN_ID overrides it so a shell script driving several commands can
    stamp them all as one logical run, which is how the three-command pipeline
    is actually used.
    """
    global _RUN_ID
    if _RUN_ID is None:
        _RUN_ID = os.environ.get("PYLON_RUN_ID") or uuid.uuid4().hex[:16]
    return _RUN_ID


class Provenance(Strict):
    """Which build, which model, which moment, which run."""

    run_id: str
    pylon_version: str
    generated_at: str            # ISO 8601, UTC, because runs cross machines
    provider: str = ""           # azure-openai | openai | anthropic
    model: str = ""
    host: str = ""
    command: str = ""            # the verb that wrote this, e.g. "design plan"


def stamp(command: str = "", provider: str = "", model: str = "") -> Provenance:
    """The provenance for something written right now by this process."""
    from . import __version__

    return Provenance(
        run_id=run_id(),
        pylon_version=__version__,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        # Same default `make_chat_client` uses, so an unset variable records the
        # provider that actually ran rather than a blank.
        provider=provider or os.environ.get("PYLON_PROVIDER", "openai").lower(),
        model=model or os.environ.get("OPENAI_CHAT_MODEL", ""),
        host=platform.node(),
        command=command,
    )
