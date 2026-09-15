"""What to turn on in Content Hub — a SEPARATE document from the analysis.

This used to rank Microsoft's rule templates: one row per template whose tables
held data. That produced 119 rows in this tenant, of which 45 presumed a
workload it does not run, because table names are shared and `Event` holding
963 MB from one Windows host passes every domain-controller template. Filtering
on the connector each template DECLARES cut it to 72, which was more honest and
still not a decision: 72 templates covering 37 techniques is a catalogue, not a
queue.

So the unit is the solution now, and `contenthub.py` measures it. The document
this file produces is the same shape as before -- separate from the analysis,
carrying the analysis timestamp so drift is visible -- and it costs nothing,
which is why the cost fields are all real zeros rather than unreported figures.
"""

from __future__ import annotations

from datetime import datetime

SCHEMA_VERSION = 2


def build(solutions: list[dict], workspace: str,
          analysis_generated_at: datetime) -> dict:
    """A `Recommendations` document, as a dict ready for the model."""
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(analysis_generated_at.tzinfo),
        "workspace": workspace,
        "analysis_generated_at": analysis_generated_at,
        "solutions": solutions,
        # Measured, not generated: this document cost nothing to produce, and a
        # zero here is a real zero rather than an unreported figure.
        "cost_usd": 0.0,
        "model_calls": 0,
        "unreported_calls": 0,
        "cost_is_partial": False,
    }
