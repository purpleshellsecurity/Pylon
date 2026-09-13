"""The Entra audit activity vocabulary — what AuditLogs.OperationName can be.

Every Entra detection filters on `OperationName`, and until this existed that
field was the one surface in the tool with neither half of the pattern
everything else uses: nothing put the real vocabulary in front of the model, and
nothing checked what came back. ARM operations are grounded and checked.
Data-plane operations are grounded and checked. Techniques got both today. Entra
had neither, while `docs/grounding-sources.md` listed the reference as a source
the tool already used.

The evidence it mattered: an Entra run produced ten detections, seven of them
T1098.003, every OperationName recalled — and the eval reported "operation
warnings: 0" for that target, which reads as clean and meant the check never ran.

Two lookups, and the difference between them is the same honesty argument the
technique index makes:

    activities_for(service)   the vocabulary a prompt should offer
    is_known(activity)        whether a generated value appears anywhere

`is_known` returning False is a strong hallucination signal, NOT proof: Entra
ships new activities continuously and the snapshot is deliberate rather than
live. Callers warn; nothing here may reject a detection.
"""

from __future__ import annotations

import gzip
import json
from functools import lru_cache
from importlib import resources

_FILE = "entra-audit-activities.json.gz"


@lru_cache(maxsize=1)
def _data() -> dict:
    try:
        raw = (resources.files("pylon.catalog") / _FILE).read_bytes()
    except (FileNotFoundError, OSError):
        return {}
    try:
        return json.loads(gzip.decompress(raw))
    except (OSError, ValueError):
        return {}


# Entra writes activity names with typographic characters and the reference page
# transcribes them with ASCII ones. Measured on a live tenant: the directory
# emits
#     'Update application \u2013 Certificates and secrets management '
# -- EN DASH, and a trailing space -- where the catalogue holds
#     'Update application - Certificates and secrets management'
# A detection built from the catalogue entry filters with `=~`, which forgives
# case and nothing else, so it runs and matches zero events forever. That is
# credential management on an application, which is among the operations most
# worth seeing.
#
# Folding case alone is not enough, and patching the two names we have evidence
# for would leave the next typographic name to fail the same way.
_DASHES = str.maketrans({"\u2013": "-", "\u2014": "-", "\u2212": "-",
                         "\u2018": "'", "\u2019": "'",
                         "\u201c": '"', "\u201d": '"'})


def normalise(activity: str) -> str:
    """An activity name reduced to what two spellings of it have in common.

    Case, outer whitespace, runs of inner whitespace, and the typographic
    punctuation Microsoft's own pages and its own logs disagree about.
    """
    folded = (activity or "").translate(_DASHES).casefold().strip()
    return " ".join(folded.split())


@lru_cache(maxsize=1)
def _by_activity() -> dict[str, str]:
    """activity (normalised) -> the service that writes it."""
    out: dict[str, str] = {}
    for service, activities in (_data().get("activities") or {}).items():
        for activity in activities:
            out.setdefault(normalise(activity), service)
    return out


def categories() -> tuple[str, ...]:
    """Every Category value in the catalog.

    Named for the column that holds these strings. The reference's own column
    header is "Audit Category", and a row carrying "RoleManagement" carries it in
    `Category` -- `LoggedByService` on the same row says "Core Directory".
    Calling them services is what put the wrong column in the prompt.
    """
    return tuple(sorted(_data().get("activities") or {}))


def activities_for(category: str) -> tuple[str, ...]:
    """The documented activities in one Category, or () if unknown."""
    block = (_data().get("activities") or {}).get(category)
    return tuple(sorted(block)) if block else ()


def is_known(activity: str) -> bool:
    """Whether `activity` appears anywhere in the catalog.

    False means "not in this snapshot", never "not real" — Entra adds activities
    continuously, so a caller may warn and must not reject.
    """
    return bool(activity) and normalise(activity) in _by_activity()


def category_for(activity: str) -> str:
    """The Category `activity` belongs to, or "" when unknown. Useful for a
    detection's Category filter, which narrows a very broad table."""
    return _by_activity().get(normalise(activity), "")


def describe(activity: str) -> str:
    """The documented description, where the reference gives one."""
    category = category_for(activity)
    if not category:
        return ""
    for name, description in (_data()["activities"][category]).items():
        if normalise(name) == normalise(activity):
            return description
    return ""


# There is deliberately no "security-relevant services" list here.
#
# There was one: ten of the reference's forty-eight, chosen by me. It had no
# basis — no citation, no rule, just taste — and a test caught that one of the
# ten was a service I had invented outright. Asked how the ten were decided, the
# honest answer was that they were not.
#
# It existed to control cost, and that problem is now solved somewhere else: the
# block is injected into the threat phase only, where the operation is chosen,
# rather than into every detection call. That took the full vocabulary from
# ~170,000 tokens a run to ~10,600 — once, against a run that already spends
# ~44,000 on input. A few cents.
#
# So the whole reference goes in. Nothing is silently excluded on a judgement
# about what counts as security-relevant, and a detection for an unusual service
# — Lifecycle Workflows, Entitlement Management, Global Secure Access — is not
# structurally impossible because of a list somebody typed. If completeness ever
# measurably hurts generation quality, narrow it THEN, with the eval showing it.


def render_for_prompt(categories_wanted: tuple[str, ...] = (), per_category: int = 1000) -> str:
    """The vocabulary as a prompt block, grouped by Category.

    Grouped rather than flattened because `Category` is a real column: a
    detection that filters on it narrows a table carrying every directory event
    in the tenant, and the grouping is what makes that filter obvious.

    It said `LoggedByService` here for twelve releases, and taught the model to
    write a filter that can never match. Both columns exist, so the query parsed,
    validated, deployed and returned clean for ever. Measured on a live tenant:
    one row carried Category="ApplicationManagement" and LoggedByService="Core
    Directory". The grounding block was teaching the mistake the table asset and
    the KQL validator both existed to catch.

    Capped per category and SAYS when it caps. Silent truncation would read as a
    complete vocabulary, which is exactly the failure this block exists to fix.
    """
    available = categories_wanted or categories()
    lines: list[str] = []
    for category in available:
        activities = activities_for(category)
        if not activities:
            continue
        shown = activities[:per_category]
        lines.append(f"  Category =~ \"{category}\"")
        lines.append("    " + " · ".join(shown))
        if len(activities) > per_category:
            lines.append(f"    (+{len(activities) - per_category} more in this category)")
    if not lines:
        return ""
    return (
        "Documented AuditLogs OperationName values, grouped by the Category column "
        "that carries them. Use one of these strings verbatim. If the behaviour you "
        "want is not listed, say so in the rationale rather than inventing a value: "
        "a query filtering on an OperationName that does not exist parses cleanly "
        "and never fires.\n"
        "Match OperationName with =~ and never with ==. These are the names "
        "Microsoft DOCUMENTS, and a tenant writes them in a different case: the "
        "reference says \"Delete Conditional Access policy\" and the tenant logged "
        "\"Delete conditional access policy\". == is case-sensitive in KQL.\n"
        "To narrow the table, filter Category — NOT LoggedByService. Both columns "
        "exist and they hold different things: the row above carries "
        "Category \"RoleManagement\" and LoggedByService \"Core Directory\", so a "
        "LoggedByService filter using a name from this block matches nothing at "
        "all.\n\n" + "\n".join(lines)
    )
