"""Assemble the IR playbook in code, and ask the model only for what is left.

Three runs of the same vector produced three structurally different documents.
None used the fourteen sections. The cause was not a weak rule; it was that the
whole document was a REQUEST. Phase 3 handed the model a nearly-complete template
and asked it to "produce exactly the structure below", and a model handed a
document to reproduce rewrites it.

Measured on the rendered data-plane template: 336 lines, 21 bracketed blanks.
Sorted, they are

  9   the RESPONDER fills at 3am from the alert row (AlertTime, AlertActor, the
      correlation id, the containment timestamp). These must survive into the
      output as brackets -- filling them would be inventing alert data.
  6   PYLON ALREADY KNOWS (the detection name, its severity, its technique, its
      false-positive notes, the operation, and the read/write operation lists
      from the data-plane catalogue). Asking for these is how they drift: one
      run re-mapped T1485 to "unmapped (host/endpoint)" against the catalogue
      that maps it to Key Vault purge.
  3   genuinely need a model.

So the model is asked for four fields and Pylon renders the rest. What the
document looks like stops being a thing that can vary.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator


# A sentence ends where a terminator meets whitespace or the end of the string.
# Counting the characters instead -- `sum(v.count(c) for c in ".!?")` -- counts
# the dot in every dotted identifier, and the ARM plane writes them constantly.
# An attack_context naming `Microsoft.Authorization/roleAssignments` twice
# scored five sentences for three and the whole playbook was discarded before it
# ever rendered, on every ARM run, deterministically. No identifier's dot is
# followed by whitespace, so the lookahead is the whole fix.
_TERMINATOR = re.compile(r"[.!?]+(?=\s|$)")


def _sentences(text: str) -> int:
    """How many sentences a one-line string holds."""
    return len(_TERMINATOR.findall(text))

# The blank exactly as it appears in the rendered template -> where it comes
# from. "responder" means it stays a bracket: the value is on the alert row, in
# front of the person reading, and nowhere else.
RESPONDER_BLANKS: tuple[str, ...] = (
    "[FROM ALERT: TimeGenerated]",
    "[FROM ALERT: ActorUpn or ActorId]",
    "[FROM ALERT: ActorUpn]",
    "[FROM ALERT: ActorId]",
    "[FROM ALERT: SrcIp]",
    "[FROM ALERT: TargetResource]",
    "[FROM ALERT: CorrelationId]",
    "[TIME YOU RAN CONTAINMENT]",
    "[the resource from the alert]",
    "[the resource id]",
    "[THE WINDOW THE DETECTION AGGREGATES OVER, e.g. 1h / 24h / 7d]",
    # The cross-log pivots carry their own lets rather than reading the prelude.
    # Deliberate: a pivot is pasted on its own, into a different table's query,
    # often hours later, and a self-contained query survives that.
    "[object ID from the alert]",
    # AzureActivity.Caller holds a UPN for a user and an object id for a service
    # principal, so a pivot over it takes both and matches on whichever the
    # responder has. See pivot._predicate.
    "[actor UPN from the alert]",
    "[resource ID from the alert]",
    "[source IP from the alert]",
)


class PlaybookFill(BaseModel):
    """The only four things a playbook needs a model for.

    Everything else in the document is either a fact Pylon holds or text the
    responder supplies from the alert. Kept this small deliberately: each field
    here is a thing that can come back wrong, and the list is the whole surface.
    """

    what_happened: str = Field(
        description="ONE sentence naming what the actor achieved by this "
                    "operation. Not what the operation is; what it got them."
    )
    attack_context: str = Field(
        description="TWO OR THREE sentences: what the attacker achieved, and why "
                    "it matters on this specific resource. No generic prose."
    )
    why_it_matters: list[str] = Field(
        min_length=2, max_length=4,
        description="Two to four bullets on why this matters for THIS resource. "
                    "One clause each, no leading dash."
    )
    containment_role: str = Field(
        description="The exact Azure RBAC role or access-policy permission that "
                    "grants this operation, as Azure names it (for example "
                    "'Key Vault Secrets Officer'). Removing it is the reversible "
                    "containment step."
    )

    @field_validator("what_happened")
    @classmethod
    def _one_sentence(cls, v: str) -> str:
        # A count in a prompt is a suggestion; a count on a field is a check.
        v = " ".join(v.split())
        if not v:
            raise ValueError("what_happened is empty")
        found = _sentences(v)
        if found > 2:
            raise ValueError(
                f"what_happened must be one sentence, found {found}")
        return v

    @field_validator("attack_context")
    @classmethod
    def _two_or_three_sentences(cls, v: str) -> str:
        v = " ".join(v.split())
        # The prompt asks for two or three; the bound keeps the slack it always
        # had. The message now states the bound it actually enforces -- the old
        # one said "two or three" while accepting one through four, which made a
        # rejection impossible to read against the rule it broke.
        found = _sentences(v)
        if not 1 <= found <= 4:
            raise ValueError(
                "attack_context must be between one and four sentences, "
                f"found {found}")
        return v

    @field_validator("why_it_matters")
    @classmethod
    def _clauses_not_paragraphs(cls, v: list[str]) -> list[str]:
        out = [" ".join(b.split()).lstrip("-• ").strip() for b in v]
        if any(not b for b in out):
            raise ValueError("why_it_matters has an empty bullet")
        if any(len(b.split()) > 30 for b in out):
            raise ValueError("why_it_matters bullets must be one clause each")
        return out

    @field_validator("containment_role")
    @classmethod
    def _a_role_not_a_paragraph(cls, v: str) -> str:
        v = " ".join(v.split()).strip(" .")
        if not v or len(v.split()) > 8:
            raise ValueError("containment_role must be a role name, not prose")
        return v


def operation_lists(table: str) -> tuple[str, str]:
    """(reads, writes) for `table`, as KQL string lists, from the catalogue.

    The template asks the model for "the read operations for this table" inside a
    `has_any (...)`. The catalogue tags every operation with a verb, so this is a
    lookup, not a recall -- and a recalled list is a list of plausible operation
    names, which is the exact failure the operation vocabulary exists to stop.
    """
    from . import data_plane_operations as dp

    block = dp._tables().get(table) or {}
    ops = block.get("operations") or {}
    reads, writes = [], []
    for name, meta in ops.items():
        verb = (meta or {}).get("verb", "")
        if verb in ("read", "list"):
            reads.append(name)
        elif verb in ("write", "delete"):
            writes.append(name)
    fmt = lambda names: ", ".join(f'"{n}"' for n in sorted(names))
    return fmt(reads), fmt(writes)


# The per-table normalisation the data-plane queries open with. The asset used to
# carry BOTH lines with "keep one and delete the other" — a choice the model made
# and Pylon now has to make, because nobody is reading the instruction any more.
# Shipped as-was, a Key Vault playbook read RequesterUpn and StatusCode, which are
# Storage columns: every query in it returned an error instead of rows, and the
# checker passed it because `validate_kql` does not flag a missing column on the
# right of an `extend`.
_NORMALISE: dict[str, dict[str, str]] = {
    "identity": {
        "AZKVAuditLogs": "tostring(Identity.claim.upn)",
        "_storage": "RequesterUpn",
    },
    "actor_id": {
        "AZKVAuditLogs": "tostring(Identity.claim.oid)",
        "_storage": "RequesterObjectId",
    },
    "failure": {
        "AZKVAuditLogs": "HttpStatusCode >= 300",
        "_storage": 'StatusCode != "200"',
    },
    "agent": {
        "AZKVAuditLogs": "ClientInfo",
        "_storage": "UserAgentHeader",
    },
}


def _norm(part: str, table: str) -> str:
    return _NORMALISE[part].get(table) or _NORMALISE[part]["_storage"]


def normalisation(table: str) -> dict[str, str]:
    """The three shapes the data-plane asset asks for, written for `table`."""
    upn, oid = _norm("identity", table), _norm("actor_id", table)
    fail, agent = _norm("failure", table), _norm("agent", table)
    return {
        "__NORMALISE_FULL__": (
            f"| extend ActorUpn = {upn}, ActorId = {oid},\n"
            f"         IsFailure = {fail}, UserAgent = {agent}"),
        "__NORMALISE_ACTOR_FAIL__": f"| extend ActorUpn = {upn}, IsFailure = {fail}",
        "__NORMALISE_ACTOR__": f"| extend ActorUpn = {upn}",
    }


def reverse_sentence(table: str, operation: str) -> str:
    """What undoes this operation, for the responder — or plainly that nothing
    catalogued does.

    The graph asset used to tell the MODEL to "use the grounded containment
    reverse supplied with this prompt", which is an instruction, not a playbook
    step. Pylon holds the reverse, so it writes the sentence.
    """
    from . import operation_grounding

    ref = operation_grounding.reference(table, operation) or {}
    rev = ref.get("reverse") or {}
    name = rev.get("operation") or rev.get("action") or ""
    if name:
        desc = rev.get("description", "")
        return (f"Reverse it with **{name}**"
                + (f" — {desc}" if desc else "")
                + "\nRun it against the same object the alert names.")
    if (ref.get("recovery") or "") == "none":
        return ("This operation destroys permanently. Nothing reverses it, so "
                "containment here means stopping the next one, not undoing this "
                "one.")
    return ("No reverse operation is catalogued for this one. Identify the real "
            "inverse before acting, and record it here — do not guess at a "
            "command under time pressure.")


def facts(target, table: str) -> dict[str, str]:
    """The blanks Pylon can fill from what it already holds.

    Keyed by the blank's literal text in the rendered template, so a template
    edit that renames a blank shows up as an unfilled blank rather than as
    silently missing content.
    """
    reads, writes = operation_lists(table)
    det = target.detection
    return {
        "[Detection name from Phase 2]": det.vector_name,
        "[from Phase 2]": getattr(target, "priority", "") or "unstated",
        "[technique ID and name]": det.mitre_technique,
        "[common false positives]": (
            det.false_positive_notes or "application service accounts, backup jobs, CI/CD"
        ),
        "[the operation from Phase 2]": target.operation or det.vector_name,
        "[the reverse operation]": reverse_sentence(table, target.operation or ""),
        "[the read operations for this table]": reads or '"<no read operations catalogued>"',
        "[the write operations for this table]": writes or '"<no write operations catalogued>"',
    }


def render(template: str, target, table: str, fill: PlaybookFill) -> str:
    """The finished playbook: Pylon's facts, the model's four fields, and every
    responder blank left as a blank."""
    out = template
    for token, value in normalisation(table).items():
        out = out.replace(token, value)
    for blank, value in facts(target, table).items():
        out = out.replace(blank, value)
    for blank, value in (
        ("[1 sentence]", fill.what_happened),
        ("[2–3 sentences: what the attacker achieved, and why it matters here.]",
         fill.attack_context),
        ("[the role that grants this operation]", fill.containment_role),
        ("[why it matters]", "\n".join(f"- {b}" for b in fill.why_it_matters)),
    ):
        out = out.replace(blank, value)
    return out


def unfilled(document: str) -> list[str]:
    """Blanks left in a finished playbook that are NOT the responder's to fill.

    A blank nobody filled is a blank the responder cannot fill either, because
    the template never said where its value comes from. Reported rather than
    shipped.
    """
    import re

    return [
        f"[{m}]"
        for m in dict.fromkeys(re.findall(r"\[([^\]\[\n]{3,120})\]", document))
        # A quoted string in brackets is KQL indexing a dynamic column
        # (Claims["http://schemas..."]), not a blank anyone fills.
        if not m.lstrip().startswith(('"', "'"))
        and f"[{m}]" not in RESPONDER_BLANKS
    ]


FILL_TASK = """## Task: the four fields this playbook needs from you

Pylon assembles the document. It already holds the detection name, its severity,
its MITRE technique, its false-positive notes, the operation, and this table's
read and write operation lists — do not restate any of them, and do not re-map
the technique.

Return exactly these four fields:

- `what_happened` — ONE sentence naming what the actor ACHIEVED by this
  operation. Not what the operation is; what it got them.
- `attack_context` — TWO OR THREE sentences on what the attacker achieved and why
  it matters on this specific resource. Ground it in the operation reference
  supplied above, including whether the operation can be undone.
- `why_it_matters` — two to four bullets on why this matters for THIS resource.
  One clause each.
- `containment_role` — the exact Azure RBAC role or access-policy permission that
  grants this operation, as Azure names it. This is the thing a responder removes
  as the reversible containment step, so it must be a real role name.

Nothing else. No markdown document, no headings, no queries."""


def fill_prompt(playbook_prompt: str) -> str:
    """The Phase 3 prompt, with its "produce this whole document" task swapped for
    the three-field one.

    Everything BEFORE <task> is the grounding — the role, the KQL rules, the table
    schema, the operation vocabulary and the technique reference — and all of it
    still applies to writing three sentences about this operation. Only the task
    changes, so there is one grounding and not a second copy to drift from it.
    """
    head, sep, _rest = playbook_prompt.partition("<task>")
    if not sep:
        return f"{playbook_prompt}\n\n<task>\n{FILL_TASK}\n</task>"
    return f"{head}<task>\n{FILL_TASK}\n</task>"


def pivot_markdown(table: str) -> str:
    """The grounded cross-log pivots as document markdown, or '' when none exist.

    `pivot.render_pivot_block` is written for a prompt: bracketed labels, no
    fences. A responder needs headings and fenced queries, and the checker needs
    the fences to see the KQL at all.
    """
    from . import pivot

    plan = pivot.pivot_plan(table)
    if not plan:
        return ""
    out = []
    for hop in plan:
        out.append(f"**{hop['label']}**\n\n```kql\n{hop['kql'].strip()}\n```")
    return "\n\n".join(out)


def document_template(platform_id: str, service: str, target_label: str) -> str:
    """The playbook as a DOCUMENT: skeleton assembled, prompt-only regions gone,
    every template token substituted, every blank still a blank.

    Same skeleton the prompt uses. `strip_guides` is the only difference, so the
    structure a run produces cannot diverge from the structure the prompt
    describes -- there is nothing to diverge from.
    """
    from .prompts import _TABLE_RULES_KEY, _chain_for, _render, load_asset, render_playbook, strip_guides

    # The TABLE decides the chain. Deriving it from the request handed an
    # AZKVAuditLogs playbook the ARM asset, because the request's platform is not
    # the table's plane -- and the ARM asset's blanks are different ones, so the
    # document shipped with holes nobody could fill.
    chain = _TABLE_RULES_KEY.get(service) or _chain_for(platform_id, service)
    assembled = render_playbook(load_asset(f"{chain}/playbook.md"),
                                pivots=pivot_markdown(service))
    document = _render(
        strip_guides(assembled),
        service=service,
        target=target_label,
        chain=chain,
        platform_id=platform_id,
    )
    # Every asset opens with a <!-- GUIDE --> region, and stripping it leaves the
    # newline that followed. The title landed on line two on all three planes, so
    # a reader opening the file saw a blank before the heading and nothing here
    # asserted otherwise. The document starts at its title.
    return document.lstrip("\n")
