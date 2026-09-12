"""Check the fenced code blocks in a generated Phase 3 IR playbook.

Phase 2 validates every detection and retries once on failure. Phase 3 returned
the model's text unchecked — and a playbook carries 6-10 KQL queries and 3
PowerShell blocks that a responder copy-pastes at 3am, when nobody is going to
notice that a `let` shadows the column it is compared against.

The defects this exists to catch are not hypothetical. All of these shipped:

  * `let CorrelationId = "..."; ... | where CorrelationId == CorrelationId` —
    a tautology that returns the entire retention window.
  * `Connect-AzAccount` followed by `Get-MgUser` — Graph cmdlets on an Azure
    connection, which cannot authenticate.
  * `\\$(\\$_.Exception.Message)` — a TypeScript escape left in PowerShell, so
    the error handler failed exactly when containment failed.
  * `Invoke-MgInvalidateServicePrincipalRefreshToken` — a cmdlet that does not
    exist in any Graph module.

Reuses the Phase 2 validators rather than growing a second opinion: `validate_kql`
for the queries, `script_check.parse_check` for the PowerShell (which resolves
cmdlets and parameters against the installed modules, so it catches the last two).

Degrades the same way those do. No `pwsh` means the PowerShell tier is skipped and
recorded as unchecked, never as passed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_FENCE = re.compile(r"```(kql|kusto|powershell|pwsh)\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
# `let X = ...` compared against a column of the same name is always true. The
# name shadows the column, so the predicate cannot filter anything.
_SHADOW = re.compile(r"let\s+(\w+)\s*=.*?\|\s*where\s+\1\s*==\s*\1\b", re.DOTALL)
# A literal backslash before $ in PowerShell — a TypeScript template-literal
# escape that survived the port. It PARSES, so script_check's tiers do not see
# it, and tier 3 skips it specifically: `\$_.Exception.Message` has no hyphen, so
# the external-tool exemption (there so `az` and `kubectl` are not flagged) lets
# it through. Measured: pwsh treats it as a command name and fails with "The term
# '\$_.Exception.Message' is not recognized" — inside a catch block, so the error
# handler breaks exactly when containment has already failed.
_PS_ESCAPE = re.compile(r"\\\$")


@dataclass
class PlaybookCheck:
    """What the fenced blocks in one playbook were found to contain."""

    kql_blocks: int = 0
    powershell_blocks: int = 0
    errors: list[str] = field(default_factory=list)
    # Checks that could not run — no pwsh, say. Never folded into a pass.
    unchecked: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return bool(self.errors)


def blocks(markdown: str) -> list[tuple[str, str]]:
    """[(language, body)] for every fenced kql/powershell block, in order."""
    out = []
    for lang, body in _FENCE.findall(markdown or ""):
        lang = lang.lower()
        out.append(("kql" if lang in ("kql", "kusto") else "powershell", body))
    return out



def unfenced_kql(markdown: str) -> bool:
    """True when the text carries KQL that is NOT inside a fence.

    A playbook whose queries are bare indented text passes every check by
    default: `blocks()` finds nothing, the loop never runs, and zero errors reads
    as a clean file. Measured on a real SecretPurge playbook -- fourteen queries,
    none fenced, zero errors, every validator bypassed.

    Detects a known table name at the start of a line followed by a KQL pipe
    operator within the next few lines, with fenced regions removed first so a
    correctly fenced playbook never matches.
    """
    from .schemas import TABLE_SCHEMAS

    outside = _FENCE.sub("", markdown or "")
    lines = outside.splitlines()
    for i, line in enumerate(lines):
        if line.strip().rstrip(";") not in TABLE_SCHEMAS:
            continue
        for nxt in lines[i + 1 : i + 6]:
            if re.match(r"\s*\|\s*(where|project|summarize|extend|order|take|top)\b",
                        nxt):
                return True
    return False


_KQL_PIPE = re.compile(r"^\s*\|\s*[a-z][\w-]*\b")
# `let X = X;` is a cycle. Kusto rejects it, so the query never runs -- and it
# appears when a model tries to carry a value from one block into the next,
# where lets do not reach. Measured: seven pivot queries in one playbook.
_SELF_LET = re.compile(r"^[ \t]*let\s+(\w+)\s*=\s*\1\s*;?[ \t]*$", re.M)
_LET_DEF = re.compile(r"^[ \t]*let\s+(\w+)\s*=", re.M)
# ago(name) where `name` is an identifier rather than a timespan literal. It has
# to be a let in the SAME block; a let in an earlier block is out of scope.
_AGO_NAME = re.compile(r"\bago\s*\(\s*([A-Za-z_]\w*)\s*\)")
# A bare identifier on the right of a comparison. Not followed by "(", so a
# function call is not mistaken for a name.
_COMPARED = re.compile(r"(?:==|=~|!=|!~|<=|>=|<|>)\s*([A-Za-z_]\w*)\b(?!\s*\()")
# Names a query introduces for itself, so they are not reported as undefined.
_ALIAS = re.compile(r"(?:\bextend\s+|\bproject\s+|\bsummarize\s+|,\s*)"
                    r"([A-Za-z_]\w*)\s*=(?!=|~)")
_BY_ALIAS = re.compile(r"\bby\s+([A-Za-z_]\w*)\s*=(?!=|~)")
# KQL's own words. `true`/`false`/`null` and the scalar type names read as bare
# identifiers to the pattern above and are not names anyone has to define.
_KQL_WORDS = frozenset("""true false null dynamic datetime timespan int long real
string bool guid decimal now ago todynamic tostring toint tolong toreal tobool
""".split())


def _known_names(body: str, table: str, prelude: frozenset[str] = frozenset()) -> set[str]:
    """Every name a query may legitimately reference: the table's real columns,
    everything the query defines for itself, and the playbook's own prelude.

    `prelude` matters. The skeleton deliberately opens with a "Fill these in
    first" block so a responder sets AlertTime and AlertActor once at 3am instead
    of pasting them into eight separate `let` statements, and every query below
    reads them. A check that did not know about that block reported the skeleton
    itself as broken -- caught by `test_the_data_plane_skeleton_passes_its_own_checker`
    on the first run, which is the whole reason that test exists.

    What still fails is a name defined NOWHERE in the document. That is a real
    fault, and it is the one worth catching.
    """
    from .schemas import TABLE_SCHEMAS

    names = set(TABLE_SCHEMAS.get(table, ()))
    names |= set(_LET_DEF.findall(body))
    names |= set(_ALIAS.findall(body))
    names |= set(_BY_ALIAS.findall(body))
    return names | set(prelude)


def _opens_a_query(line: str, tables) -> bool:
    """A line that starts a query: a bare table name, or `let X = <Table>`."""
    bare = line.strip().rstrip(";").strip()
    if bare in tables:
        return True
    m = re.match(r"^\s*let\s+\w+\s*=\s*([A-Za-z_]\w*)\s*;?\s*$", line)
    return bool(m and m.group(1) in tables)


def fence_bare_kql(markdown: str) -> str:
    """Wrap unfenced KQL in ```kql fences, leaving fenced text untouched.

    Asking the model produced two runs in a row with fourteen bare queries each.
    A rule it can ignore is not a rule, and the cost is not cosmetic: an unfenced
    query is never validated, so a broken `let` reaches the responder unexamined.
    Doing it here makes the fence a property of the output rather than a request,
    and the real checks then run on queries that were previously invisible.

    Conservative by construction. It only fences a run of lines that OPENS on a
    table name (bare, or `let X = <Table>`) and contains a KQL pipe operator, and
    it starts the fence at that opening line, so prose above a query stays prose.
    """
    from .schemas import TABLE_SCHEMAS

    if not markdown:
        return markdown
    tables = set(TABLE_SCHEMAS)
    # Split on fences so already-fenced regions pass through verbatim.
    parts = re.split(r"(```.*?```)", markdown, flags=re.DOTALL)
    out = []
    for i, part in enumerate(parts):
        if i % 2:                       # the captured fenced region
            out.append(part)
            continue
        out.append(_fence_plain(part, tables))
    return "".join(out)


def _fence_plain(text: str, tables) -> str:
    """Fence every query inside one unfenced stretch of markdown."""
    lines = text.splitlines(keepends=True)
    result: list[str] = []
    i = 0
    while i < len(lines):
        if not _opens_a_query(lines[i], tables):
            result.append(lines[i])
            i += 1
            continue
        # Walk BACK over contiguous `let` lines: they belong to this query, and
        # leaving them outside the fence hides exactly the faults worth catching
        # (a self-referencing let sat one line above the table name, unfenced and
        # therefore unchecked). Never crosses a blank line or the previous fence.
        start = i
        while start > 0 and re.match(r"^[ \t]*let\s+\w+\s*=", lines[start - 1]):
            start -= 1
        # Run forward to the next blank line. A query ends at a paragraph break.
        j = i
        while j < len(lines) and lines[j].strip():
            j += 1
        # Anything reclaimed above was already appended; take it back.
        for _ in range(i - start):
            result.pop()
        run = lines[start:j]
        if not any(_KQL_PIPE.match(ln) for ln in run):
            result.extend(run)          # a table name in prose, not a query
            i = j
            continue
        body = "".join(run)
        if not body.endswith("\n"):
            body += "\n"
        result.append("```kql\n" + body + "```\n")
        i = j
    return "".join(result)


def _block_table(body: str, default: str) -> str:
    """The table a KQL block actually runs against.

    A playbook's PRIMARY queries use the detection's table; its Cross-Log Pivots
    deliberately do not. Validating a pivot against the detection's schema reports
    every column of the pivoted table as fabricated. `tests/test_column_names_are_real`
    has always resolved this by reading the table the block opens on; this is the
    same rule, applied where it actually costs a retry.

    The detection's own table wins whenever it appears, so a join that mentions
    another table is still judged against the one it runs on.
    """
    import re

    from .schemas import TABLE_SCHEMAS

    at_start = {
        name
        for name in TABLE_SCHEMAS
        if re.search(rf"^\s*{re.escape(name)}\b", body, re.MULTILINE)
    }
    if not at_start or default in at_start:
        return default
    return min(at_start)


def check_playbook(markdown: str, table: str) -> PlaybookCheck:
    """Validate a playbook's KQL and PowerShell blocks.

    `table` is the detection's log table, so KQL is validated against the schema
    it will actually run on. A playbook query legitimately references OTHER
    tables (the cross-log pivots), so a table mismatch is not treated as an
    error here — only genuine schema and structural faults are.
    """
    from .script_check import parse_check
    from .validate_kql import validate_kql

    result = PlaybookCheck()
    parsed_blocks = blocks(markdown)
    # Names a PRECEDING block defined. Ordering matters: the skeleton's "Fill
    # these in first" block comes before everything that reads it, so scoping to
    # the whole document was close enough -- until the positive control read
    # ContainmentTime from the block BELOW it. That query is the first thing a
    # responder runs and it does not run at all. Document-wide scope passed it.
    prelude: set[str] = set()
    for lang, body in parsed_blocks:
        if lang == "kql":
            result.kql_blocks += 1
            selfref = _SELF_LET.search(body)
            if selfref:
                result.errors.append(
                    f"KQL block: `let {selfref.group(1)} = {selfref.group(1)};` "
                    "refers to itself, so the query does not run. A `let` does "
                    "not carry from one code block to the next — define the "
                    "value in this block, or make the blocks one block."
                )
            defined = set(_LET_DEF.findall(body))
            for name in dict.fromkeys(_AGO_NAME.findall(body)):
                if name not in defined and name not in prelude:
                    result.errors.append(
                        f"KQL block: `ago({name})` uses a name this block never "
                        f"defines, so the query does not run. Either add `let "
                        f"{name} = <timespan>;` here or write the literal."
                    )
            # The same fault in a comparison rather than in ago(). A playbook
            # that sets ActorId in one block and compares against it in the next
            # six does not run any of the six -- `let` does not reach across a
            # code block, and every one of those queries looks correct.
            known = _known_names(body, _block_table(body, table), prelude)
            for name in dict.fromkeys(_COMPARED.findall(body)):
                if name in known or name in _KQL_WORDS or name in defined:
                    continue
                result.errors.append(
                    f"KQL block: compares against `{name}`, which is neither a "
                    f"column of this table nor defined here or in any block "
                    f"above. The query does not run."
                )
            prelude |= set(_LET_DEF.findall(body))
            if _SHADOW.search(body):
                result.errors.append(
                    "KQL block: a `let` variable shadows the column it is compared "
                    "against, so the predicate is always true and the query scans "
                    "the whole retention window. Rename the variable."
                )
            # Validate against the table this BLOCK opens on, not the detection's.
            # The Cross-Log Pivots section exists to query other tables, and
            # `InitiatedBy` is a real AuditLogs column that does not exist on
            # AzureActivity — so a correct pivot was reported as a phantom column,
            # burned a corrective retry, and warned the operator about KQL that was
            # right. Filtering on "does not query" did not catch it because the
            # error says "does not exist".
            # A playbook is a runbook the responder completes at the console, and
            # the Phase 3 skeleton hands the model the slots to leave open, so the
            # detection-only fill-in rule does not apply here. Said in the call
            # rather than filtered out of the result: a rule that does not apply
            # should not run.
            verdict = validate_kql(
                body, _block_table(body, table), allow_placeholders=True
            )
            # Only real faults. A pivot query naming another table is expected.
            result.errors.extend(
                e for e in verdict.errors if "does not query" not in e.lower()
            )
        else:
            result.powershell_blocks += 1
            if _PS_ESCAPE.search(body):
                result.errors.append(
                    r"PowerShell block: `\$` is not an escape in PowerShell. "
                    r"`\$($_.Exception.Message)` is parsed as a command name and "
                    "fails at run time — in a catch block, so the error handler "
                    "breaks precisely when the thing it reports on has failed. "
                    "Use `$($_.Exception.Message)`."
                )
            # Only after this block has been judged: a block cannot define a
            # name for itself by using it.
            prelude |= set(_LET_DEF.findall(body))
            parsed = parse_check(body, "powershell")
            if not parsed.ran:
                result.unchecked.append("PowerShell blocks: pwsh is not installed")
            else:
                result.errors.extend(parsed.errors)
                result.unchecked.extend(parsed.unchecked)

    # Nothing to validate is not the same as nothing wrong. Every playbook the
    # skeleton asks for carries queries, so zero KQL blocks means either the
    # model wrote them unfenced -- where no checker can reach them -- or it wrote
    # none at all. Both are failures, and both used to report clean.
    if result.kql_blocks == 0:
        if unfenced_kql(markdown):
            result.errors.append(
                "Playbook: the KQL is not inside fenced code blocks, so none of "
                "it was validated. Wrap every query in a ```kql fence. Bare "
                "indented queries are invisible to the checker and cannot be "
                "copied cleanly at a console."
            )
        else:
            result.errors.append(
                "Playbook: no KQL query blocks found. A playbook without queries "
                "gives a responder nothing to run. Every query goes in a ```kql "
                "fence."
            )
    return result
