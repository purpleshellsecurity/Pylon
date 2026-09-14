"""The KQL rules as ONE object with two consumers.

`render()` puts a rule in front of the model. `problems()` enforces it. They
read the same list, so a rule cannot reach one without reaching the other --
which is the property the table contracts have and the KQL rules did not.

Before this, the rules lived in two piles that never met: about 68 bullets
across `_KQL_RULES` and `QUERY_RULES` in the prompts, and 43 checks in
`validate_kql`. Nothing said which bullet a check enforced, which bullets were
never enforced, or which check contradicted a bullet. All three were true at
once, and the third one shipped: the exclusion-scaffolding rule was REQUIRED in
four copies of the prompt while `_dead_empty_collections` and
`_unverified_watchlists` rejected both forms of it, so the only output the gates
accepted was one that ignored the prompt. Two generated detections did exactly
that and nothing noticed, because there was no place where the requirement and
the checks could be compared.

The checkers here are deliberately small and regex-based. A real KQL parser is
the correct answer and this is not one; each check errs toward silence rather
than toward a false accusation, because a gate that cries wolf gets a rule
deleted rather than fixed.
"""

from __future__ import annotations

import functools
import re
from importlib import resources
from typing import Callable

_CATALOG = "kql-rules.yaml"

# Ordered worst-first. A caller deciding whether to fail a build reads this, not
# a set of strings it happens to know about.
SEVERITIES = ("blocks-deployment", "error", "warning", "guidance")

# Severities that mean "do not ship this". `warning` is real and does not stop a
# detection; `guidance` has no checker and cannot stop anything.
FATAL = ("blocks-deployment", "error")


@functools.lru_cache(maxsize=1)
def _document() -> dict:
    import yaml

    text = (resources.files("pylon.catalog") / _CATALOG).read_text(encoding="utf-8")
    return yaml.safe_load(text) or {}


def rules() -> list[dict]:
    """Every rule, in file order. File order is the order a reader should meet
    them: blockers, then correctness, then cost, then unchecked prose."""
    return list(_document().get("rules") or [])


def sources() -> dict[str, str]:
    """{short name: the URL a rule cites}. Rendered under the rules so the model
    -- and a human reviewing the prompt -- can see which are Microsoft's words
    and which are this repo's judgement."""
    return dict(_document().get("sources") or {})


def by_id(rule_id: str) -> dict | None:
    return next((r for r in rules() if r.get("id") == rule_id), None)


# ── The checkers ──────────────────────────────────────────────────────────────
#
# One function per `check:` id. A checker returns True when the query BREAKS the
# rule. Registered by name rather than imported by name so a rule naming a
# checker that does not exist is a loud failure in the suite rather than a rule
# that silently enforces nothing.

_CHECKS: dict[str, Callable[[str], bool]] = {}


def _check(name: str):
    def register(fn: Callable[[str], bool]) -> Callable[[str], bool]:
        _CHECKS[name] = fn
        return fn
    return register


def _bare(kql: str) -> str:
    """`kql` with string literals and comments blanked, so a rule never fires on
    a word inside a value. `| where Caller has "contains"` is not a `contains`."""
    from .validate_kql import _blank_strings_and_comments

    return _blank_strings_and_comments(kql)


# A cross-resource query is the ONE union Microsoft still supports in an alert
# rule, because it scopes to named resources rather than scanning tables.
_CROSS_RESOURCE = re.compile(r"\b(?:app|workspace)\s*\(", re.IGNORECASE)


@_check("union_or_search")
def _union_or_search(kql: str) -> bool:
    body = _bare(kql)
    if re.search(r"(?:^|\|)\s*search\b", body, re.IGNORECASE):
        return True
    if not re.search(r"(?:^|\|)\s*union\b", body, re.IGNORECASE):
        return False
    # `union app('...').requests, workspace('...').Perf` is the documented
    # exception and is explicitly still supported.
    return not _CROSS_RESOURCE.search(body)


@_check("trailing_count")
def _trailing_count(kql: str) -> bool:
    """A query whose LAST operator is a bare `count`.

    Not any `count`: `summarize Attempts = count() by Caller` is the normal way
    to write a threshold rule and must stay legal. Only the operator form, at
    the end, where the alerting service's own appended count doubles it.
    """
    body = _bare(kql).strip().rstrip(";").strip()
    return bool(re.search(r"\|\s*count\s*$", body, re.IGNORECASE))


@_check("take_or_limit")
def _take_or_limit(kql: str) -> bool:
    return bool(re.search(r"\|\s*(?:take|limit)\s+\d+", _bare(kql), re.IGNORECASE))


@_check("contains_operator")
def _contains_operator(kql: str) -> bool:
    # `contains_cs` is a different operator and Microsoft's advice about it is
    # the same sentence; the word-boundary keeps this to bare `contains`.
    return bool(re.search(r"\|\s*where\s+[^|]*?\bcontains\b(?!_)", _bare(kql),
                          re.IGNORECASE))


@_check("tolower_equality")
def _tolower_equality(kql: str) -> bool:
    return bool(re.search(r"\b(?:tolower|toupper)\s*\([^)]*\)\s*==", _bare(kql),
                          re.IGNORECASE))


@_check("json_in_where")
def _json_in_where(kql: str) -> bool:
    """parse_json() called inside a `where`, with no term match before it.

    The term match is what makes the pattern cheap, so a query that does filter
    the raw column first is doing exactly what Microsoft asks and must not be
    flagged for then parsing it.
    """
    body = _bare(kql)
    for clause in re.findall(r"\|\s*where\s+([^|]+)", body, re.IGNORECASE):
        if not re.search(r"\bparse_json\s*\(", clause, re.IGNORECASE):
            continue
        column = re.search(r"parse_json\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)", clause,
                           re.IGNORECASE)
        name = column.group(1) if column else ""
        # Was that same column term-matched anywhere earlier in the query?
        before = body[:body.index(clause)] if clause in body else ""
        if name and re.search(rf"\b{re.escape(name)}\s+(?:has|has_cs|contains)\b",
                              before, re.IGNORECASE):
            continue
        return True
    return False


# Columns that hold a NAME rather than an identifier. Matching a substring of
# one of these is matching a naming convention.
_NAME_COLUMNS = (
    "ResourceGroup", "Resource", "ResourceId", "AccountName", "SubscriptionId",
    "ResourceProvider", "AppName", "LogicalServerName_s", "database_name_s",
)


@_check("name_substring_scope")
def _name_substring_scope(kql: str) -> bool:
    """A `where` deciding importance by a substring of a resource NAME.

    The exact shape that matched 0 of 32 real vault deletions: every column real,
    every value a plausible English word, and the whole rule switched off by a
    naming convention that does not exist in the tenant.

    Equality is NOT this. `ResourceGroup == "rg-payments"` names one real group
    and is a legitimate scope; `ResourceGroup has "prod"` is a guess about how
    somebody names things.
    """
    body = _bare(kql)
    names = "|".join(_NAME_COLUMNS)
    return bool(re.search(rf"\b(?:{names})\s+(?:has|has_cs|contains|startswith"
                          rf"|endswith|matches\s+regex)\b", body, re.IGNORECASE))


_CLOUD_PLATFORMS = frozenset({"IaaS", "SaaS", "Identity Provider", "Office Suite"})


@_check("technique_not_cloud_tagged")
def _technique_not_cloud_tagged(technique: str) -> bool:
    """A technique ATT&CK does not tag for any cloud platform.

    Takes the technique id rather than KQL -- `applies_to: detection` with
    `needs: technique` decides what it is handed. Unknown ids pass: an id this
    index has never heard of is a different fault and `mitre.ground` reports it.
    """
    from .. import knowledge

    parts = (technique or "").split()
    entry = knowledge._techniques().get(parts[0].strip()) if parts else None
    if not entry:
        return False
    return not (_CLOUD_PLATFORMS & set(entry.get("platforms") or []))


# ── The two consumers ─────────────────────────────────────────────────────────


def _rendered_in(rule: dict, context: str) -> bool:
    """Whether a rule belongs in the prompt built for `context`.

    A tuning-guidance rule is rendered into the DETECTION prompt, because the
    same model call produces the query and the tuning notes together. Scoping
    the prompt the way `problems()` scopes enforcement would have left the
    model measured against a rule it was never shown -- which is the defect
    this whole file exists to remove, rebuilt one layer down.
    """
    scope = str(rule.get("applies_to") or "any")
    if scope in ("any", context):
        return True
    return scope == "tuning-guidance" and context == "detection"


def render(context: str = "detection") -> str:
    """The rules as prompt text. Every enforced rule, worst severity first.

    `guidance` rules are rendered too: they are real instructions, they are
    simply ones no checker can confirm, and leaving them out of the prompt to
    keep the prompt honest would instead make the prompt incomplete.
    """
    lines: list[str] = []
    urls = sources()
    for severity in SEVERITIES:
        group = [r for r in rules() if r.get("severity") == severity
                 and _rendered_in(r, context)]
        if not group:
            continue
        for rule in group:
            says = " ".join(str(rule.get("says", "")).split())
            cite = urls.get(str(rule.get("source", "")), "")
            mark = {"blocks-deployment": "MUST", "error": "MUST",
                    "warning": "SHOULD", "guidance": "SHOULD"}[severity]
            # A rule that applies only to certain techniques has to NAME them,
            # or the model is told a rule and left to guess when it is in force.
            listed = [str(t).strip() for t in (rule.get("techniques") or [])]
            when = f" Applies to: {', '.join(listed)}." if listed else ""
            suffix = f" [{cite}]" if cite else ""
            lines.append(f"- {mark}: {says}{when}{suffix}")
    return "\n".join(lines)


def problems(kql: str, context: str = "detection",
             technique: str = "") -> list[tuple[str, str, str]]:
    """[(severity, rule id, what it says)] for every rule `kql` breaks.

    Worst first, so a caller that reports only the first one reports the one
    that matters most.

    `context` says what this KQL IS. Three of the rules are constraints on a
    Sentinel analytics rule -- no union, no trailing count, no take/limit -- and
    a playbook query is not an analytics rule. A responder running a triage
    query by hand may `take 20`; an alert rule may not, because it would alert
    on a different arbitrary subset every run. Applied indiscriminately, those
    rules rejected a correct playbook.
    """
    found: list[tuple[str, str, str]] = []
    for severity in SEVERITIES:
        for rule in rules():
            if rule.get("severity") != severity:
                continue
            scope = str(rule.get("applies_to") or "any")
            if scope != "any" and scope != context:
                continue
            # A rule declaring `needs: technique` applies only to the techniques
            # it lists. Without the technique it is SKIPPED rather than applied:
            # a caller who cannot say which technique this is cannot be told
            # their advice is wrong for it, and guessing would reject correct
            # tuning notes on every detection that never named one.
            if rule.get("needs") == "technique":
                listed = {str(t).strip() for t in (rule.get("techniques") or [])}
                # An EMPTY list means every technique, not none. The
                # privilege-grant rule lists six and applies to those; the
                # cloud-matrix rule lists none and applies to all, because it is
                # about a property ATT&CK publishes rather than a set somebody
                # chose. Reading empty as "no techniques" silently disabled it.
                if not listed:
                    listed = None
                # `"".split()` is [], so index it only after checking. An empty
                # technique is the common case -- most callers do not pass one --
                # and crashing there would break every validation that does not.
                parts = (technique or "").split()
                tid = parts[0].strip() if parts else ""
                if not tid or (listed is not None and tid not in listed):
                    continue
            checker = _CHECKS.get(str(rule.get("check") or ""))
            # WHAT the checker is handed. Most read the query; a rule about the
            # TECHNIQUE ITSELF -- rather than about a query that happens to
            # carry one -- reads the technique. Handing every checker `kql`
            # made the cloud-matrix rule inspect an empty string and pass
            # everything, silently, which is how a rule comes to exist and
            # enforce nothing.
            subject = technique if rule.get("checks") == "technique" else kql
            if checker is None or not checker(subject):
                continue
            found.append((severity, str(rule["id"]),
                          " ".join(str(rule.get("says", "")).split())))
    return found


def fatal(kql: str, context: str = "detection", technique: str = "") -> list[str]:
    """The messages for rules whose severity means "do not ship this"."""
    return [f"{rule_id}: {says}"
            for sev, rule_id, says in problems(kql, context, technique)
            if sev in FATAL]


def advisory(kql: str, context: str = "detection", technique: str = "") -> list[str]:
    """The messages for rules that are worth saying and do not block."""
    return [f"{rule_id}: {says}"
            for sev, rule_id, says in problems(kql, context, technique)
            if sev not in FATAL]


def technique_problems(technique: str, table: str = "",
                       operation: str = "") -> list[str]:
    """What is wrong with a detection's TECHNIQUE, given where it fired.

    Suppressed by a `platform_exception` recorded in the technique map. The
    exception is legitimate -- App Service compute inherits host techniques from
    its runtime, so a file written into a site is T1505.003 even though ATT&CK
    tags that Windows/Linux/macOS -- and it is honoured here rather than by
    weakening the rule, so a mapping that relies on it has to SAY so in the
    catalogue and a mapping that does not still gets flagged.
    """
    from .. import knowledge

    if table and knowledge.platform_exception(table, technique):
        return []
    return advisory("", "detection", technique)


def guidance_problems(notes: str, technique: str) -> list[str]:
    """What is wrong with a detection's TUNING NOTES, given its technique.

    A separate entry point because the input is prose rather than KQL and the
    caller has to say which technique it is talking about. Same rules file, same
    `render()`, so the model is told the rule it will be measured against.
    """
    return fatal(notes, "tuning-guidance", technique)


def unchecked() -> list[str]:
    """Rules stated to the model that no checker enforces.

    A number, deliberately reachable, so "how much of what we tell the model do
    we actually verify" has an answer instead of an assumption.
    """
    return [str(r["id"]) for r in rules() if not r.get("check")]


_OPENS_WITH_LET = re.compile(r"^\s*let\s+[A-Za-z_]", re.IGNORECASE | re.MULTILINE)


@_check("unterminated_let_query")
def _unterminated_let_query(kql: str) -> bool:
    """A let-form query with no closing semicolon.

    Only the let form: a plain `Table | where ...` needs no terminator and
    requiring one everywhere would reject the majority of correct detections.
    """
    body = _bare(kql).strip()
    if not _OPENS_WITH_LET.search(body):
        return False
    return not body.rstrip().endswith(";")


# ── Checkers that read the TUNING NOTES rather than the query ─────────────────
#
# `tuning_guidance` is free text the model writes and nothing checked it, so the
# advice a SOC acts on was the least verified thing in the output. These take
# the same (text) shape as every other checker; `applies_to: tuning-guidance`
# is what decides which input they are handed.

# Words that mean "stop this from firing for a given identity". `narrow`,
# `scope` and `threshold` are deliberately absent -- those are the RIGHT advice
# on a privilege grant and must not be flagged.
_SUPPRESSION = re.compile(
    r"\b(allow[- ]?list(ed|ing)?|whitelist(ed|ing)?|exclude[ds]?|excluding"
    r"|suppress(es|ed|ing)?|ignore[ds]?|filter out)\b", re.IGNORECASE)

# Names a reader would recognise as "the identity that did it". Matched loosely
# on purpose: the advice is prose, not KQL, and it says ActorUPN on one table
# and InitiatedBy on another.
_ACTOR_WORDS = re.compile(
    r"\b(actor\w*|caller|principal\w*|identit(y|ies)|account\w*|user\w*"
    r"|upn|initiatedby|requester\w*|service principal\w*|pipeline)\b",
    re.IGNORECASE)


@_check("actor_suppression_advice")
def _actor_suppression_advice(text: str) -> bool:
    """Advice to suppress by identity, anywhere in the tuning notes.

    Line by line, because a note may legitimately say "narrow by role scope"
    on one line and nothing about identity on another, and scanning the whole
    block would let a suppression line hide beside a good one.
    """
    for line in (text or "").splitlines():
        if _SUPPRESSION.search(line) and _ACTOR_WORDS.search(line):
            return True
    return False
