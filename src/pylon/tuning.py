"""The tuning contract: what an analyst needs to make a target's rules usable.

One row per target, ASSEMBLED from catalogues that already exist. Nothing here
is typed by hand and nothing is stored: a saved copy of derived facts is a copy
that drifts, and this repo has spent enough of its life on facts that existed in
one place and never reached the other.

Eight of the nine fields are sourced:

  target, table, covers   the target registry
  key fields              the table contract's measured `roles`
  noisy activities        the curated rejection taxonomy, scoped to the target
  baseline KQL            the table contract's own verified reference query
  tuning levers           the same `roles` -- the columns this table can be
                          filtered on, rather than columns an analyst might
                          assume exist
  severity floor          ATT&CK's own tactics, via knowledge.tier

The ninth is deliberately NOT sourced, and deliberately not guessed. See
FALSE_POSITIVES.
"""

from __future__ import annotations


# The same sentence on every target, on purpose.
#
# "Is this actor authorized" is not a property of the log data. It is a fact
# about one organisation -- who they have designated to run a given account,
# service principal, sync identity or pipeline -- and no catalogue, registry or
# taxonomy can hold it. That is true of the narrow version too: whether a
# first-party Microsoft principal is authorised HERE is still tenant-specific.
#
# So this field is a verification prompt rather than content. It carries no
# DRAFT tag because it is not a guess at an answer; it is the question, stated
# once, in the place an analyst will be looking when they need to ask it.
#
# Generic first-party noise -- token issuance, sync job mechanics, portal reads
# -- is a different thing entirely, IS groundable, and lives in `noisy` below.
FALSE_POSITIVES = (
    "Verify the initiating actor is an organization-approved user, service "
    "principal, sync account, or pipeline identity for this action. "
    "[Customer to populate: list authorized identities for this target.]"
)


# Everything the catalogues hold is reached through `knowledge`, never opened
# here. Four sources with different owners and refresh paths sit behind that
# accessor, and a second module opening one of them directly is a second place
# for its shape to be assumed wrongly -- which is the rule the repo's own test
# enforces, and which this module broke on its first draft.


def _key_fields(table: str, service: str = "") -> list[tuple[str, str]]:
    """[(expression, what it carries)] -- the columns an analyst filters on.

    The actor comes from `_actor_reference`, not from the contract string,
    because on Key Vault and Entra the contract's honest answer is "not a
    column" and the expression that DOES reach the principal lives in the
    correlation map. Rendering the prose here would put "see identity recipe"
    in the field an analyst is told to alert on.
    """
    from . import contracts
    from .playbook import _actor_reference, _is_column

    roles = contracts.roles(table, service)
    out: list[tuple[str, str]] = []
    actor = _actor_reference(table, service)
    if actor:
        out.append((actor, "who did it"))
    # No `elif` emitting the contract's sentence. A table that names nobody has
    # nothing to put in this list, and the sentence explaining why belongs in
    # prose -- it was appearing here as though it were a column, in the one
    # field that is supposed to be paste-able into a query. Fixed once for the
    # primary table and missed on the other-tables path, because the test only
    # covered the primary.

    for role, meaning in (("what", "which operation"), ("outcome", "did it succeed"),
                          ("target", "what was acted on"),
                          ("from_where", "source address")):
        value = roles.get(role) or ""
        if not value:
            continue
        # A role whose value is PROSE is not a field to alert on. The contracts
        # say so in words where the honest answer is "no single column carries
        # this" -- AuditLogs records the source address inside InitiatedBy, not
        # in a column of its own. Rendering that sentence under "key fields"
        # hands an analyst something they cannot put in a query, in the one
        # place they are being told what to put in a query.
        if not _is_column(value):
            continue
        column = value.split("--")[0].strip()
        # A column can carry two roles -- an IP-restriction row's `Result` is
        # both the action and its outcome -- and listing it twice reads as two
        # fields.
        if column not in {c for c, _ in out}:
            out.append((column, meaning))
    return out


def _levers(table: str, service: str = "") -> list[str]:
    """The columns this table can actually be tuned on.

    Sourced rather than suggested: an analyst told to "allowlist by account
    name" on a table whose principal is an opaque credential id gets a rule
    that suppresses nothing. Only columns the contract measured appear here.
    """
    from . import contracts
    from .playbook import _actor_reference, _is_column

    roles = contracts.roles(table, service)
    out: list[str] = []
    actor = _actor_reference(table, service)
    if actor:
        out.append(f"{actor} — exclude an identity")
    for role, how in (("from_where", "exclude or require a source address"),
                      ("outcome", "filter to successes, or keep failures"),
                      ("scope", "narrow to a resource"),
                      ("target", "narrow to an object")):
        value = roles.get(role) or ""
        if value and _is_column(value):
            out.append(f"{value.split('--')[0].strip()} — {how}")
    return out


def _baseline(table: str, *, category: str = "", resource_type: str = "") -> str:
    """The contract's own reference query, scoped to this target.

    Not a query written for this document. The contract's reference query is
    the one that was run against a workspace when the contract was measured, so
    it is the only starter query here that is known to execute.
    """
    from . import contracts

    c = contracts.for_table(table) or {}
    query = (c.get("reference_query") or "").strip()
    if not query:
        return ""
    # A FAMILY contract is written once for several tables, so its reference
    # query is a template: the storage one carries {table} and {category}.
    # Substituting only {window} shipped four queries that begin with a literal
    # `{`, which do not parse -- caught by running all 25 against a workspace.
    query = query.replace("{window}", "24h").replace("{table}", table)
    # Any line still holding a placeholder is DROPPED rather than guessed at. A
    # baseline should not pick one of `{category}`'s measured values for the
    # analyst: storage writes StorageRead, StorageWrite and StorageDelete, and
    # choosing one here would narrow the starting point on their behalf.
    query = "\n".join(line for line in query.splitlines()
                      if "{" not in line or "}" not in line)
    if category:
        query = query.replace("| where TimeGenerated > ago(24h)",
                              f'| where TimeGenerated > ago(24h)\n'
                              f'| where Category =~ "{category}"', 1)
    elif resource_type and table == "AzureActivity":
        query = query.replace("| where TimeGenerated > ago(24h)",
                              f'| where TimeGenerated > ago(24h)\n'
                              f'| where OperationNameValue startswith '
                              f'"{resource_type.upper()}"', 1)
    return query


def _tiers_across(tables: list[str], *, category: str = "",
                  resource_type: str = "") -> dict[str, int]:
    """Kill-chain tiers summed over every table a target writes to."""
    from . import knowledge

    total: dict[str, int] = {}
    for table in tables:
        for tier, n in knowledge.mapped_tiers(
                table, category=category, resource_type=resource_type).items():
            total[tier] = total.get(tier, 0) + n
    return total


def _technique_tables(tables: list[str], *, category: str = "",
                      resource_type: str = "") -> list[str]:
    """The tables that actually carry a mapped technique for this target."""
    from . import knowledge

    return [t for t in tables
            if knowledge.mapped_tiers(t, category=category,
                                      resource_type=resource_type)]


def contract(key: str) -> dict:
    """The tuning contract for one target key, as data."""
    from . import knowledge
    from .services import targets, tables_for

    target = targets()[key]
    tables = list(tables_for(key))
    category = getattr(target, "entra_category", "") or ""
    resource_type = getattr(target, "resource_type", "") or ""
    # The table an analyst tunes on is the SPECIFIC one where the target has
    # one. AzureActivity is listed first for every ARM-capable target and is the
    # right answer only when there is no dedicated table.
    primary = next((t for t in tables if t != "AzureActivity"), tables[0])

    return {
        # `key` on the target object is the DISPLAY form ("Entra RoleManagement");
        # the registry's dict key is the lowercased lookup form. Printing the
        # lookup form gave every Entra row a lowercase name that matches nothing
        # a user would type from `design list`.
        "target": getattr(target, "key", "") or key,
        "key": key,
        "tables": tables,
        "primary_table": primary,
        "category": category,
        "resource_type": resource_type,
        "covers": (getattr(target, "label", "") or "").strip(),
        "key_fields": _key_fields(primary),
        "noisy": [
            {"rule": str(f.value), "why": f.detail, "source": f.source}
            for f in knowledge.excluded(primary, category=category,
                                        resource_type=resource_type)
        ],
        "baseline": _baseline(primary, category=category, resource_type=resource_type),
        "levers": _levers(primary),
        # Across EVERY table the target writes to, not just the primary one.
        # App Service's techniques are all on AzureActivity -- 12 of them across
        # 93 control-plane operations -- and computing this from the primary
        # table alone made the row say "no technique mapped to this target yet",
        # which is flatly false for a target with twelve.
        "severity": _tiers_across(tables, category=category,
                                  resource_type=resource_type),
        # Which table each technique count came from, so a reader is never left
        # to assume it was the one named at the top of the row.
        "technique_tables": _technique_tables(tables, category=category,
                                              resource_type=resource_type),
        "other_tables": [
            {"table": t, "key_fields": _key_fields(t)}
            for t in tables if t != primary
        ],
        "false_positives": FALSE_POSITIVES,
    }


def contracts_all() -> list[dict]:
    """Every target's tuning contract, in the order `design list` prints them."""
    from .services import targets

    return [contract(k) for k in sorted(targets())]


def render(row: dict) -> str:
    """One tuning contract as markdown."""
    out = [f"## {row['target']}", ""]
    line = f"**Log table** — `{row['primary_table']}`"
    if row["category"]:
        line += f", `Category =~ \"{row['category']}\"`"
    others = [t for t in row["tables"] if t != row["primary_table"]]
    if others:
        line += "  (also writes to " + ", ".join(f"`{t}`" for t in others) + ")"
    out += [line]
    if row["covers"]:
        out += [f"**Covers** — {row['covers']}"]
    out += [""]

    out += ["**Key fields to alert on**"]
    out += [f"- `{expr}` — {meaning}" for expr, meaning in row["key_fields"]] or \
           ["- none measured for this table"]
    out += [""]

    out += ["**Common noisy activities**"]
    if row["noisy"]:
        for n in row["noisy"][:6]:
            out += [f"- `{n['rule']}` — {n['why'][:210]}"]
        if len(row["noisy"]) > 6:
            out += [f"- …and {len(row['noisy']) - 6} more, each with a written reason"]
    else:
        out += ["- none catalogued for this target"]
    out += [""]

    if row["baseline"]:
        out += ["**Suggested baseline KQL**", "```kql", row["baseline"], "```", ""]

    out += ["**Tuning levers**"]
    out += [f"- {lever}" for lever in row["levers"]] or \
           ["- none: this table has no measured column worth filtering on"]
    out += [""]

    tiers = row["severity"]
    if tiers:
        parts = ", ".join(f"{n} {t}" for t, n in sorted(tiers.items()))
        where = row.get("technique_tables") or []
        on = (" (all on " + ", ".join(f"`{t}`" for t in where) + ")"
              if where and where != [row["primary_table"]] else "")
        out += [f"**Severity guidance** — mapped techniques by ATT&CK tier: "
                f"{parts}{on}. "
                "`late` (impact, exfiltration, credential access) justifies High; "
                "`early` (discovery, reconnaissance) is capped at Medium because "
                "ATT&CK places it before anything has been taken."]
    else:
        out += ["**Severity guidance** — no technique mapped to this target yet, so "
                "there is no tier to derive a floor from."]
    out += [""]

    others = row.get("other_tables") or []
    if others:
        out += ["**This target also writes to**"]
        for entry in others:
            fields = ", ".join(f"`{e}`" for e, _m in entry["key_fields"]) or "no measured roles"
            out += [f"- `{entry['table']}` — {fields}"]
        out += [""]

    out += [f"**False-positive scenarios** — {row['false_positives']}", ""]
    return "\n".join(out)


def render_all() -> str:
    """Every target's tuning contract as one document."""
    head = [
        "# Tuning contract",
        "",
        "One row per target. Every field except the last is assembled from a "
        "catalogue: the target registry, the measured table contracts, the "
        "curated exclusion taxonomy, and ATT&CK's own tactics. Nothing here is "
        "written by hand, so nothing here can drift from what the tool enforces.",
        "",
        "The false-positive field is identical on every target and is a question "
        "rather than an answer. Whether an actor is authorized is a fact about "
        "one organization, not a property of the log data, and no catalogue can "
        "hold it.",
        "",
    ]
    return "\n".join(head + [render(r) for r in contracts_all()])
