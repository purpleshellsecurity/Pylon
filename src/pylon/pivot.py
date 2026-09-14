"""Phase-1 investigation-pivot generator.

Given the table a detection fired on, generate the ordered set of pivot queries
that follow the *actor* across log surfaces — identity -> control -> data (two
tiers: same-resource, then blast-radius) -> context — using each table's real
correlation fields (from correlation.py). Rendered into the playbook's
Investigation section.

Queries use `let ActorId = "[...]"` / `let TargetResource = "[...]"` placeholders
in the existing playbook style; the analyst fills them from the alert. Identity
is the join key (object ID canonical); when a table has no actor field (e.g.
Cosmos key-auth) the pivot falls back to the source IP. Context tables are
resource/time-scoped, never actor-joined. See
docs/correlation-pivot-layer-spec.md.
"""

from . import correlation as co

_ACTOR_VAR = "ActorId"
# For a column that holds a UPN or an object id depending on principal type.
_ACTOR_UPN_VAR = "ActorUpn"
_RESOURCE_VAR = "TargetResource"
_IP_VAR = "SourceIP"

# Standard identity / control / activity hops walked for every covered cloud
# fired-table.
_IDENTITY_HOPS = ("SigninLogs", "AuditLogs")
_CONTROL_HOP = "AzureActivity"
_ACTIVITY_HOPS = ("MicrosoftGraphActivityLogs",)  # what API calls did the actor make?

# The Defender endpoint island is gone with the tables it walked. Device* joined
# on a Windows account and a device name rather than a cloud identity, so it was
# a second plan shape; no target can fire on those tables, so it walked nothing.


def _actor_expr(field: dict) -> str:
    """KQL expression that yields the actor value for an actor field spec.

    Indexed directly, NOT through parse_json. Both columns that carry a json_path
    -- AZKVAuditLogs.Identity and AuditLogs.InitiatedBy -- are dynamic, and the
    Key Vault table asset says so by name: "Identity is DYNAMIC, not a JSON
    string. Do NOT call parse_json() on it." Both playbook assets index directly
    too. This generator was the one place doing the opposite, so a run was told
    the rule in the schema reference and handed the violation in its grounded
    pivots -- and copied the pivots. Blamed on the model twice before it was
    traced here.
    """
    if field.get("json_path"):
        return f"tostring({field['field']}.{field['json_path']})"
    return field["field"]


def _predicate(table: str) -> tuple[str, list[str]] | None:
    """(where-predicate, required let-statements) for `table`, identity-first
    with IP fallback. None if the table has neither a usable actor nor IP."""
    fields = co.actor_fields(table)
    if fields:
        preferred = next((f for f in fields if f["kind"] == "oid"), fields[0])
        # A column that carries EITHER shape cannot be compared to one of them.
        # AzureActivity.Caller is `upn_or_oid` and means it: measured over
        # thirty days, 15,139 rows hold a UPN and 8,222 hold an object id. The
        # pivot compared it to an object id, so it silently found nothing every
        # time a human did the thing -- which is the case these detections fire
        # on. Valid KQL, zero rows, forever; the same shape as filtering
        # AzureActivity on `Authorization.role`, a field that does not exist.
        #
        # So the responder supplies both and the pivot accepts either. A blank
        # they cannot fill is left empty and `in` still matches on the other.
        if preferred.get("kind") == "upn_or_oid":
            return f"{_actor_expr(preferred)} in ({_ACTOR_VAR}, {_ACTOR_UPN_VAR})", [
                f'let {_ACTOR_VAR} = "[object ID from the alert]";',
                f'let {_ACTOR_UPN_VAR} = "[actor UPN from the alert]";',
            ]
        # The blank has to name what the COLUMN holds. Every covered table used
        # to prefer an object-id column, so "[object ID from the alert]" was
        # always right and the label was hard-coded. The shared table broke that:
        # AzureDiagnostics SQL audit and Automation job logs carry a UPN and
        # nothing else, and a responder handed a box marked "object ID" above a
        # column holding tenant@example.com pastes the wrong value into a query
        # that then runs and returns nothing.
        label = {"upn": "actor UPN", "appid": "application (client) ID"}.get(
            preferred.get("kind", ""), "object ID")
        var = _ACTOR_UPN_VAR if preferred.get("kind") == "upn" else _ACTOR_VAR
        return f"{_actor_expr(preferred)} == {var}", [
            f'let {var} = "[{label} from the alert]";'
        ]
    ip = co.ip_field(table)
    if ip:
        let = f'let {_IP_VAR} = "[source IP from the alert]";'
        if ip.get("array"):  # e.g. AKS SourceIps
            return f"{ip['field']} has {_IP_VAR}", [let]
        # Some columns are not a bare address. AppServiceIPSecAuditLogs.CIp is
        # "address:ephemeral port", a different port on every row, so comparing
        # it to an address never matches -- valid KQL, zero rows, forever. The
        # correlation entry records how to get the address out and this is
        # where that has to be honoured, not in prose beside it.
        expr = ip.get("extract") or ip["field"]
        return f"{expr} == {_IP_VAR}", [let]
    return None


def _project(table: str) -> str:
    """Comma-joined project columns for a hop: TimeGenerated plus the table's
    actor and (non-array) IP fields, deduped.

    Plus the column that decides whether the actor field means anything, where
    the contract records one. The storage family only names a principal when
    `AuthenticationType == "OAuth"` -- 38 rows of 196 measured -- and its own
    contract says to state the auth type in the output or filter on it. The
    pivot did neither, and the contract checker said so on every storage hop.
    """
    from . import contracts

    cols = ["TimeGenerated"]
    fields = co.actor_fields(table)
    if fields:
        cols.append(fields[0]["field"])
        gate = (contracts.for_table(co.table_name(table)) or {}).get(
            "attribution", {}).get("gate", "")
        # The gate is an expression ("AuthenticationType == \"OAuth\""); the
        # column is its first identifier.
        column = gate.split()[0] if gate else ""
        if column:
            cols.append(column)
    ip = co.ip_field(table)
    if ip and not ip.get("array"):
        cols.append(ip["field"])
    return ", ".join(dict.fromkeys(cols))


def _hop(label: str, table: str, tier: str, *, scope_resource: bool) -> dict | None:
    """Build one actor-joined pivot hop dict (label, table, tier, kql,
    actor_joined), optionally resource-scoped. None if the table has no predicate."""
    pred = _predicate(table)
    if pred is None:
        return None
    where, lets = [pred[0]], list(pred[1])
    if scope_resource:
        res = co.resource_field(table)
        if res:
            where.append(f"{res['field']} == {_RESOURCE_VAR}")
            lets.append(f'let {_RESOURCE_VAR} = "[resource ID from the alert]";')
    # A shared-table entry reads AzureDiagnostics and must narrow to its own
    # service FIRST. Appending the scope to the actor predicate instead would
    # still be correct KQL and would read as though the actor filter were the
    # point; leading with it says what this query is looking at.
    scope = co.scope(table)
    query = (f"{co.table_name(table)} | where "
             f"{' and '.join(([scope] if scope else []) + where)} "
             f"| project {_project(table)}")
    return {
        "label": label,
        "table": co.table_name(table),
        "key": table,
        "tier": tier,
        "kql": "\n".join(lets + [query]),
        "actor_joined": bool(co.actor_fields(table)),
    }


def _context_hop(table: str) -> dict:
    """Build a context-table hop dict — resource/time-scoped, never actor-joined."""
    res = co.resource_field(table)
    lets, where = [], ["TimeGenerated between (ago(1d) .. now())"]
    if res:
        where.insert(0, f"{res['field']} == {_RESOURCE_VAR}")
        lets.append(f'let {_RESOURCE_VAR} = "[resource ID from the alert]";')
    scope = co.scope(table)
    if scope:
        where.insert(0, scope)
    return {
        "label": f"Additional context — {table} (not actor-joined; resource/time scoped)",
        "table": co.table_name(table),
        "key": table,
        "tier": "context",
        "kql": "\n".join(lets + [f"{co.table_name(table)} | where {' and '.join(where)}"]),
        "actor_joined": False,
    }


def pivot_plan(fired_table: str) -> list[dict]:
    """Ordered pivot hops for a detection that fired on `fired_table`. Empty if
    the table isn't in the correlation map (caller falls back to prose)."""
    if not co.has_table(fired_table):
        return []
    hops: list[dict] = []

    # A table with no actor column cannot start an identity pivot. Every hop
    # below begins "take the object ID from the alert", and an alert on a
    # front-door access decision or a function host log has no object ID to
    # take -- the row names nobody. Offering those hops hands a responder a
    # query they cannot fill in, which is worse than offering none.
    #
    # Measured: AppServiceIPSecAuditLogs decides before authentication, and
    # FunctionAppLogs records what the runtime did rather than who asked.
    if not co.actor_fields(fired_table):
        # What a responder CAN do here: the same address, if the row carries
        # one, and the same resource over the same window. `_context_hop` is
        # already the resource/time-scoped, never-actor-joined shape, so it is
        # exactly right and does not need reinventing.
        if co.ip_field(fired_table):
            hop = _hop("Same source address — what else did it reach?",
                       fired_table, "address", scope_resource=False)
            if hop:
                hops.append(hop)
        hops.append(_context_hop(fired_table))
        return hops

    # Identity — how did they authenticate / what did they change in the directory?
    for t in _IDENTITY_HOPS:
        if t != fired_table and co.has_table(t):
            hop = _hop(f"Identity — {t}", t, "identity", scope_resource=False)
            if hop:
                hops.append(hop)

    # Control — what did the actor change across the subscription?
    if fired_table != _CONTROL_HOP and co.has_table(_CONTROL_HOP):
        hop = _hop("Control plane — what did they change?", _CONTROL_HOP, "control", scope_resource=False)
        if hop:
            hops.append(hop)

    # Activity — what API calls did the actor make?
    for t in _ACTIVITY_HOPS:
        if t != fired_table and co.has_table(t):
            hop = _hop(f"Graph activity — {t}", t, "activity", scope_resource=False)
            if hop:
                hops.append(hop)

    # Data — only when the alert itself is a data-plane detection source.
    if co.plane(fired_table) == "data" and co.is_detection_source(fired_table):
        same = _hop("Data (same resource) — what else here?", fired_table, "data-same", scope_resource=True)
        blast = _hop("Data (blast radius) — what else did they touch, any resource?",
                     fired_table, "data-blast", scope_resource=False)
        hops += [h for h in (same, blast) if h]

    # Context tables — resource/time-scoped pointers, never actor-joined.
    hops += [_context_hop(t) for t in co.context_tables()]
    return hops


def render_pivot_block(fired_table: str) -> str:
    """Prompt-ready grounded pivot queries for the playbook's Investigation
    section, or '' when the fired table isn't covered (fall back to prose)."""
    hops = pivot_plan(fired_table)
    if not hops:
        return ""
    header = (
        "Grounded pivot queries — follow the actor across logs for the "
        "Investigation section (use these exact fields, casing, and parse paths):"
    )
    parts = [header]
    parts += [f"[{h['tier']}] {h['label']}\n{h['kql']}" for h in hops]
    return "\n\n".join(parts)
