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
        return f"{_actor_expr(preferred)} == {_ACTOR_VAR}", [
            f'let {_ACTOR_VAR} = "[object ID from the alert]";'
        ]
    ip = co.ip_field(table)
    if ip:
        let = f'let {_IP_VAR} = "[source IP from the alert]";'
        if ip.get("array"):  # e.g. AKS SourceIps
            return f"{ip['field']} has {_IP_VAR}", [let]
        return f"{ip['field']} == {_IP_VAR}", [let]
    return None


def _project(table: str) -> str:
    """Comma-joined project columns for a hop: TimeGenerated plus the table's
    actor and (non-array) IP fields, deduped."""
    cols = ["TimeGenerated"]
    fields = co.actor_fields(table)
    if fields:
        cols.append(fields[0]["field"])
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
    query = f"{table} | where {' and '.join(where)} | project {_project(table)}"
    return {
        "label": label,
        "table": table,
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
    return {
        "label": f"Additional context — {table} (not actor-joined; resource/time scoped)",
        "table": table,
        "tier": "context",
        "kql": "\n".join(lets + [f"{table} | where {' and '.join(where)}"]),
        "actor_joined": False,
    }


def pivot_plan(fired_table: str) -> list[dict]:
    """Ordered pivot hops for a detection that fired on `fired_table`. Empty if
    the table isn't in the correlation map (caller falls back to prose)."""
    if not co.has_table(fired_table):
        return []
    hops: list[dict] = []

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
