"""Attack-path edges from each detection's preconditions and effects.

Every attack vector declares two things about the action it describes:

  requires  — footholds the attacker must ALREADY hold to perform it
  enables   — footholds the attacker gains once it succeeds

Both draw from ONE shared token list (``Tag``) so the values line up across
detections. An edge runs from vector A to vector B when ``A.enables`` overlaps
``B.requires`` — A hands B a token it needs. Chaining those edges turns a set of
independent detections into attack paths, computed rather than hand-drawn.

The tokens are attacker *state*, not detection state: an edge exists whether or
not either end has a working detection. Coverage is painted onto this graph
later; it does not define it.
"""

from enum import Enum


class Tag(str, Enum):
    """The shared, closed token list for ``requires`` / ``enables``.

    Environment-agnostic (privilege/access classes, never named resources) and
    deliberately small — the whole model relies on one action's ``enables``
    matching another's ``requires``, which only happens if the vocabulary is
    shared and stable. Grow it deliberately; each addition is a modelling call.
    """

    # ── footholds / entry (typically require nothing — path starts) ──
    FOOTHOLD_UNAUTH = "foothold.unauth"            # network/public reachability only
    IDENTITY_PHISHED_USER = "identity.phished_user"  # a duped user action (consent, creds)

    # ── identity & session ──
    IDENTITY_VALID_SESSION = "identity.valid_session"  # a working user/interactive session
    IDENTITY_STOLEN_CRED = "identity.stolen_cred"      # password / cert / key in hand
    IDENTITY_APP_CREDENTIAL = "identity.app_credential"  # standing SP/app secret or cert
    IDENTITY_TOKEN = "identity.token"                  # stolen or forged access token

    # ── privilege ──
    PRIV_ROLE_ASSIGNED = "priv.role_assigned"      # some scoped RBAC / Graph role
    PRIV_ADMIN = "priv.admin"                      # Global Admin / Owner-equivalent

    # ── recon ──
    RECON_TENANT_MAP = "recon.tenant_map"          # knows principals / resources / roles

    # ── data / objective access ──
    DATA_STORAGE_READ = "data.storage_read"
    DATA_DISK_ACCESS = "data.disk_access"
    DATA_SECRET_ACCESS = "data.secret_access"      # Key Vault / secrets store
    DATA_MAIL_ACCESS = "data.mail_access"

    # ── persistence & defense evasion ──
    PERSIST_BACKDOOR_IDENTITY = "persist.backdoor_identity"  # rogue app/SP/role that survives
    DEFENSE_LOGGING_DISABLED = "defense.logging_disabled"

    # ── objectives (typically enable nothing — path ends) ──
    IMPACT_EXFIL = "impact.exfil"
    IMPACT_DESTROY = "impact.destroy"
    IMPACT_RANSOM = "impact.ransom"


_BY_VALUE: dict[str, Tag] = {t.value: t for t in Tag}

# One-line meaning per token, for the Phase-1 prompt block. Keep in sync with Tag.
_TAG_HELP: dict[Tag, str] = {
    Tag.FOOTHOLD_UNAUTH: "only network/public reachability, no identity yet",
    Tag.IDENTITY_PHISHED_USER: "a user was tricked into an action (consent, creds, MFA approval)",
    Tag.IDENTITY_VALID_SESSION: "a working user/interactive session",
    Tag.IDENTITY_STOLEN_CRED: "a password, cert, or key in hand",
    Tag.IDENTITY_APP_CREDENTIAL: "a standing service-principal/app secret or cert",
    Tag.IDENTITY_TOKEN: "a stolen or forged access token",
    Tag.PRIV_ROLE_ASSIGNED: "some scoped RBAC / Graph role",
    Tag.PRIV_ADMIN: "Global Admin / Owner-equivalent control",
    Tag.RECON_TENANT_MAP: "knowledge of principals, resources, and roles",
    Tag.DATA_STORAGE_READ: "read access to blob/file storage data",
    Tag.DATA_DISK_ACCESS: "access to disk/VM data (e.g. via snapshot)",
    Tag.DATA_SECRET_ACCESS: "access to Key Vault / a secrets store",
    Tag.DATA_MAIL_ACCESS: "access to mailbox contents",
    Tag.PERSIST_BACKDOOR_IDENTITY: "a rogue app/SP/role that survives remediation",
    Tag.DEFENSE_LOGGING_DISABLED: "cloud logging turned off or evaded",
    Tag.IMPACT_EXFIL: "data moved out to attacker-controlled storage",
    Tag.IMPACT_DESTROY: "data or resources destroyed",
    Tag.IMPACT_RANSOM: "data encrypted / held for ransom",
}


def tag_seed_context() -> str:
    """Phase-1 prompt block listing the shared token list and how to use it.

    Appended to the threat-analysis instructions the same way the known-technique
    catalog seed is, so the model tags each vector's requires/enables from a
    closed list instead of inventing tokens."""
    lines = [
        "\n<attacker_footholds>",
        (
            "For each attack vector also set two fields that let the vectors "
            "chain into attack paths:"
        ),
        (
            "- requires: footholds the attacker must ALREADY hold to perform "
            "this action. Leave empty if it needs nothing (an entry point)."
        ),
        (
            "- enables: footholds the attacker GAINS once it succeeds. Leave "
            "empty if it is a terminal objective (exfil/destroy/ransom)."
        ),
        "Use ONLY these tokens — never invent one:",
    ]
    lines += [f"- {t.value}: {_TAG_HELP[t]}" for t in Tag]
    lines.append("</attacker_footholds>")
    return "\n".join(lines)


def normalize_tags(values) -> tuple[list[Tag], list[str]]:
    """Coerce raw ``requires``/``enables`` values to ``Tag``.

    Returns ``(tags, dropped)`` — recognized tokens (deduped, first-seen order)
    and the raw strings that were not in the list. Accepts ``Tag`` or ``str``
    items. Use this to sanitize model output without hard-failing a run when the
    model emits an off-list token (mirrors the MITRE-ID verification pattern).
    """
    seen: set[Tag] = set()
    tags: list[Tag] = []
    dropped: list[str] = []
    for v in values or []:
        key = v.value if isinstance(v, Tag) else str(v).strip()
        tag = _BY_VALUE.get(key)
        if tag is None:
            dropped.append(str(v))
        elif tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tags, dropped


def derive_edges(units) -> list[tuple[int, int, list[str]]]:
    """Attack-path edges over a sequence of units.

    Each unit must expose ``requires`` and ``enables`` (lists of ``Tag`` or of
    their string values). Returns ``(i, j, shared)`` for every ordered pair where
    unit ``i`` ENABLES a token that unit ``j`` REQUIRES; ``i != j``. ``shared`` is
    the sorted token values that formed the edge (the "why" of the pivot).

    Pure and O(n²) — fine for a run's worth of detections, and trivially
    testable.
    """
    def _vals(seq) -> set[str]:
        """The set of string token values from a requires/enables sequence."""
        return {v.value if isinstance(v, Tag) else str(v) for v in (seq or [])}

    enables = [_vals(getattr(u, "enables", None)) for u in units]
    requires = [_vals(getattr(u, "requires", None)) for u in units]

    edges: list[tuple[int, int, list[str]]] = []
    for i, ei in enumerate(enables):
        if not ei:
            continue
        for j, rj in enumerate(requires):
            if i == j:
                continue
            shared = ei & rj
            if shared:
                edges.append((i, j, sorted(shared)))
    return edges


def sources(units) -> list[int]:
    """Indices of units with no ``requires`` — attack-path entry points."""
    return [i for i, u in enumerate(units) if not getattr(u, "requires", None)]


def sinks(units) -> list[int]:
    """Indices of units with no ``enables`` — terminal objectives."""
    return [i for i, u in enumerate(units) if not getattr(u, "enables", None)]
