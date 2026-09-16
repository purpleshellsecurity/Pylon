"""Operation-string sanity checks — a light guard on the model-asserted
`operation` field.

The operation drives the KQL filter (e.g. `OperationNameValue == "..."`) and is
the strongest anchor for saved-list matching, so a hallucinated operation yields
a query that passes schema validation but silently never fires — a false-negative
detection that looks fine.

Three checks, all WARNINGS, never errors — a legitimate-but-unusual operation
must never be rejected:

  * shape — a value that isn't an ARM operation path at all;
  * namespace — a provider that doesn't match the resource under analysis;
  * existence — the operation is not in the vendored provider-operations
    catalog (~18k operations across 152 providers, `provider_operations`).

That third check is newer than this paragraph used to admit. This docstring said
"there is no offline catalog of every valid Azure operation ... true verification
needs a live provider-operations API call and is out of scope here", while line
~120 of this same file imports exactly such a catalog and uses it.
`provider_operations` names operation validation as one of its two purposes. The
code caught up; the docstring had not.

What the catalog still cannot do is prove an operation is FAKE. It is harvested
from documentation, so it lags reality, and 40 of the providers this tool indexes
have no operations in it at all — for those, every operation misses and the miss
says nothing about the operation. A miss is a signal to check, not a verdict.
"""


# Providers whose operations legitimately appear against ANY resource — role
# assignments, diagnostic settings, resource/tag management — so a namespace
# mismatch against these is expected, not suspicious.
_CROSS_CUTTING = {
    "microsoft.authorization",
    "microsoft.insights",
    "microsoft.resources",
    "microsoft.resourcehealth",
}


def _namespace(resource_or_op: str) -> str:
    """The provider namespace (text before the first '/'), lowercased."""
    return resource_or_op.split("/", 1)[0].strip().lower()


def validate_operation(
    operation: str, table: str, resource_provider: str | None = None
) -> list[str]:
    """Warning-only structural check on an ARM operation string.

    Args:
        operation: the model-asserted operation (e.g. MICROSOFT.KEYVAULT/VAULTS/WRITE).
        table: the table the detection queries. Structural checks apply only to
            AzureActivity (ARM control-plane); data-plane operation names have no
            single shape and are left alone.
        resource_provider: the resource type under analysis when known
            (e.g. Microsoft.KeyVault/vaults), used for the namespace-match check.
            None (single-service / free-text runs) skips that check.

    Returns a list of human-readable warnings (possibly empty). Never raises,
    never returns an error — a warning cannot invalidate a detection.
    """
    op = (operation or "").strip()
    if not op:
        return []

    # Entra AuditLogs first: the operation is a documented ACTIVITY NAME, not an
    # ARM path and not a data-plane vocabulary, so neither branch below fits. It
    # has to come first — the data-plane branch returns for EVERY table that is
    # not AzureActivity, which is how AuditLogs ended up checked by nothing at
    # all. A query filtering on an OperationName Entra never writes parses
    # cleanly, validates cleanly, and can never fire.
    if table == "AuditLogs":
        from ..entra_audit_activities import is_known as _entra_known

        if not _entra_known(op):
            return [
                (f'Operation "{op}" is not in the Entra audit activity reference — '
                 "verify it is a real AuditLogs OperationName, or the detection may "
                 "never fire.")
            ]
        return []

    # Data-plane audit tables: no single ARM shape, but where we have a curated
    # per-service vocabulary, verify the operation is a real one for the table
    # (catches e.g. "GetSecret" where AZKVAuditLogs writes "SecretGet"). Tables
    # we don't cover are left alone.
    if table != "AzureActivity":
        from ..data_plane_operations import field_for, has_table, is_known

        if has_table(table) and not is_known(table, op):
            field = field_for(table) or "OperationName"
            msg = (
                f'Operation "{op}" is not a known {table} operation — verify it '
                f"matches a real {field} value, or the detection may never fire."
            )
            return [msg]
        return []

    warnings: list[str] = []

    # Shape: an ARM operation is NAMESPACE/RESOURCETYPE.../ACTION. The minimum
    # tell is a provider namespace ("microsoft.<x>") followed by a path. A bare
    # verb like "delete secret" filtered against OperationNameValue never fires.
    ns = _namespace(op)
    if "/" not in op or "." not in ns or not ns.startswith("microsoft."):
        warnings.append(
            f'Operation "{op}" is not shaped like an ARM operation (expected e.g. '
            "MICROSOFT.KEYVAULT/VAULTS/WRITE) — verify it matches a real "
            "AzureActivity OperationNameValue, or the detection may never fire."
        )
        return warnings

    # Namespace match: the operation should belong to the resource under
    # analysis, or to a cross-cutting provider that applies to any resource.
    if resource_provider:
        rp = _namespace(resource_provider)
        if ns != rp and ns not in _CROSS_CUTTING:
            warnings.append(
                f'Operation "{op}" is under "{op.split("/", 1)[0]}" but the target '
                f'resource provider is "{resource_provider.split("/", 1)[0]}" — '
                "confirm this operation belongs to the resource; a mismatched "
                "operation yields a query that never fires."
            )

    # Catalog existence: the op is well-shaped — but is it a REAL ARM operation?
    # The vendored provider-operations catalog is the closest offline stand-in
    # for the live provider-operations API. A miss is a strong hallucination
    # signal, but stays a WARNING: a brand-new operation not yet in the docs
    # must never be rejected.
    from ..provider_operations import PROVIDER_ABSENT, UNKNOWN, coverage

    state = coverage(op)
    if state == UNKNOWN:
        warnings.append(
            f'Operation "{op}" is well-formed but is not in the Azure '
            "provider-operations catalog — verify it is a real operation, or the "
            "detection may never fire."
        )
    elif state == PROVIDER_ABSENT:
        # Deliberately silent. The catalog holds no operations for this provider
        # at all, so a miss is the catalog's gap and not the operation's fault.
        # Warning here would fire on every operation for 62 of the 212 indexed
        # resource types, and a warning that is usually wrong is one nobody
        # reads — which costs the UNKNOWN case, the only one carrying evidence.
        # `operation_status` records it instead, so it is measurable rather than
        # merely quiet.
        pass

    return warnings


def operation_status(operation: str, table: str, resource_provider: str | None = None):
    """(status, warnings) for `operation` — the catalog's three-state answer plus
    whatever `validate_operation` would say.

    Separate from `validate_operation` so that function keeps its signature and
    its callers, including the eval metrics that count warnings by phrase.
    """
    from ..provider_operations import KNOWN, PROVIDER_ABSENT, coverage

    warnings = validate_operation(operation, table, resource_provider)
    op = (operation or "").strip()
    if not op or table != "AzureActivity":
        # No ARM catalog applies; nothing was checked against it.
        return PROVIDER_ABSENT if op else KNOWN, warnings
    return coverage(op), warnings
