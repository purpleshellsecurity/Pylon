"""Unified operation grounding — route a detection's (table, operation) to the
right vendored catalog and return one grounding reference.

Four keying regimes, dispatched on what the operation IS, not only on the table:
  * data-plane audit ops (AZKVAuditLogs, StorageBlobLogs, SQL, Cosmos, AKS, ...)
    -> data_plane_operations, keyed by (table, operation)
  * control-plane ARM ops (AzureActivity, and any op shaped like an ARM string)
    -> provider_operations, keyed by the operation string
  * Entra directory actions (`microsoft.directory/...`) -> entra_actions
  * Microsoft Graph permission scopes (`Directory.ReadWrite.All`) ->
    graph_permissions. Both Graph activity tables carry `Scopes` (delegated) and
    `Roles` (application), which is exactly the split that catalog models.

The last two were shipped as "data + loaders only; wiring lands next" and the
wiring never came, so two refreshed, tested catalogs sat unimported while
CODEBASE-WALKTHROUGH claimed they were fed into prompts. Each is gated by its
own `is_known()`, so an operation that is not one of its keys falls straight
through and nothing that worked before changes.

An Entra AuditLogs OperationName is a human phrase ("Add member to role"), NOT a
directory action string, so it still has no key here and still returns {}. That
gap is real and is not papered over with a guessed phrase->action mapping.

This is the single seam the verify step, the validator, and the phase prompts
all call, so grounding is consistent across detection and playbook.
"""

from . import data_plane_operations as _dp
from . import entra_actions as _entra
from . import graph_permissions as _graph
from . import provider_operations as _arm


def reference(table: str, operation: str) -> dict:
    """Grounding block for one operation (with a `plane` tag), or {} if we have
    no catalog entry for it."""
    if not (operation or "").strip():
        return {}
    if _dp.has_table(table):
        ref = _dp.reference(table, operation)
        if ref:
            return {**ref, "plane": "data"}
    ref = _arm.reference(operation)  # matches only real ARM strings, else {}
    if ref:
        return {**ref, "plane": "control"}
    # Gated on the catalogs' own membership tests rather than on the table, so a
    # vector naming a directory action or a Graph scope is grounded wherever it
    # appears, and anything else falls through unchanged.
    if _entra.is_known(operation):
        ref = _entra.reference(operation)
        if ref:
            return {**ref, "operation": ref["action"], "plane": "directory"}
    if _graph.is_known(operation):
        ref = _graph.reference(operation)
        if ref:
            # graph_permissions keys its prose per plane, not at the top level.
            # Prefer the application plane's text, since a detection on Roles is
            # app-only; fall back to delegated.
            desc = ""
            for plane in ("application", "delegated"):
                if isinstance(ref.get(plane), dict) and ref[plane].get("desc"):
                    desc = ref[plane]["desc"]
                    break
            return {**ref, "operation": ref["scope"], "description": desc,
                    "plane": "graph-permission"}
    return {}


def grounding_block(table: str, operation: str) -> str:
    """A short prompt-ready grounding block for one operation, or '' when we have
    no catalog entry (caller falls back to the table's prose asset)."""
    ref = reference(table, operation)
    if not ref:
        return ""
    lines = [f'Operation "{ref["operation"]}" — {ref.get("description") or "(no description available)"}']
    if ref.get("service"):
        lines.append(f'Service: {ref["service"]}')
    if ref.get("sensitive"):
        lines.append("Flagged security-relevant (exfil / tamper / recon).")
    if ref.get("privileged"):
        lines.append("PRIVILEGED directory action.")
    if ref.get("roles"):
        lines.append(f'Granted by role(s): {", ".join(ref["roles"][:6])}')
    if ref.get("planes"):
        lines.append(f'Permission plane(s): {", ".join(ref["planes"])}')
        for plane in ("application", "delegated"):
            if plane in ref:
                consent = " (admin consent required)" if ref[plane].get("adminConsent") else ""
                lines.append(f'  {plane}: {ref[plane].get("display", "")}{consent}')
    # Recoverability, when the catalogue establishes it. Silence here means it
    # was never established, NOT that the operation is reversible -- so nothing
    # is printed and the playbook rule below treats it as unknown rather than
    # writing a restore step it cannot support.
    rec = (ref.get("recovery") or "").strip()
    if rec == "none":
        lines.append("Recovery: NONE. This operation destroys permanently; "
                     "nothing reverses it. The playbook's recovery section must "
                     "say the object is gone and move to downstream impact.")
    elif rec:
        lines.append(f"Recovery: reversed by {rec}, within the retention window.")
    rev = ref.get("reverse")
    if rev:
        # The catalogs name the same idea differently: data-plane/ARM entries key
        # it "operation", entra_actions keys it "action". Read whichever is there
        # rather than assuming, which raised KeyError the moment Entra was wired.
        name = rev.get("operation") or rev.get("action") or ""
        desc = rev.get("description", "")
        lines.append(f"Reverse operation (for containment): {name}"
                     + (f" — {desc}" if desc else ""))
    return "\n".join(lines)
