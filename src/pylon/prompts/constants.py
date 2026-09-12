"""Platform and phase metadata — port of lib/prompts/constants.ts."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceDefinition:
    """A selectable service: its display label and the Log Analytics table it queries."""

    label: str
    table: str


@dataclass(frozen=True)
class Platform:
    """A detection platform (ARM, Data Plane, Graph, M365, Defender) and its services."""

    id: str
    label: str
    # What a run against this platform reads, and what it CANNOT see. Both,
    # because the exclusion is the point: a clean result on one plane reads as
    # "this service is covered" to anyone who does not already know the planes
    # are separate runs. An ARM run against Key Vault correctly finds none of
    # SecretGet or KeyDecrypt -- reading a secret never touches ARM.
    #
    # Written per platform rather than per service, so it stays a property of
    # the log source. Naming the sibling TARGET would need an ARM-service to
    # data-plane-table map, which is one-to-many (ARM "Storage" is four tables)
    # and is exactly the kind of hand-written map that goes stale unseen.
    covers: str
    not_covered: str
    coming_soon: bool
    services: tuple


# The Entra chain was called "graph" until the chain it was named against was
# deleted. `signin` and `graph_activity` went with the tables they served, and
# the survivor kept the name that had distinguished it from one of them -- so
# "graph" came to mean Entra directory audit, while `az graph query` elsewhere
# in this codebase still means Azure Resource Graph. One word, two referents,
# neither of them the thing it names.
#
# The id is also written into report.json, and `design playbooks --from` reads
# it back, so an output directory produced before the rename must keep working.
# Normalising on the way in is the whole migration.
_PLATFORM_ALIASES = {"graph": "entra"}


def normalise_platform(platform_id: str) -> str:
    """A platform id as it is written today, whatever it was written as."""
    return _PLATFORM_ALIASES.get(platform_id, platform_id)


PLATFORMS: tuple[Platform, ...] = (
    Platform(
        id="arm",
        label="Azure ARM",
        covers="the control plane: resources created, deleted, reconfigured, or access granted",
        not_covered="what callers then did with the data inside those resources — each service logs that separately",
        coming_soon=False,
        # No service list. These eleven labels used to BE the list of ARM
        # targets, and a resource type could not be reached without one. The
        # catalogue decides now (see `pylon.services.targets`), so a label here
        # would be a second list that can disagree with it.
        services=(),
    ),
    Platform(
        id="dataplane",
        label="Azure Data Plane",
        covers="the data plane: what callers did inside the service, such as reading a secret or downloading a blob",
        not_covered="changes to the resource itself, including access grants — those are in AzureActivity",
        coming_soon=False,
        services=(),
    ),
    Platform(
        id="entra",
        label="Microsoft Entra ID",
        covers="changes to the Entra directory itself: accounts, roles, "
               "applications, credentials, conditional access and domain trust",
        not_covered="sign-ins, which are a different table, and anything inside "
                    "an Azure subscription",
        coming_soon=False,
        services=(
            # Changes + API access (the modern-vs-legacy Graph endpoints).
            ServiceDefinition("Directory Changes", "AuditLogs"),
            # Sign-ins and Graph activity were offered here and are not any more.
            # Neither can be partitioned the way the rest of the catalogue is:
            # SigninLogs has no OperationName column at all, and Graph activity
            # identifies a call by request URI and method rather than by a name.
            # Every technique they claimed resolved at table level, so a run
            # against them returned whatever the model recalled.
            #
            # They are not gone from the tool. `analyze` still reads them, and
            # the KQL validator still knows their columns and their traps.
        ),
    ),
    # Microsoft 365 and Defender for Endpoint were offered here and are not any
    # more. Both were thin next to the rest: OfficeActivity carried 11 techniques
    # and 27 operation names with nothing rejected, and the five endpoint tables
    # carried one or two techniques each and no operation names at all. Against
    # AzureActivity's complete partition of 643 operations they read as the same
    # product, and they are not.
    #
    # This removes them from the DESIGN picker only. `analyze` still measures
    # Office Suite from OfficeActivity data and Windows or Linux from onboarded
    # devices, because that is a measurement of the tenant and does not depend on
    # what Pylon can generate detections for.
)


PHASES = ("threat", "detection", "playbook")

GRAPH_ACTIVITY_TABLE = "MicrosoftGraphActivityLogs"

# Entra sign-in tables — one per principal type × interactivity. Each event
# lands in exactly one (deterministic), so covering the authentication surface
# is a fan-out across all four, not a routing/dedup problem.
SIGNIN_TABLES = frozenset({
    "SigninLogs",
    "AADNonInteractiveUserSignInLogs",
    "AADServicePrincipalSignInLogs",
    "AADManagedIdentitySignInLogs",
})

# Legacy Azure AD Graph (graph.windows.net) API activity — the retired-endpoint
# counterpart to MicrosoftGraphActivityLogs (graph.microsoft.com).
LEGACY_GRAPH_TABLE = "AADGraphActivityLogs"

# The combined bundles are gone. A bundle was a --service name standing for a SET
# of tables the model routed across in one analysis: "Entra" meant AuditLogs plus
# both Graph API access tables, "Sign-ins" meant the four authentication tables.
#
# When the tool narrowed to the tables it can ground an operation vocabulary
# against, every bundle lost all but one of its members -- and a bundle of one is
# just a table. The machinery kept working and kept telling the model to route
# vectors to MicrosoftGraphActivityLogs, which was then clamped back to AuditLogs:
# a vector spent on a table the run could not produce. Recoverable from history.



def get_platform(platform_id: str) -> Platform:
    """The Platform with this id; raises KeyError if none matches."""
    platform_id = normalise_platform(platform_id)
    for p in PLATFORMS:
        if p.id == platform_id:
            return p
    raise KeyError(f"Unknown platform: {platform_id}")


def table_for_target(platform_id: str, service: str) -> str:
    """The Log Analytics table a detection for this target must query.

    THE SECOND HALF of a question that was split across two modules, each
    knowing half the answer and each wrong on the other half:

        table_for_service   resolved a label for dataplane/graph/endpoint, and
                            returned the input unchanged for arm and m365
        engine._expected_table
                            knew arm means AzureActivity and m365 means
                            OfficeActivity, and assumed everything else was
                            ALREADY a table

    Neither was wrong where it was called, which is why both survived. Together
    they are the whole answer, and apart they are two of the six places that
    worked out this same fact.

    `service` is NOT the table on every track, and conflating them is what let a
    display label reach the prompt as a log table. On ARM the prompt's service
    is the resource ("Key Vault") while the table is always AzureActivity; on
    M365 it is the workload. Only on the data plane are they the same string,
    which is why nobody noticed for twelve releases.
    """
    if platform_id == "arm":
        return "AzureActivity"
    if platform_id == "m365":
        return "OfficeActivity"
    return canonical_service(platform_id, service)


def canonical_service(platform_id: str, service: str) -> str:
    """The name everything downstream uses for this target, or `service` unchanged.

    `--service "Key Vault Secrets"` is a DISPLAY LABEL. `design list` prints it,
    is_known_service accepts it, and it was then carried all the way into the
    prompt as though it were a table -- so the model was told, four times and in
    capitals, that its log table was "Key Vault Secrets", and every lookup keyed
    on the table name missed.

    The technique reference was the expensive miss. It is fetched by table, so a
    run started from the label got NO curated ATT&CK block at all: 12k of prompt
    instead of 20k, and the entire Key Vault mapping -- nine techniques over
    forty-five operations -- never reached the model. It still produced valid KQL,
    because the data-plane context happens to carry a service-to-table map the
    model could read, which is exactly why nothing caught this.

    Unknown names pass through untouched: a table this list has never heard of is
    handled downstream (the supported-logs index, or the service gate), and
    swallowing it here would turn a clear failure into a silent one.
    """
    # M365 is the exception, and it has to be: Exchange, SharePoint and OneDrive
    # all write to OfficeActivity, so the label is the ONLY thing that says which
    # workload a run is for. Its prompt is built from the label -- the schema and
    # technique blocks are narrowed to that workload's operations, and the query
    # filters OfficeWorkload on it -- so collapsing it to the shared table here
    # silently widens an Exchange run to all three. `table_for_target` is where M365's
    # table is answered; this function deliberately leaves the workload alone.
    if platform_id == "m365":
        return service
    try:
        platform = get_platform(platform_id)
    except KeyError:
        return service
    for s in platform.services:
        if not isinstance(s, str) and s.label == service:
            return s.table
    return service


def is_known_service(platform_id: str, service: str) -> bool:
    """A match on either the label OR the table name is valid — the engine
    sends the table name for Data Plane and Graph (port of validateService's
    local check)."""
    # AzureDiagnostics is the generic data-plane diagnostic table — the
    # dynamic-routing fallback for any indexed resource with no resource-specific
    # table. It's a real Log Analytics table, so the service gate passes it
    # locally instead of spending an LLM verifier call on it.
    if platform_id == "dataplane" and service == "AzureDiagnostics":
        return True
    try:
        platform = get_platform(platform_id)
    except KeyError:
        return False
    for s in platform.services:
        if isinstance(s, str):
            if s == service:
                return True
        elif s.table == service or s.label == service:
            return True
    return _in_catalog(service)


def _in_catalog(service: str) -> bool:
    """Does the Azure Monitor supported-logs index know this name?

    A service the built-in list has never heard of used to fall through to a
    VERIFIER AGENT — a model asked "is this a real cloud service? YES/NO". That
    was the only available answer when the index held 47 resource types; it now
    holds 212, so the question can be looked up instead of guessed at. "Azure
    Bastion" passed the model gate and then generated against nothing, because
    passing that gate never meant the catalog could ground it.

    Import is local: prompts is imported by the catalog's own consumers, and a
    module-level import here closes a cycle.
    """
    try:
        from ..catalog import resolve_resource
    except ImportError:  # pragma: no cover - catalog is part of the package
        return False
    return bool(resolve_resource(service))
