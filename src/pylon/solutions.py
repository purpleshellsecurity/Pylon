"""What each Content Hub solution collects from, and whether this tenant has it.

The one thing Microsoft does not publish. `contentPackages`,
`contentProductPackages`, `contentProductTemplates` and the data-connector
definitions were all read looking for it: a connector states its TABLES
(`AZFWApplicationRule`, `AZFWNetworkRule`) and its prose, and never the ARM
type it collects from. Without that link the recommendation leg told a tenant
with no firewall to connect its firewall logs, and -- worse, when the link was
faked out of `coverage_gaps` -- told a tenant with a key vault to remove the
Key Vault solution.

So the map is authored, and it is authored in two halves because a solution
attaches to this tenant in two different ways.

`service_catalog/` is vendored from Pylon, which maintains one file per Azure
service against Microsoft's own logging documentation. Each carries the ARM
type, the service's display name (which matches the Content Hub solution's),
and per-table `schema_mode`. That last field earns its place on its own: a key
vault logging to `AZKVAuditLogs` in resource-specific mode does not fill
`AzureDiagnostics`, which is what the Key Vault solution's rules read, and the
symptom of that is indistinguishable from a vault that is not logging at all.

`NON_RESOURCE` covers what a service file cannot: Defender for Endpoint is a
licence, Entra ID is the tenant, Windows Security Events is an agent on a VM.
Each entry names a test against something this scan ALREADY measures -- a
Defender plan, an XDR family row, a device census, a table -- so the answer is
a measurement and never an assertion that the product is probably there.

The honest limit: matching is on display name. Microsoft renames solutions
(`Azure Active Directory` became `Microsoft Entra ID`), and a rename shows up
here as an unmatched solution, which reports as unknown rather than as absent.
That is the safe direction, and `unmatched` in the read state is the number to
watch.
"""

from __future__ import annotations

import glob
import json
import os

# Pylon's per-service files, which arrived with the generation half. They were
# briefly vendored to a second directory here; that copy was byte-identical and
# has been dropped, because two copies of a catalogue is how one of them goes
# stale without anyone noticing.
CATALOGUE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "catalog", "service_files")

# Solutions whose presence is not an ARM resource. Each names a test against a
# measurement this scan already takes, and the kind says which input answers it:
#
#   tenant     always true; the directory exists or there is no tenant
#   xdr        an XDR family row in the inventory, from scopes.xdr_families
#   plan       a Microsoft Defender for Cloud plan, from defender_plans.json
#   devices    onboarded devices, from the endpoint census
#   table      the presence of data in a table, which the caller already has
NON_RESOURCE: dict[str, dict] = {
    "Microsoft Entra ID": {"kind": "tenant", "what": "the Entra ID directory"},
    "Microsoft Entra ID Protection": {
        "kind": "xdr", "key": "identity", "what": "the Identity XDR family"},
    "Microsoft Defender XDR": {
        "kind": "xdr", "key": "alerts", "what": "Defender XDR"},
    "Microsoft Defender for Endpoint": {
        "kind": "xdr", "key": "endpoint", "what": "Defender for Endpoint"},
    "Microsoft Defender for Office 365": {
        "kind": "xdr", "key": "email", "what": "Defender for Office 365"},
    "Microsoft Defender for Cloud Apps": {
        "kind": "xdr", "key": "cloudapps", "what": "Defender for Cloud Apps"},
    "Microsoft Defender for Identity": {
        "kind": "xdr", "key": "identity", "what": "Defender for Identity"},
    # Deliberately NOT keyed to a single plan. An earlier version tested
    # Defender for Cloud against `CloudPosture` and Defender for IoT against
    # `IoT`, both of which are off here, and told the tenant to remove two
    # solutions that are delivering SecurityAlert data right now. A product
    # with many sub-plans is present if ANY of them is on.
    "Microsoft Defender for Cloud": {
        "kind": "any_plan", "what": "a Microsoft Defender for Cloud plan"},
    # A product that runs ON other resources rather than being one. The
    # harvested service files are keyed one per resource type, so a name match
    # can only ever find a solution whose product IS a resource type -- and
    # Azure WAF is not one. Microsoft: "Azure Web Application Firewall can be
    # deployed with these Microsoft services: Azure Application Gateway, Azure
    # Application Gateway for Containers, Azure Front Door, Azure Content
    # Delivery Network."
    #
    # Measured on a live tenant before this existed: the row said "connect
    # data" and named diagnostic categories, on the strength of 11 resources
    # that share nothing with a web application firewall except writing to
    # AzureDiagnostics. Azure Firewall, one row above it, correctly said
    # "nothing here to collect from" -- because it IS a resource type and had
    # a test.
    "Azure Web Application Firewall": {
        "kind": "resources",
        "types": ("microsoft.network/applicationgateways",
                  "microsoft.servicenetworking/trafficcontrollers",
                  "microsoft.network/frontdoors",
                  "microsoft.cdn/profiles"),
        "what": "Application Gateway, Front Door or CDN profile"},
    "Microsoft Defender for IoT": {
        "kind": "any_plan", "what": "a Microsoft Defender for Cloud plan"},
    "Microsoft Defender Threat Intelligence": {
        "kind": "table", "key": "ThreatIntelligenceIndicator",
        "what": "a threat intelligence feed"},
    "Threat Intelligence (NEW)": {
        "kind": "table", "key": "ThreatIntelligenceIndicator",
        "what": "a threat intelligence feed"},
    "Windows Security Events": {
        "kind": "devices", "what": "a Windows machine sending security events"},
    "Windows Forwarded Events": {
        "kind": "devices", "what": "a Windows machine forwarding events"},
    "Windows Firewall": {
        "kind": "devices", "what": "a Windows machine"},
    "Microsoft Sysmon For Linux": {
        "kind": "devices", "what": "a Linux machine running Sysmon"},
    "Microsoft 365": {
        "kind": "table", "key": "OfficeActivity", "what": "Microsoft 365 audit"},
    # The Essentials packs and Web Shells are cross-cutting content rather than
    # a product: they ship rules over tables other solutions fill. Their
    # presence test is the tables their own rules read, which `contenthub`
    # already computes, so they are deliberately NOT listed here. Adding them
    # with a made-up product would be the naming-as-evidence mistake this
    # module exists to avoid.
}


def _key(name: str) -> str:
    """A solution name and a service name, reduced to the same thing.

    Microsoft names the same service differently in two places: the Content Hub
    solution is `Azure Network Security Groups`, the service documentation is
    `Network Security Groups`. An exact match missed that, the presence test
    silently did not run, and the row fell through to a guess and told a tenant
    with four NSGs to connect a data source.

    Only the leading `Azure` and case are normalised. Nothing fuzzier: a match
    that is nearly right here produces advice about the wrong product.
    """
    n = " ".join((name or "").split()).lower()
    return n[6:] if n.startswith("azure ") else n


def load() -> dict[str, dict]:
    """{normalised service name: {resource_type, tables, schema modes}}."""
    out: dict[str, dict] = {}
    for path in glob.glob(os.path.join(CATALOGUE_DIR, "*.json")):
        if os.path.basename(path) == "_index.json":
            continue
        try:
            with open(path) as handle:
                doc = json.load(handle)
        except (OSError, ValueError):
            continue
        name = doc.get("service_name")
        if not name:
            continue
        tables = doc.get("tables") or {}
        out[_key(name)] = {
            "service_name": name,
            "resource_type": (doc.get("resource_type") or "").lower(),
            # The diagnostic categories Azure offers on this resource type.
            # What a reader has to go and tick, so it belongs on the row.
            "categories": list(doc.get("resource_log_categories") or []),
            "tables": sorted(tables),
            # {table: resource-specific | azure-diagnostics}. The mismatch this
            # detects is real and silent: a resource logging in one mode fills
            # a table the other mode's rules never read.
            "schema_mode": {t: (v or {}).get("schema_mode")
                            for t, v in tables.items()},
        }
    return out


def presence(name: str, catalogue: dict[str, dict], resource_types,
             live_tables: set[str], xdr: set[str], plans: set[str],
             devices: int) -> tuple[bool | None, str]:
    """(does this tenant have what the solution collects from, why).

    `None` means unmatched, which is NOT absent. A solution this map has never
    heard of has to report unknown, because the alternative is a report that
    recommends removing content for a product it simply failed to look up.
    """
    entry = catalogue.get(_key(name))
    if entry and entry["resource_type"]:
        arm = entry["resource_type"]
        n = sum(count for t, count in resource_types.items() if t == arm)
        return bool(n), (f"{n} {arm}" if n else f"no {arm} in this tenant")

    rule = NON_RESOURCE.get(name)
    if not rule:
        return None, "this scan has no presence test for this solution"
    kind, what = rule["kind"], rule["what"]
    if kind == "tenant":
        return True, what
    if kind == "xdr":
        return (rule["key"] in xdr), (what + (" is connected" if rule["key"] in xdr
                                              else " is not connected"))
    if kind == "plan":
        return (rule["key"] in plans), (what + (" is on" if rule["key"] in plans
                                                else " is off"))
    if kind == "any_plan":
        return bool(plans), (f"{len(plans)} Defender plan(s) on" if plans
                             else "no Defender for Cloud plan is on")
    if kind == "devices":
        return bool(devices), (f"{devices} onboarded device(s)" if devices
                               else "no onboarded devices")
    if kind == "resources":
        # ANY of them. A product that runs on several host types is present if
        # one is here. Name what was FOUND rather than the whole list of places
        # it could have been: a reader with two Application Gateways does not
        # need to be told about Front Door.
        found = {t: n for t, n in resource_types.items()
                 if t in rule["types"] and n}
        n = sum(found.values())
        if not n:
            return False, f"no {what} in this tenant"
        kinds = ", ".join(sorted(t.split("/")[-1] for t in found))
        return True, f"{n} {kinds}"
    if kind == "table":
        on = rule["key"] in live_tables
        return on, (f"{what} is arriving" if on else f"{what} is not arriving")
    return None, "this scan has no presence test for this solution"


def mode_mismatch(name: str, catalogue: dict[str, dict],
                  needs: list[str]) -> str | None:
    """Why a resource can be logging and the solution still see nothing.

    Azure writes a resource's logs either into the shared `AzureDiagnostics`
    table or into a dedicated one, and which it does is a per-resource setting.
    A key vault in resource-specific mode fills `AZKVAuditLogs`; the Key Vault
    solution's rules read `AzureDiagnostics`; both are configured correctly and
    nothing fires. Nothing else in this scan can tell that apart from a vault
    with no diagnostic setting at all.
    """
    entry = catalogue.get(_key(name))
    if not entry:
        return None
    dedicated = [t for t, mode in entry["schema_mode"].items()
                 if mode == "resource-specific"]
    if not dedicated or not needs:
        return None
    if "AzureDiagnostics" in needs and not set(needs) & set(dedicated):
        return (f"its content reads AzureDiagnostics, but this service logs to "
                f"{', '.join(dedicated[:2])} in resource-specific mode")
    return None
