"""Which techniques each table can detect, read from the tenant.

Built by scanning the target workspace's own rule templates rather than
shipped as a file. Every template carries both a KQL query and the MITRE
techniques it detects, so the pair (tables the query reads, techniques it
claims) IS the index -- authored by Microsoft, free to read, and already in
the tenant.

It must be scanned rather than baked in because the template set is a
function of which Content Hub solutions are installed. A tenant with two
solutions has a thin index and a tenant with forty has a thick one, and an
index built elsewhere would silently claim coverage for content this
workspace does not have.

That makes the index's own thinness a fact worth reporting: a technique
absent from it is not a technique nothing can detect, it is a technique no
INSTALLED template mentions. Those read differently and `coverage` says which
this is.
"""

from __future__ import annotations

import collections
import json
import re

from . import apiversions
from . import azcli

API = apiversions.SENTINEL


def _az_json(url: str) -> dict | None:
    p = azcli.run(["rest", "--method", "get", "--url", url, "-o", "json"],
                  timeout=azcli.CONTROL_TIMEOUT)
    return json.loads(p.stdout) if p.returncode == 0 else None


def required_data_types(props: dict,
                        known_tables: set[str] | None = None
                        ) -> tuple[set[str], set[str]]:
    """(tables the template needs, declared names that are not tables).

    `requiredDataConnectors.dataTypes` is MOSTLY table names and not reliably
    so, which is the trap this function exists to close. Across the 477
    templates in this tenant, 18 of 57 distinct declared names are not tables
    in the workspace schema at all:

        SecurityEvents  36 templates   a CONNECTOR id; the table is SecurityEvent
        KeyVaultData     4 templates   not a table; those rules read AzureDiagnostics
        Corelight_CL    25 templates   a real table, for a product not deployed here

    Comparing those against a table list as though they were tables is how a
    filter disqualifies content for a table that cannot exist. `SecurityEvents`
    alone would wrongly drop 36 templates in any tenant that has Security
    Events flowing.

    So each name is resolved against the workspace's own table list, tolerating
    the two ways Microsoft's label drifts from the table: the product qualifier
    ("SecurityAlert (MDATP)") and the connector plural ("SecurityEvents"). What
    still does not resolve is returned SEPARATELY rather than being treated as
    an absent table, because those are two different facts -- "this workspace
    produces no Corelight_CL" and "this name was never a table" -- and only the
    first is a statement about the tenant.

    An empty first set means the template declared nothing, which is NOT the
    same as declaring no dependency: 53 of the 477 here are in that state, and
    a caller must decide what to do about them.
    """
    known = known_tables or set()
    lower = {t.lower(): t for t in known}
    resolved, unresolved = set(), set()
    for connector in props.get("requiredDataConnectors") or []:
        for name in connector.get("dataTypes") or []:
            bare = re.sub(r"\s*\(.*\)\s*$", "", name).strip()
            if not bare:
                continue
            if bare in known:
                resolved.add(bare)
            elif bare.lower() in lower:
                resolved.add(lower[bare.lower()])
            elif bare.endswith("s") and bare[:-1].lower() in lower:
                # The connector is named for the stream, the table for the row:
                # SecurityEvents -> SecurityEvent.
                resolved.add(lower[bare[:-1].lower()])
            else:
                unresolved.add(bare)
    return resolved, unresolved


def probe(workspace_arm_id: str, known_tables: set[str],
          tables_in) -> tuple[dict[str, list[str]], list[dict], dict]:
    """({table: [technique ids]}, usable templates, read state).

    `tables_in` is injected rather than imported so the same KQL-to-tables
    routine serves the rules leg and this one -- two parsers would drift and
    the index would disagree with the rule inventory about what a query reads.
    """
    url = (f"https://management.azure.com{workspace_arm_id}/providers/"
           f"Microsoft.SecurityInsights/alertRuleTemplates?api-version={API}")
    templates, pages = [], 0
    while url:
        payload = _az_json(url)
        if payload is None:
            return {}, [], {"ran": False,
                            "detail": f"could not read rule templates after {pages} page(s)"}
        templates.extend(payload.get("value", []))
        url = payload.get("nextLink")
        pages += 1

    index: dict[str, set[str]] = collections.defaultdict(set)
    catalogue: list[dict] = []
    usable = unresolved = 0
    # Declared dependency names that are not tables in this workspace.
    # Reported rather than swallowed: they are the seam where Microsoft's
    # connector vocabulary and the table schema disagree.
    unresolved_names: set[str] = set()
    for t in templates:
        props = t.get("properties") or {}
        query, techs = props.get("query"), props.get("techniques") or []
        if not query or not techs:
            continue
        found = tables_in(query, known_tables)
        if not found:
            # The template reads a table this workspace does not define, so
            # nothing here can say what it would detect. Counted, not dropped.
            unresolved += 1
            continue
        usable += 1
        needs, unknown = required_data_types(props, known_tables)
        unresolved_names.update(unknown)
        catalogue.append({
            "template_id": t.get("name"),
            "display_name": props.get("displayName") or "",
            "severity": props.get("severity"),
            # Microsoft's sentence about what it detects. Present on all
            # 477 templates, and the only field that distinguishes a rule
            # watching activity ON a resource from one watching the
            # CREATION of it -- which is what decides applicability when
            # the tables alone cannot.
            "description": (props.get("description") or "").strip(),
            # How many ACTIVE rules exist in this workspace that were created
            # from this template. Installing a solution does not switch its
            # rules on -- each one is created by hand from Analytics > Rule
            # templates -- so this is the difference between content being
            # available and content running.
            "active_rules": props.get("alertRulesCreatedByTemplateCount") or 0,
            "techniques": sorted(techs),
            "tables": found,
            # What the template DECLARES it needs, which is a different and
            # better fact than what a query-text scan can find. `tables` above
            # is what this workspace could resolve; a table the workspace does
            # not define is invisible to it, so a template that reads
            # AWSCloudTrail and SigninLogs looks like it reads only SigninLogs.
            # That is how a detection for a workload nobody runs ends up
            # recommended. Microsoft states the dependency instead.
            "required_data_types": sorted(needs),
            # Declared names that are not tables here. Carried rather than
            # folded into the line above so a consumer can tell "this tenant
            # produces no such table" from "this was never a table name".
            "unresolved_data_types": sorted(unknown),
            # {connectorId: [data types it delivers]}, verbatim. Carried so the
            # Content Hub leg can learn the connector vocabulary from what this
            # workspace actually declares, instead of a second fetch or a
            # shipped map that would claim connectors nobody here has.
            "required_connectors": {
                c.get("connectorId"): sorted(
                    {re.sub(r"\s*\(.*\)\s*$", "", d).strip()
                     for d in (c.get("dataTypes") or [])})
                for c in (props.get("requiredDataConnectors") or [])
                if c.get("connectorId")},
        })
        for table in found:
            index[table].update(techs)

    out = {table: sorted(techs) for table, techs in index.items()}
    all_techs = {tech for techs in out.values() for tech in techs}
    detail = (f"{len(templates)} template(s) across {pages} page(s); "
              f"{usable} mapped {len(all_techs)} technique(s) onto {len(out)} table(s); "
              f"{unresolved} referenced tables this workspace does not define. "
              + (f"{len(unresolved_names)} declared dependency name(s) resolve to no "
                 f"table here and are recorded apart from empty tables: "
                 f"{', '.join(sorted(unresolved_names)[:6])}. " if unresolved_names else "")
              + "The index is only as broad as the installed Content Hub solutions.")
    return out, catalogue, {"ran": True, "detail": detail}


def techniques_for(index: dict[str, list[str]], tables: list[str]) -> set[str]:
    """Every technique the given tables could detect."""
    out: set[str] = set()
    for table in tables:
        out.update(index.get(table, []))
    return out
