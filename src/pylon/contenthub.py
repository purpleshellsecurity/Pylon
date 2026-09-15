"""What to turn on in Content Hub, and what is already on and doing nothing.

This replaces the template-level recommendation, which asked the wrong
question. That leg emitted one row per Microsoft rule template whose tables
held data, and table names are shared: `Event` holding 963 MB from one Windows
host passed every AD FS and domain-controller template, `OfficeActivity`
holding 0.32 MB passed every Teams and SharePoint one. Filtering it harder
made it shorter without making it a decision -- 119 rows became 72, and 72
templates covering 37 techniques is still not something anyone can act on.

The unit here is the SOLUTION, because that is the unit Content Hub installs
and the unit an operator turns on. Three questions, in the order they get
asked:

    aligned      does this solution match what the tenant actually runs
    installed    is it here, at what version, and is that current
    working      is its connector delivering, or is it installed and dark

The last one is the finding this leg exists to surface, and it is the inverse
of a recommendation. A solution installed with an unfed connector contributes
rule templates to the index that `techniques.py` reads, none of which can
fire. It inflates the apparent library and detects nothing. Eight of the 31
solutions in this tenant are in that state.

Alignment resolves from measurement, never from a name:

    1. the connector's declared data types, if any hold data       -> fed
    2. the connector's declared data types, if none hold data      -> unfed
    3. no connector declared: the tables its own content reads     -> fed / unfed
    4. neither                                                      -> unknown

Step 3 matters because 12 of the 31 installed solutions declare no data
connector at all. Reading their content's tables answers the same question
without a hand-maintained map from a solution name to an Azure service, which
would go stale the first time Microsoft renamed one.
"""

from __future__ import annotations

import collections
import json
import re

from . import apiversions
from . import azcli
from . import solutions

API = apiversions.SENTINEL


def _az_json(url: str) -> dict | None:
    p = azcli.run(["rest", "--method", "get", "--url", url, "-o", "json"],
                  timeout=azcli.CONTROL_TIMEOUT)
    return json.loads(p.stdout) if p.returncode == 0 else None


def _paged(workspace_arm_id: str, endpoint: str) -> list[dict] | None:
    url = (f"https://management.azure.com{workspace_arm_id}/providers/"
           f"Microsoft.SecurityInsights/{endpoint}?api-version={API}")
    out: list[dict] = []
    while url:
        payload = _az_json(url)
        if payload is None:
            return None
        out.extend(payload.get("value", []))
        url = payload.get("nextLink")
    return out


def template_bodies(workspace_arm_id: str,
                    names: list[str]) -> dict[str, dict]:
    """{template name: its analytics-rule properties}, for every name given.

    Concurrent because the cost is `az rest` start-up, not the tenant. Measured
    sequentially against a live tenant: 0.72s each, so 306 templates is three
    minutes forty. Eight at a time brings that to roughly half a minute, which
    is what makes reading ALL of them affordable -- and reading all of them is
    the point, because the alternative was leaving most solutions resolved by a
    connector map built from the wrong list.

    A template that cannot be read is simply absent from the result. The caller
    counts what it got and says so rather than treating a failed read as an
    empty rule.
    """
    from concurrent.futures import ThreadPoolExecutor

    if not names:
        return {}
    out: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for name, props in zip(names, pool.map(
                lambda n: template_body(workspace_arm_id, n), names)):
            if props is not None:
                out[name] = props
    return out


def template_body(workspace_arm_id: str, name: str) -> dict | None:
    """The analytics-rule properties inside one contentTemplate, or None.

    The LIST call strips `mainTemplate`, so the query only arrives on a GET of
    a single template. Measured against a live tenant: 20 of 20 returned a
    populated body, at 0.72s each -- most of that `az rest` start-up rather
    than network, which is why the caller fetches lazily instead of walking all
    306 up front. That would be three minutes forty on a command that takes a
    few, spent almost entirely on solutions that already resolve.
    """
    url = (f"https://management.azure.com{workspace_arm_id}/providers/"
           f"Microsoft.SecurityInsights/contentTemplates/{name}?api-version={API}")
    payload = _az_json(url)
    if payload is None:
        return None
    resources = (((payload.get("properties") or {}).get("mainTemplate") or {})
                 .get("resources") or [])
    for r in resources:
        if "alertrule" in str(r.get("type", "")).lower():
            return r.get("properties") or {}
    return None


def template_data_types(props: dict) -> set[str]:
    """The tables one rule template declares it needs.

    `requiredDataConnectors` is on the template body itself -- the same field
    `techniques.required_data_types` digs out of the other API -- so nothing
    has to be inferred from the query text here.
    """
    out: set[str] = set()
    for c in (props.get("requiredDataConnectors") or []):
        out.update(_bare(d) for d in (c.get("dataTypes") or []) if d)
    return out


def _bare(name: str) -> str:
    """`SecurityAlert (MDATP)` -> `SecurityAlert`. See techniques.required_data_types."""
    return re.sub(r"\s*\(.*\)\s*$", "", name).strip()


def connector_map(catalogue: list[dict]) -> dict[str, set[str]]:
    """{connectorId: data types it delivers}, learned from the catalogue.

    Built from what this workspace's own templates declare rather than from a
    shipped file, for the same reason the technique index is: a map authored
    elsewhere would claim connectors nobody here has. It is therefore only as
    broad as the installed solutions, which is why a package whose connector is
    absent from it resolves to `unknown` and not to `unfed`.
    """
    out: dict[str, set[str]] = collections.defaultdict(set)
    for tpl in catalogue:
        for cid, types in (tpl.get("required_connectors") or {}).items():
            out[cid].update(t for t in types if t)
    return out


def emitters(coverage_gaps: list[dict], resources: list[dict]
             ) -> dict[str, dict]:
    """{table: what in THIS tenant would emit it}.

    Measured, not mapped. `coverage_gaps` already records, per resource, the
    table it should be sending and whether it is -- so the inverse of that is
    "which resources would fill this table", which is the join the Content Hub
    leg was missing. Without it the report told a tenant with no firewall to
    connect its firewall logs.

    `ships_elsewhere` matters as much as the count. A VNet flow log with no
    Traffic Analytics is working correctly and still reaches no workspace, so
    the instruction is "repoint it", not "switch it on".
    """
    by_id = {r["resource_id"]: r for r in resources}
    out: dict[str, dict] = {}
    for g in coverage_gaps:
        rec = out.setdefault(g["expected_table"],
                             {"resources": set(), "types": set(),
                              "categories": set(), "ships_elsewhere": 0,
                              "never_configured": 0})
        rec["resources"].add(g["resource_id"])
        r = by_id.get(g["resource_id"])
        if r:
            rec["types"].add(r["resource_type"])
        rec["categories"].update(g.get("categories_to_enable") or [])
        reason = (g.get("dark_reason") or "").lower()
        if "elsewhere" in reason:
            rec["ships_elsewhere"] += 1
        elif not g.get("is_logging"):
            rec["never_configured"] += 1
    return out


def _unfed(needed: list[str], emits: dict[str, dict],
           live_tables: frozenset[str] | set[str] = frozenset()) -> tuple[str, str]:
    """Why a solution's tables are empty, and whose problem that is.

    `emits` is built from `coverage_gaps`, which only records resources with a
    DIAGNOSTIC SETTING to assess. It knows 14 tables in this tenant and knows
    nothing about agent-collected ones (`SecurityEvent`, `Syslog`, `Event`),
    connector-filled ones (`ThreatIntelligenceIndicator`) or product ones.

    So a table missing from it means NOT MEASURED, never "nothing emits it".
    An earlier version of this function read absence as absence of a source and
    told a tenant with a key vault to remove the Key Vault solution. That is
    the same mistake `tables_in` made against the workspace table list: an
    intersection with a partial list, with the miss reported as a negative
    fact.
    """
    known = [t for t in needed if t in emits]
    if not known:
        names = ", ".join(needed[:2])
        # Two facts, and this reported neither. `live_tables` is every table the
        # usage meter saw inside the window, and by the time a caller reaches
        # here none of `needed` is in it -- the row would have resolved as fed
        # otherwise. So the table received nothing, which is a MEASUREMENT
        # already in hand, and it was being discarded in favour of "never
        # established" on rows an operator knew perfectly well were switched off.
        #
        # A non-empty set proves the read ran. An empty one is a failed read and
        # a workspace with no tables wearing the same clothes, so the weaker
        # sentence stands there. That is the distinction, not a hedge.
        #
        # Two names instead of one "unknown", so the sentence that follows is
        # chosen on a value rather than by matching a prefix of this string.
        if live_tables:
            # Was three clauses. The middle one explained which internal map
            # cannot answer the second question, which is a fact about Pylon
            # and not about the tenant -- and it repeated on every such row.
            # A row says what was found and what to do; the reasoning lives in
            # this module, where the next person to change it will look.
            return "unseen", f"{names} received nothing in the window"
        return "unmeasured", (f"nothing here was measured for {names}, so "
                              "whether this tenant produces it was never "
                              "established")
    best = max(known, key=lambda t: len(emits[t]["resources"]))
    rec = emits[best]
    n, types = len(rec["resources"]), sorted(rec["types"])
    # A shared table has many emitters and naming one of them is a fabrication:
    # AzureDiagnostics is filled by automation accounts, NSGs, public IPs and
    # Cognitive Services here, and calling it "9 automation accounts" told the
    # Azure Firewall row something about automation accounts.
    who = (f"{n} resource(s) across {len(types)} type(s)" if len(types) > 1
           else f"{n} {types[0].split('/')[-1] if types else 'resource'}")
    if rec["ships_elsewhere"] and not rec["never_configured"]:
        return "repoint", (f"{who} already produces {best} and ships it "
                           "somewhere other than this workspace")
    cats = sorted(rec["categories"])[:2]
    # No terminal period. Every one of the six places this lands embeds it
    # mid-sentence or ends the sentence itself, and a clause that punctuates
    # itself is wrong in both. It read "...switch on Audit, AuditEvent., so its
    # rule templates sit in the library" on a live run -- a full stop inside a
    # subordinate clause -- and produced ".." on the update and current rows.
    return "unfed", (f"{who} would emit {best} and none is sending it"
                     + (f"; switch on {', '.join(cats)}" if cats else ""))


# How many category names a piece of advice may recite before the count is the
# more useful sentence. Three read as the whole job when there were 53.
CATEGORIES_IN_A_SENTENCE = 3


def switch_on(cats: list[str]) -> str:
    """What to tick, for a solution whose logs are not arriving.

    `cats` is every diagnostic category the resource type offers, sorted
    alphabetically. This said `", ".join(cats[:3])` -- an instruction naming an
    arbitrary prefix of the alphabet. Twenty-four of the 48 catalogue entries
    have more than three categories and Azure Databricks has 53, so on half of
    them the sentence was wrong and the rest of the list appeared nowhere.

    `report.headline` names every category in its equivalent sentence, and that
    is right there: it renders at most three steps. This renders on every
    installed solution, so the count carries the sentence, three are an example
    said to be one, and the whole list rides on the row as
    `categories_to_enable`.
    """
    if len(cats) <= CATEGORIES_IN_A_SENTENCE:
        what = ", ".join(cats)
    else:
        what = (f"the {len(cats)} diagnostic categories it offers, including "
                + ", ".join(cats[:CATEGORIES_IN_A_SENTENCE]))
    return f"Switch on {what}, and point the diagnostic setting at this workspace."


def build(workspace_arm_id: str, live_tables: set[str],
          templates: list[dict], coverage_gaps: list[dict] | None = None,
          resources: list[dict] | None = None,
          defender_plans: list[dict] | None = None,
          devices: int = 0) -> tuple[list[dict], dict]:
    """(Solution rows, read state).

    `templates` is the distilled rule-template catalogue from `techniques`,
    used ONLY to learn the connector vocabulary. Named apart from the Content
    Hub package catalogue below, which is a different list entirely.
    """
    installed = _paged(workspace_arm_id, "contentPackages")
    packages = _paged(workspace_arm_id, "contentProductPackages")
    content = _paged(workspace_arm_id, "contentTemplates")
    if installed is None or packages is None:
        return [], {"ran": False, "detail": "could not read Content Hub packages"}

    conn = connector_map(templates)
    emits = emitters(coverage_gaps or [], resources or [])
    # What each solution collects from, and whether this tenant has it. The one
    # link Microsoft publishes nowhere; see solutions.py.
    catalog = solutions.load()
    have_types = collections.Counter((r.get("resource_type") or "").lower()
                                     for r in (resources or []))
    xdr = {(r.get("resource_type") or "").rsplit("/", 1)[-1].lower()
           for r in (resources or [])
           if "xdrfamilies" in (r.get("resource_type") or "")}
    plans_on = {p.get("plan") for p in (defender_plans or []) if p.get("enabled")}
    unmatched = 0
    fetched = 0
    cat = {(p.get("properties") or {}).get("contentId"): p["properties"]
           for p in packages}
    # What each installed solution ships, and which tables that content reads.
    ships: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    rule_names: dict[str, list[str]] = collections.defaultdict(list)
    # The GET key for each of a solution's rule templates, by package. This is
    # the join, and it is not a join: `packageId` is on the list response, so a
    # solution's rules are the templates that say they belong to it. Nothing is
    # matched by name or by id against a second list.
    rule_ids: dict[str, list[str]] = collections.defaultdict(list)
    for item in content or []:
        pr = item.get("properties") or {}
        ships[pr.get("packageId")][pr.get("contentKind")] += 1
        if pr.get("contentKind") == "AnalyticsRule":
            rule_names[pr.get("packageId")].append((pr.get("displayName") or "").strip())
            if item.get("name"):
                rule_ids[pr.get("packageId")].append(item["name"])

    # Every installed solution's rule templates, read once. This is the source
    # of truth for what a solution needs, and it replaces two uses of the
    # `alertRuleTemplates` gallery: the per-solution tables AND the connector
    # map. Measured on a live tenant, that gallery holds 477 templates against
    # 306 installed here and overlaps on 161 by name -- fewer than half -- so
    # anything resting on it was resting on a list that does not carry most
    # Content Hub content.
    bodies = template_bodies(workspace_arm_id,
                             [n for ids in rule_ids.values() for n in ids])

    # {connectorId: data types it delivers}, from the templates THIS tenant has
    # installed rather than from the gallery. Same field, right list.
    conn = collections.defaultdict(set, {k: set(v) for k, v in conn.items()})
    for props in bodies.values():
        for c in (props.get("requiredDataConnectors") or []):
            cid_ = c.get("connectorId")
            if cid_:
                conn[cid_].update(_bare(d) for d in (c.get("dataTypes") or []) if d)

    # `by_name` survives for ONE job: how many rules a solution has switched on.
    # That count lives on the distilled catalogue and nowhere else.
    by_name = {(t.get("display_name") or "").strip(): t for t in templates}

    def enabled_of(cid: str) -> int:
        """Active rules created from this solution's templates."""
        return sum((by_name.get(n) or {}).get("active_rules") or 0
                   for n in (rule_names.get(cid) or []))

    def tables_of(cid: str) -> tuple[set[str], int, int]:
        """(tables its rules read, rules it ships, rules this scan could read).

        Reads each of the solution's own templates. This used to join the
        installed content against `alertRuleTemplates` on display name, and that
        was the wrong list: measured on a live tenant, 306 installed rule
        templates against 477 in that gallery, overlapping on 161 by name and
        126 by id. Fewer than half. `alertRuleTemplates` is the older built-in
        gallery and does not carry most Content Hub solution content, so no
        amount of better matching could have found it -- the query is in the
        contentTemplate itself.

        Called only where a solution's connector did not resolve, because each
        template costs a round trip.
        """
        ids = rule_ids.get(cid) or []
        n_rules = len(rule_names.get(cid) or [])
        tabs, read = set(), 0
        for name in ids:
            props = bodies.get(name)
            if props is None:
                continue
            read += 1
            tabs.update(template_data_types(props))
        return tabs, n_rules, read

    def declared(props: dict) -> list[str]:
        criteria = (props.get("dependencies") or {}).get("criteria") or []
        return [c.get("contentId") for c in criteria
                if c.get("kind") == "DataConnector"]

    rows, tally = [], collections.Counter()
    for pkg in installed:
        pr = pkg.get("properties") or {}
        cid = pr.get("contentId")
        c = cat.get(cid) or {}
        types = {t for k in (declared(pr) or declared(c)) for t in conn.get(k, ())}
        fed = sorted(t for t in types if t in live_tables)

        name = pr.get("displayName") or cid
        present, why_present = solutions.presence(
            name, catalog, have_types, live_tables, xdr, plans_on, devices)
        if present is None:
            unmatched += 1
        n_enabled = enabled_of(cid)
        # How many analytics rules this solution SHIPS, which is the denominator
        # the enablement verdict is judged against.
        ships_rules = ships.get(cid, collections.Counter()).get("AnalyticsRule", 0)
        # Read for EVERY solution, not only the ones the connector map could
        # not resolve. Fetching on demand was the wrong shape: the connector map
        # is itself built from the gallery that is missing half this tenant's
        # content, so falling back to the good source only for the leftovers
        # left the majority resting on the bad one.
        own_tables, n_rules, read = tables_of(cid)
        fetched += read
        own_fed = sorted(t for t in own_tables if t in live_tables)

        if types and fed:
            alignment = "fed"
            evidence = f"its connector delivers {', '.join(fed[:2])}, which holds data"
        elif types:
            alignment, evidence = _unfed(sorted(types), emits, live_tables)
        elif own_tables and own_fed:
            # The connector was not resolvable, but its own rules name tables and
            # some hold data. That answers the same question one step further out.
            alignment = "fed"
            evidence = (f"its detections read {', '.join(own_fed[:2])}, "
                        "which holds data")
        elif own_tables:
            alignment, evidence = _unfed(sorted(own_tables), emits, live_tables)
        elif n_rules == 0:
            # Nothing to switch on. The solution ships workbooks, playbooks,
            # hunting queries or a connector definition and no analytics rules,
            # so there is no detection here to be dark.
            alignment = "no_rules"
            other = ", ".join(f"{n} {k.lower()}" for k, n in
                              sorted(ships.get(cid, collections.Counter()).items())
                              if k != "AnalyticsRule")
            evidence = ("it ships no analytics rules at all"
                        + (f", only {other}" if other else ""))
        else:
            alignment = "unmatched"
            evidence = (f"none of its {n_rules} rule template(s) could be read "
                        "from the Content Hub")

        # `presence` has three answers and two of them were printing the same
        # confident sentence. True means the resource was found here. False means
        # it was looked for and is not here. None means this scan has no test for
        # this solution and never looked -- there are 64 tests against a Content
        # Hub catalogue many times that size, so None is common, not exotic.
        #
        # Measured on a live run: the Azure Web Application Firewall solution has
        # no presence test, so presence returned None, both `present is False`
        # branches were skipped, and the row was decided on table data alone. It
        # said "connect data" and named diagnostic categories, on the strength of
        # 11 resources that share nothing with a web application firewall except
        # writing to AzureDiagnostics -- a table this file's own comments note is
        # filled here by automation accounts, NSGs, public IPs and Cognitive
        # Services. Telling someone to switch on logging for a product they may
        # not run is the "could not look" reported as "looked" that the rest of
        # this codebase refuses to do.
        #
        # Empty when presence WAS established, so a row that knows says nothing.
        unverified = ("" if present is not None else
                      " This scan has no presence test for this solution, so "
                      "whether this tenant runs the product at all was not "
                      "established; if it does not, uninstall it rather than "
                      "connecting anything.")

        version, available = pr.get("version"), c.get("version")
        behind = bool(available and version and available != version)
        deprecated = bool(c.get("isDeprecated"))
        newer = f" A newer version is published: {version} installed, {available} available."

        # ONE sentence per row. The verdict and the evidence for it used to be
        # separate fields rendered on separate lines, which read as two
        # unrelated claims stacked on top of each other. They are one argument.
        if n_rules == 0:
            # Keyed on the RULE COUNT, not on how alignment resolved. An earlier
            # version tested `alignment == "no_rules"`, which never fired for a
            # solution that declares a connector -- `Azure Network Security
            # Groups` declares `AzureNSG`, resolved to unfed, and was told to
            # connect a log source for detections it does not ship.
            #
            # Ahead of every telemetry verdict, because switching on a log for
            # a solution with nothing to fire is advice with no consequence.
            action = "none"
            other = ", ".join(f"{n} {k.lower()}" for k, n in
                              sorted(ships.get(cid, collections.Counter()).items())
                              if k != "AnalyticsRule")
            detail = ("Nothing to switch on: it ships no analytics rules"
                      + (f", only {other}" if other else "") + ".")
        elif present is False and (
                catalog.get(solutions._key(name), {}).get("resource_type")
                or (solutions.NON_RESOURCE.get(name) or {}).get("kind") == "resources"):
            # `remove` is reserved for STRUCTURAL absence: no such resource
            # exists, so no setting can make this solution useful. A licence
            # that is off or a feed that is not connected is switchable, and
            # calling that "remove" told this tenant to uninstall Threat
            # Intelligence when the honest advice was to connect a feed.
            action = "remove"
            detail = (f"Nothing here to collect from: {why_present}. It is "
                      "installed for a product this tenant does not run.")
        elif present is False:
            action = "connect"
            detail = (f"{why_present[0].upper()}{why_present[1:]}, so nothing "
                      "this solution ships can fire. Switch the source on, or "
                      "uninstall the solution if you do not intend to.")
        elif deprecated:
            action = "remove"
            detail = ("Microsoft has deprecated this solution, so its content is "
                      "no longer maintained.")
        elif alignment == "repoint":
            action = "connect"
            detail = ("The solution is installed and " + evidence
                      + ". Point it at this workspace and its detections can "
                        "fire." + unverified)
        elif solutions.mode_mismatch(name, catalog,
                                    sorted(types or own_tables)):
            action = "review"
            detail = ("The resource is logging, but "
                      + solutions.mode_mismatch(name, catalog,
                                               sorted(types or own_tables))
                      + ", so the two never meet. Either add a diagnostic "
                        "setting in Azure-diagnostics mode or use content "
                        "written for the dedicated table.")
        elif alignment == "unfed":
            action = "connect"
            cats = (catalog.get(solutions._key(name), {}) or {}).get("categories") or []
            if cats:
                # The service file knows what Azure offers on this resource
                # type. Naming the categories beats naming a shared table:
                # "9 resources would emit AzureDiagnostics" told the NSG row
                # nothing an operator could go and tick.
                #
                # What it must NOT do is name three of them as if they were the
                # job. `cats` is every category the type offers, sorted
                # alphabetically, and half the catalogue has more than three --
                # Databricks has 53. `cats[:3]` read as an instruction and was
                # the first three letters of the alphabet. The count is the
                # honest headline, a few are an example, and the full list goes
                # on the row where a renderer or a script can use all of it.
                detail = ("The solution is installed and " + why_present
                          + " is not sending its logs here. "
                          + switch_on(cats) + unverified)
                tally[action] += 1
                rows.append({
                    "solution_id": cid, "display_name": name,
                    "publisher": c.get("publisherDisplayName") or (pr.get("providers") or [None])[0],
                    "installed": True, "version_installed": version,
                    "version_available": available, "deprecated": deprecated,
                    "alignment": alignment, "basis": evidence,
                    "data_types": sorted(types),
                    "analytics_rules": ships.get(cid, collections.Counter()).get("AnalyticsRule", 0),
                    "rules_enabled": n_enabled,
                    "collects_from": why_present,
                    "categories_to_enable": cats,
                    "action": action, "action_detail": detail,
                })
                continue
            detail = (f"The solution is installed, but {evidence}, so its rule "
                      "templates sit in the library and none of them can fire. "
                      "Connect the data source, or switch on the diagnostic "
                      "setting that fills it." + unverified)
        elif alignment == "no_rules":
            action = "none"
            detail = ("Nothing to switch on: " + evidence + "."
                      + (newer if behind else ""))
        elif alignment in ("unseen", "unmeasured", "unmatched"):
            # NOT "fine". Unjudged is not judged clean, and calling it current
            # would be the report claiming something it did not measure.
            #
            # Branch on the alignment VALUE, never on the evidence text: this
            # once tested `evidence.startswith(...)`, so rewording a message
            # silently reassigned rows to the wrong sentence.
            #
            # `unseen` is not unproven. The meter RAN and the table received
            # nothing -- a measurement, and a different instruction from the
            # two cases where this scan could not look.
            action = "connect" if alignment == "unseen" else "review"
            if alignment == "unseen":
                detail = (evidence + ". If the source is switched off, that is "
                          "the answer; if you think it is on, check the agent "
                          "or connector.")
            elif alignment == "unmeasured":
                detail = (f"{evidence[0].upper()}{evidence[1:]}. Confirm in the "
                          "workspace whether it is arriving.")
            else:
                detail = (f"{evidence[0].upper()}{evidence[1:]}, so what they "
                          "need is unknown.")
            detail += (newer if behind else "")
        elif behind:
            action = "update"
            detail = (f"{version} installed, {available} available, and {evidence}.")
            if ships_rules and present and n_enabled < ships_rules:
                # Two things are true; saying only the version leaves the
                # reader thinking an update is the whole job.
                detail += (f" {ships_rules - n_enabled} of its {ships_rules} "
                           "detection(s) are not switched on.")
        elif ships_rules and n_enabled == 0 and present:
            # Installed, current, fed -- and not one of its detections is on.
            # "Nothing to do" was measuring the SOLUTION and ignoring whether it
            # detects anything, so this report told one tenant nine things
            # needed attention while its own second table said 212 rule
            # templates had never been turned into an analytics rule. Both
            # numbers were right and they never met.
            #
            # Gated on `present`, deliberately. A presence test that could not
            # run is not a tenant that needs the content: without this, a
            # tenant with no OT devices is told to switch on fifteen IoT
            # detections because the solution happens to be installed.
            action = "enable"
            detail = (f"Installed, current, and {evidence}. None of its "
                      f"{ships_rules} detection(s) are switched on.")
        elif ships_rules and n_enabled and n_enabled < ships_rules and present:
            action = "enable"
            detail = (f"Installed, current, and {evidence}. "
                      f"{ships_rules - n_enabled} of its {ships_rules} "
                      "detection(s) have never been switched on.")
        else:
            action = "none"
            detail = f"Installed, current, and {evidence}."

        tally[action] += 1
        rows.append({
            "solution_id": cid,
            "display_name": pr.get("displayName") or cid,
            "publisher": c.get("publisherDisplayName") or (pr.get("providers") or [None])[0],
            "installed": True,
            "version_installed": version,
            "version_available": available,
            "deprecated": deprecated,
            "alignment": alignment,
            "basis": evidence,
            "data_types": sorted(types),
            "analytics_rules": ships.get(cid, collections.Counter()).get("AnalyticsRule", 0),
            "rules_enabled": n_enabled,
            "collects_from": why_present,
            "action": action,
            "action_detail": detail,
        })

    # Not installed, but every data type its connector delivers already holds
    # data here. Anything else cannot be judged without installing it, so it is
    # counted rather than listed.
    candidates = 0
    for cid, pr in cat.items():
        if cid in {r["solution_id"] for r in rows}:
            continue
        types = {t for k in declared(pr) for t in conn.get(k, ())}
        if not types or not all(t in live_tables for t in types):
            continue
        candidates += 1
        tally["install"] += 1
        rows.append({
            "solution_id": cid,
            "display_name": pr.get("displayName") or cid,
            "publisher": pr.get("publisherDisplayName"),
            "installed": False,
            "version_installed": None,
            "version_available": pr.get("version"),
            "deprecated": bool(pr.get("isDeprecated")),
            "alignment": "fed",
            "basis": f"{', '.join(sorted(types)[:2])} holds data",
            "data_types": sorted(types),
            "analytics_rules": 0,
            "rules_enabled": 0,
            "action": "install",
            "action_detail": ("Not installed, and the data it needs is already "
                              f"arriving: {', '.join(sorted(types)[:2])} holds data."),
        })

    rows.sort(key=lambda r: ({"remove": 0, "connect": 1, "update": 2,
                              "enable": 3, "install": 4, "review": 5,
                              "none": 6}[r["action"]],
                             r["display_name"]))
    # Counts only. Two sentences of methodology used to follow them here --
    # how alignment is measured, and why `enable` is the finding this leg
    # exists for. Both are true and neither belongs in a read state: this
    # string is printed on an operator's terminal and listed in the report's
    # unanswered-questions section, and in both places it should say what was
    # found. The reasoning is in this module's docstring, for the reader who
    # wants it.
    noun = "solution" if len(installed) == 1 else "solutions"
    return rows, {"ran": True, "detail": (
        f"{len(installed)} {noun} installed of {len(packages)} in Content Hub; "
        + ", ".join(f"{n} to {k}" for k, n in tally.most_common() if k != "none")
        + f", {tally['none']} current and delivering"
        + (f"; read {fetched} rule template(s) from the Content Hub to resolve "
           f"solutions whose connector did not" if fetched else ""))}
