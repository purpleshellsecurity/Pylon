#!/usr/bin/env python3
"""Regenerate the vendored Entra directory-actions and Graph-permissions catalogs.

Two permission systems, two Microsoft-maintained sources — both public markdown,
no tenant or credentials required:

  * Entra directory roles/actions — MicrosoftDocs/entra-docs
    role-based-access-control/permissions-reference.md is an index that INCLUDEs
    one file per built-in role under `includes/`, each a
    `| microsoft.directory/... | description |` table. We flatten to the unique
    action -> description set (the AuditLogs / directory-change vocabulary) plus a
    role -> actions map. Actions the docs tag with the "Privileged" label are
    flagged `privileged: true`.

  * Microsoft Graph permissions — microsoftgraph/microsoft-graph-docs-contrib
    concepts/permissions-reference.md, self-contained: one `### Scope` block per
    permission with an Application/Delegated table (identifier GUID, display text,
    description, admin-consent). The application-vs-delegated split is the Graph
    analog of ARM's isDataAction.

Writes:
  src/pylon/catalog/entra-directory-actions.json.gz
  src/pylon/catalog/graph-permissions.json.gz

Usage:
    python scripts/refresh-entra-graph-catalogs.py                    # fetch
    python scripts/refresh-entra-graph-catalogs.py --entra-dir D --graph-file F
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from datetime import date
from pathlib import Path
from urllib.request import ProxyHandler, build_opener, getproxies

ENTRA = "https://raw.githubusercontent.com/MicrosoftDocs/entra-docs/main/docs/identity/role-based-access-control"
GRAPH = "https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-docs-contrib/main/concepts/permissions-reference.md"

_ACTION_ROW = re.compile(r"^>?\s*\|\s*(microsoft\.directory/[^\s|]+)\s*\|\s*(.*?)\s*\|\s*$")
_INCLUDE = re.compile(r"\[!INCLUDE\s*\[[^\]]*\]\(includes/([a-z0-9-]+\.md)\)\]")
_ROLE_HEADING = re.compile(r"^##\s+(.+?)\s*$")
_SCOPE = re.compile(r"^###\s+(\S+)")
_CELL = re.compile(r"^\|\s*(\w+)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*$")
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

OUT_ENTRA = Path("src/pylon/catalog/entra-directory-actions.json.gz")
OUT_GRAPH = Path("src/pylon/catalog/graph-permissions.json.gz")


def _fetch(url: str) -> str:
    with build_opener(ProxyHandler(getproxies())).open(url, timeout=60) as resp:
        return resp.read().decode("utf-8")


def _clean_action_desc(raw: str) -> tuple[str, bool]:
    """Strip the trailing '<br/>[![Privileged label]...]' markup; return the
    plain description and whether the action is tagged privileged."""
    privileged = "privileged" in raw.lower()
    desc = raw.split("<br/>", 1)[0]
    desc = re.sub(r"\[!\[.*$", "", desc).strip()
    return desc, privileged


def _role_name_map(index_md: str) -> dict[str, str]:
    """include-slug -> role display name, from the '## Role' + INCLUDE index."""
    names: dict[str, str] = {}
    pending: str | None = None
    for line in index_md.splitlines():
        h = _ROLE_HEADING.match(line)
        if h:
            pending = h.group(1).strip()
            continue
        inc = _INCLUDE.search(line)
        if inc and pending:
            names[inc.group(1)[:-3]] = pending
            pending = None
    return names


def build_entra(index_md: str, includes: dict[str, str]) -> dict:
    names = _role_name_map(index_md)
    actions: dict[str, dict] = {}
    roles: dict[str, list[str]] = {}
    for slug, text in sorted(includes.items()):
        acts: list[str] = []
        for line in text.splitlines():
            m = _ACTION_ROW.match(line)
            if not m:
                continue
            act, raw = m.group(1).strip(), m.group(2).strip()
            desc, priv = _clean_action_desc(raw)
            acts.append(act)
            if act not in actions or (desc and not actions[act]["d"]):
                actions[act] = {"d": desc, "p": priv}
        if acts:
            roles[names.get(slug, slug)] = sorted(set(acts))
    return {
        "meta": {"source": "MicrosoftDocs/entra-docs permissions-reference", "actions": len(actions), "roles": len(roles)},
        "actions": dict(sorted(actions.items())),
        "roles": dict(sorted(roles.items())),
    }


def _cell_value(v: str) -> str:
    v = v.strip()
    return "" if v in ("", "-", "N/A", "Not supported.", "Not supported") else v


def build_graph(md: str) -> dict:
    scopes: dict[str, dict] = {}
    cur: str | None = None
    cells: dict[str, dict] = {}

    def flush() -> None:
        if not cur or not cells:
            return
        entry: dict = {}
        for plane in ("application", "delegated"):
            ident = _cell_value(cells.get("Identifier", {}).get(plane, ""))
            if not _GUID.match(ident or ""):
                continue
            entry[plane] = {
                "id": ident,
                "display": _cell_value(cells.get("DisplayText", {}).get(plane, "")),
                "desc": _cell_value(cells.get("Description", {}).get(plane, "")),
                "adminConsent": _cell_value(cells.get("AdminConsentRequired", {}).get(plane, "")).lower() == "yes",
            }
        if entry:
            scopes[cur] = entry

    for line in md.splitlines():
        h = _SCOPE.match(line)
        if h:
            flush()
            cur, cells = h.group(1).strip(), {}
            continue
        c = _CELL.match(line)
        if c and cur and c.group(1) in ("Identifier", "DisplayText", "Description", "AdminConsentRequired"):
            cells[c.group(1)] = {"application": c.group(2).strip(), "delegated": c.group(3).strip()}
    flush()
    return {
        "meta": {"source": "microsoftgraph/microsoft-graph-docs-contrib permissions-reference", "scopes": len(scopes)},
        "scopes": dict(sorted(scopes.items())),
    }


# Floors for the two vocabularies, well under what the sources carry today (939
# scopes, ~2,900 actions) and well over what a broken parse returns. Inherited
# from refresh-graph-permissions.py, which harvested the Graph half separately
# and refused a short write for the reason its message gives; that script wrote a
# second copy of this catalog and was deleted, so the guard moved here rather
# than leaving the surviving harvest with no floor at all.
_FLOORS = {"scopes": 400, "actions": 500}


def _write(path: Path, catalog: dict) -> None:
    for key, floor in _FLOORS.items():
        got = catalog["meta"].get(key)
        if got is not None and got < floor:
            sys.exit(
                f"Refusing to write {path}: parsed only {got} {key}, which means the "
                f"page shape changed. A truncated catalog silently rejects valid input "
                f"— the exact failure this vocabulary exists to prevent."
            )
    # Stamped here rather than in each builder, so a catalog cannot be written
    # undated. Staleness is the whole question for these two: a directory action
    # or Graph scope Microsoft shipped after the harvest reads as fabricated to
    # the validator, and without a date nobody can tell how far behind we are.
    catalog["meta"]["harvested"] = date.today().isoformat()
    payload = json.dumps(catalog, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(payload, 9))
    print(f"Wrote {path}: {catalog['meta']} — {path.stat().st_size // 1024} KB gzipped")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--entra-dir", type=Path, help="Local dir with entra-roles.md + inc/*.md")
    ap.add_argument("--graph-file", type=Path, help="Local Graph permissions-reference.md")
    args = ap.parse_args()

    if args.entra_dir:
        index_md = (args.entra_dir / "entra-roles.md").read_text(encoding="utf-8")
        includes = {p.stem: p.read_text(encoding="utf-8") for p in (args.entra_dir / "inc").glob("*.md")}
        if not includes:
            sys.exit(f"No includes in {args.entra_dir}/inc")
    else:
        print("Fetching Entra role index + includes ...")
        index_md = _fetch(f"{ENTRA}/permissions-reference.md")
        includes = {}
        for slug in sorted({m[:-3] for m in _INCLUDE.findall(index_md)}):
            includes[slug] = _fetch(f"{ENTRA}/includes/{slug}.md")
    _write(OUT_ENTRA, build_entra(index_md, includes))

    graph_md = args.graph_file.read_text(encoding="utf-8") if args.graph_file else (
        print("Fetching Graph permissions reference ...") or _fetch(GRAPH)
    )
    _write(OUT_GRAPH, build_graph(graph_md))


if __name__ == "__main__":
    main()
