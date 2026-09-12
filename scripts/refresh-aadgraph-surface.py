#!/usr/bin/env python3
"""Regenerate the Azure AD Graph entity/function surface from a CSDL dump.

The Azure AD Graph API (graph.windows.net) is an OData service: its full surface
is machine-enumerable from the endpoint's $metadata document. That endpoint is
token-gated (and being retired), so dump it once from an authenticated session
and vendor the XML, then run this to (re)generate the grounded surface asset.

Dump the metadata (PowerShell, from a session with Azure access):

    $tok = az account get-access-token --resource https://graph.windows.net `
             --query accessToken -o tsv
    Invoke-RestMethod -Headers @{ Authorization = "Bearer $tok" } `
      -Uri 'https://graph.windows.net/myorganization/$metadata?api-version=1.6' `
      -OutFile aadgraph-metadata.xml

Then:

    python scripts/refresh-aadgraph-surface.py aadgraph-metadata.xml \
        > src/pylon/catalog/aadgraph-entities.yaml

The parser is namespace-agnostic (matches on local tag names), so it tolerates
CSDL/EDMX version differences. It emits entity sets and function imports; the
human-authored `recon:` notes in the checked-in YAML are not machine-derivable
and should be re-added by hand after a regeneration (diff, don't overwrite blind).
"""

import sys
import xml.etree.ElementTree as ET


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_surface(xml_path: str) -> tuple[list[str], list[str]]:
    root = ET.parse(xml_path).getroot()
    entity_sets: list[str] = []
    functions: list[str] = []
    for el in root.iter():
        tag = _local(el.tag)
        name = el.get("Name")
        if not name:
            continue
        if tag == "EntitySet":
            entity_sets.append(name)
        elif tag in ("FunctionImport", "Action", "Function"):
            functions.append(name)
    return sorted(set(entity_sets)), sorted(set(functions))


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: refresh-aadgraph-surface.py <aadgraph-metadata.xml>")
    entities, functions = parse_surface(sys.argv[1])
    print("# Azure AD Graph (graph.windows.net) entity/function surface.")
    print("# Regenerated from $metadata by scripts/refresh-aadgraph-surface.py.")
    print("# Re-add the human 'recon:' notes by hand (diff against the prior file).")
    print("endpoint: graph.windows.net")
    print('api_version: "1.6"')
    print("entities:")
    for e in entities:
        print(f"  - name: {e}")
    print("functions:")
    for f in functions:
        print(f"  - {f}")


if __name__ == "__main__":
    main()
