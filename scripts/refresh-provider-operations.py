#!/usr/bin/env python3
"""Regenerate the vendored Azure provider-operations catalog.

Source of truth: the ARM API itself.

    GET /providers/Microsoft.Authorization/providerOperations
        ?api-version=2022-04-01&$expand=resourceTypes

It used to parse Microsoft's RBAC permission DOCS instead. The two agree: a live
tenant returned all 122 Microsoft.KeyVault operations, byte-identical to what
the doc harvest had produced. That agreement is what made switching safe, and
checking it first is the only reason to trust the switch at all.

The reason to move is not the operation names. It is the three fields the docs
do not carry:

    isDataAction   Azure's OWN answer to control plane vs data plane. This was
                   being INFERRED here by pattern-matching "/action" in the
                   string, which is a guess wearing a rule's clothes. A control
                   action lands in AzureActivity; a data action lands in the
                   resource's own audit table or nowhere, so this field decides
                   routing and nothing else in the repo could answer it.
    displayName    "Get Secret" rather than the slug.
    resourceType   the operation grouped by Vault, Secret, Key, Certificate --
                   the same grouping the data-plane catalog builds by hand.

`$expand=resourceTypes` is required. Without it every `operations` array comes
back empty, which reads as a provider with no operations rather than an error.

THE COST, STATED PLAINLY: the refresh now needs an Azure login where it used to
need only a network fetch. Nothing changes for anyone RUNNING Pylon -- the
catalog is vendored either way -- but a contributor with no subscription can no
longer refresh it. `--from-docs` keeps the old path for exactly that case, and
it produces a file with the three new fields absent rather than guessed.

Usage:
    az login
    python scripts/refresh-provider-operations.py               # the ARM API
    python scripts/refresh-provider-operations.py --from-docs   # the old doc path
    python scripts/refresh-provider-operations.py --from-dir DIR  # local *.md

Re-run when Azure adds providers/operations, or when onboarding a new service.
The CONTENT is deterministic — an unchanged Azure surface yields the same
providers and operations — but `meta.harvested` is stamped each run, so a
re-harvest always produces a diff of exactly that one line. That is the point of
it: without a date, "this catalog lags reality" cannot be checked, and the lag is
what decides whether an operation missing from it means anything at all.
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import ProxyHandler, build_opener, getproxies

RAW = "https://raw.githubusercontent.com/MicrosoftDocs/azure-docs/main/articles/role-based-access-control"
INDEX = f"{RAW}/resource-provider-operations.md"

_ROW = re.compile(r"^>\s*\|\s*`([^`]+)`\s*\|\s*(.*?)\s*\|\s*$")
_SVC = re.compile(r"^Azure service:\s*\[?([^\]\(]+)")
_CATFILE = re.compile(r"\./permissions/([a-z0-9-]+\.md)")

OUT = Path("src/pylon/catalog/provider-operations.json.gz")


def _fetch(url: str) -> str:
    opener = build_opener(ProxyHandler(getproxies()))
    with opener.open(url, timeout=60) as resp:
        return resp.read().decode("utf-8")


API = ("https://management.azure.com/providers/Microsoft.Authorization"
       "/providerOperations?api-version=2022-04-01&$expand=resourceTypes")


def _token() -> str:
    """A bearer token for ARM, via the Azure CLI the rest of this repo uses.

    Deliberately not DefaultAzureCredential: that would add azure-identity to
    the refresh scripts' dependencies for one call, and every other live script
    here already shells out to `az`.
    """
    import subprocess

    # Same reason every other credential-reading script here does it: the
    # settings may live in ~/.config/pylon/config.env rather than the
    # environment, and a script that skips this fails pointing at the wrong
    # thing entirely. tests/test_config.py holds all of them to it.
    try:
        from pylon import config

        config.apply()
    except Exception:  # noqa: BLE001 - a missing config must not stop a harvest
        pass

    try:
        out = subprocess.run(
            ["az", "account", "get-access-token",
             "--resource", "https://management.azure.com/",
             "--query", "accessToken", "-o", "tsv"],
            capture_output=True, text=True, timeout=60,
        )
    except FileNotFoundError:
        sys.exit("the Azure CLI is not installed. Use --from-docs to harvest "
                 "from documentation instead, without the new fields.")
    if out.returncode != 0:
        sys.exit(f"az could not get a token ({out.stderr.strip()}). Run `az login`, "
                 f"or use --from-docs.")
    return out.stdout.strip()


def _get_json(url: str, token: str) -> dict:
    from urllib.request import Request

    req = Request(url, headers={"Authorization": f"Bearer {token}"})
    opener = build_opener(ProxyHandler(getproxies()))
    with opener.open(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _from_api() -> tuple[dict, dict]:
    """(providers, operations) from the ARM API. Operations carry every field the
    API returns, so nothing here has to be inferred from the operation string."""
    token = _token()
    providers: dict[str, str] = {}
    operations: dict[str, dict] = {}
    url, page = API, 0
    while url:
        page += 1
        print(f"  page {page} ...")
        body = _get_json(url, token)
        for prov in body.get("value") or []:
            name = prov.get("name") or ""
            providers.setdefault(name, prov.get("displayName") or "")
            # Operations hang off the provider AND off each resource type. The
            # resource type is worth keeping: it is the grouping the data-plane
            # catalog builds by hand, and here it comes from Azure.
            groups = [(None, prov.get("operations") or [])]
            groups += [(rt.get("name") or "", rt.get("operations") or [])
                       for rt in (prov.get("resourceTypes") or [])]
            for rtype, ops in groups:
                for op in ops:
                    key = op.get("name")
                    if not key:
                        continue
                    row = {"description": op.get("description") or "",
                           "displayName": op.get("displayName") or "",
                           "isDataAction": bool(op.get("isDataAction"))}
                    if rtype:
                        row["resourceType"] = rtype
                    # A provider-level entry and a resource-type entry can both
                    # describe one operation. Prefer whichever names a resource
                    # type, since that is the extra fact.
                    if key not in operations or "resourceType" in row:
                        operations[key] = row
        url = body.get("nextLink")
    return providers, operations


def _category_files(index_md: str) -> list[str]:
    return sorted(set(_CATFILE.findall(index_md)))


def _parse_category(md: str, providers: dict[str, str], operations: dict[str, str]) -> None:
    provider: str | None = None
    for line in md.splitlines():
        if line.startswith("## "):
            provider = line[3:].strip()
            if provider.lower() == "next steps":
                provider = None
            continue
        if provider is None:
            continue
        svc = _SVC.match(line)
        if svc:
            providers.setdefault(provider, svc.group(1).strip())
            continue
        row = _ROW.match(line)
        if row:
            op, desc = row.group(1).strip(), row.group(2).strip()
            if op.lower() == "action":  # skip the '| Action | Description |' header
                continue
            providers.setdefault(provider, providers.get(provider, ""))
            # Last non-empty description wins (tables sometimes repeat a row).
            if op not in operations or (desc and not operations[op]):
                operations[op] = desc


def build(from_dir: Path | None, from_docs: bool = False) -> dict:
    providers: dict[str, str] = {}
    operations: dict = {}
    if not from_dir and not from_docs:
        print("Fetching from the ARM API")
        providers, operations = _from_api()
        # The API wins on operations and LOSES on provider names. It returns the
        # raw namespace where the docs have the name a person uses:
        #
        #     Microsoft.AVS                 docs "Azure VMware Solution"
        #                                   api  "Microsoft.AVS"
        #     Microsoft.AlertsManagement    docs "Azure Monitor"
        #                                   api  "Microsoft.AlertsManagement"
        #     Microsoft.AAD                 docs "Microsoft Entra Domain Services"
        #                                   api  "Domain Services Resource Provider"
        #
        # 134 of the 152 shared providers read worse from the API, and
        # service_for() feeds prompts and reports. So each source is used for
        # the half it is better at, rather than one being declared the winner --
        # the same rule the operation vocabularies needed.
        print("Fetching provider names from the docs")
        try:
            doc_names: dict[str, str] = {}
            for name in _category_files(_fetch(INDEX)):
                _parse_category(_fetch(f"{RAW}/permissions/{name}"), doc_names, {})
            kept = 0
            for prov, friendly in doc_names.items():
                # A docs name that is just the namespace is no better than the
                # API's, so it does not displace it.
                if friendly and not friendly.startswith("Microsoft.") \
                        and providers.get(prov) != friendly:
                    providers[prov] = friendly
                    kept += 1
            print(f"  kept {kept} friendly provider names")
            source = ("ARM API providerOperations 2022-04-01 (operations); "
                      "MicrosoftDocs/azure-docs RBAC permissions (provider names)")
        except Exception as exc:  # noqa: BLE001 - names are a nicety, operations are not
            print(f"  could not read the docs ({exc}); keeping API provider names")
            source = "ARM API providerOperations 2022-04-01"
        return _payload(providers, operations, source)
    if from_dir:
        files = sorted(from_dir.glob("*.md"))
        if not files:
            sys.exit(f"No *.md files in {from_dir}")
        for f in files:
            _parse_category(f.read_text(encoding="utf-8"), providers, operations)
    else:
        print(f"Fetching index: {INDEX}")
        catfiles = _category_files(_fetch(INDEX))
        print(f"  {len(catfiles)} category files")
        for name in catfiles:
            print(f"  fetching {name} ...")
            _parse_category(_fetch(f"{RAW}/permissions/{name}"), providers, operations)
    return _payload(providers, operations,
                    "MicrosoftDocs/azure-docs role-based-access-control/permissions")


def _payload(providers: dict, operations: dict, source: str) -> dict:
    return {
        "meta": {
            "source": source,
            # UTC, stamped when the harvest actually ran. Without it "the catalog
            # lags reality" is unfalsifiable — nobody can tell a month from two
            # years, and the lag is what decides whether an operation missing
            # from it means anything.
            "harvested": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "providers": len(providers),
            "operations": len(operations),
        },
        "providers": dict(sorted(providers.items())),
        "operations": dict(sorted(operations.items())),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--from-dir", type=Path, help="Parse local *.md instead of fetching")
    ap.add_argument("--from-docs", action="store_true",
                    help="Harvest from the RBAC documentation instead of the ARM "
                         "API. No Azure login needed, and no isDataAction.")
    ap.add_argument("--out", type=Path, default=OUT, help=f"Output path (default: {OUT})")
    args = ap.parse_args()

    catalog = build(args.from_dir, args.from_docs)
    payload = json.dumps(catalog, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(gzip.compress(payload, 9))
    kb = args.out.stat().st_size // 1024
    print(
        f"Wrote {args.out}: {catalog['meta']['operations']} operations, "
        f"{catalog['meta']['providers']} providers, {kb} KB gzipped, "
        f"harvested {catalog['meta']['harvested']}"
    )


if __name__ == "__main__":
    main()
