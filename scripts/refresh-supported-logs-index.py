#!/usr/bin/env python3
"""Refresh the vendored supported-logs INDEX from Microsoft's docs repository.

The index is Layer 1 of the catalog: resource type -> its supported-logs page.
Everything downstream resolves through it, so a type missing here cannot be
named on the command line, cannot be grounded, and cannot be checked.

It had 47 entries against 212 upstream — 23% — and nothing said so, because the
only refresher (`refresh-supported-logs.py`) iterates the service files that
ALREADY exist. It refreshes; it has never discovered. That is why a Bastion run
produced seven generic control-plane detections: `Microsoft.Network/bastionHosts`
was absent, so there was nothing service-specific to ground on, and the model
reached for RBAC and NSG rules that are documented.

The authority is the docs repo itself rather than a rendered page: one file per
resource type under
``articles/azure-monitor/reference/supported-logs/``, so the complete set is a
directory listing and not a scrape.

The resource type is READ from each page's own `title:` line, not derived from
its filename. Filenames are lowercased and use `-` for both the provider
separator and the nesting separator, so `microsoft-apimanagement-service-
workspaces` is indistinguishable from a type literally called
`service-workspaces` — and it is really `Microsoft.ApiManagement/service/
workspaces`. This is Layer 1 and everything resolves through it, so a guess here
would be a wrong answer everywhere downstream rather than a cosmetic one.

The provider segment is normalised to `Microsoft.` because Microsoft's own pages
are inconsistent about it (`microsoft.network/bastionHosts` on one,
`Microsoft.Storage/...` on the next) and ARM treats it case-insensitively.

Network, no credentials. `--check` reports and writes nothing (for CI).
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.request import ProxyHandler, build_opener, getproxies

_ROOT = Path(__file__).resolve().parent.parent
_INDEX = _ROOT / "src" / "pylon" / "catalog" / "supported_logs_index.md"
_DOCS_API = (
    "repos/MicrosoftDocs/azure-monitor-docs/contents/"
    "articles/azure-monitor/reference/supported-logs?per_page=100"
)
_URL = "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/{slug}"
_LINK_RE = re.compile(r"\* \[([^\]]+)\]\((https?://[^)]+)\)")


def upstream_slugs() -> list[str]:
    """Every `<slug>-logs.md` upstream, as slugs. Uses `gh` so the call is
    authenticated and paginated rather than scraped."""
    proc = subprocess.run(
        ["gh", "api", _DOCS_API, "--paginate", "--jq", ".[].name"],
        capture_output=True, text=True, check=True,
    )
    return sorted(
        name[: -len("-logs.md")]
        for name in proc.stdout.splitlines()
        if name.endswith("-logs.md")
    )


_RAW = (
    "https://raw.githubusercontent.com/MicrosoftDocs/azure-monitor-docs/main/"
    "articles/azure-monitor/reference/supported-logs/{slug}-logs.md"
)
_TITLE_RE = re.compile(r"^title:\s*Supported log categories\s*-\s*(\S+)", re.MULTILINE)


def canonical_type(slug: str, opener) -> str | None:
    """The resource type as the page itself states it, or None if unreadable."""
    try:
        with opener.open(_RAW.format(slug=slug), timeout=30) as fh:
            head = fh.read(4096).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - one unreadable page must not stop the run
        return None
    m = _TITLE_RE.search(head)
    if not m:
        return None
    rtype = m.group(1).strip()
    if "/" not in rtype:
        return None
    provider, _, rest = rtype.partition("/")
    # "microsoft.network" and "Microsoft.Storage" both appear upstream.
    if provider.lower().startswith("microsoft."):
        provider = "Microsoft." + provider.split(".", 1)[1]
    return f"{provider}/{rest}"


def _repair_provider_casing(rtype: str, known: dict[str, str]) -> str:
    """Borrow a provider segment's casing from an entry we already have.

    Upstream writes the same provider both ways — `microsoft.network/bastionHosts`
    on one page, `Microsoft.Storage/...` on the next. ARM does not care, but an
    index that spells one provider two ways reads like two providers.
    """
    provider, _, rest = rtype.partition("/")
    if not rest:
        return rtype
    for existing in known.values():
        head = existing.split("/")[0]
        if head.lower() == provider.lower() and head != provider:
            return f"{head}/{rest}"
    return rtype


def known_types() -> dict[str, str]:
    """slug -> the canonical resource type already vendored, so a refresh never
    downgrades casing we have already established."""
    out = {}
    for m in _LINK_RE.finditer(_INDEX.read_text(encoding="utf-8")):
        rtype = m.group(1)
        out[rtype.replace("/", "-").replace(".", "-").lower()] = rtype
    return out


def slug_to_type(slug: str, known: dict[str, str]) -> str:
    """`microsoft-network-bastionhosts` -> `Microsoft.Network/bastionHosts` where
    we know the casing, else a faithful lowercase reading of the slug."""
    if slug in known:
        return known[slug]
    parts = slug.split("-")
    if len(parts) < 3 or parts[0] != "microsoft":
        return slug
    # Provider casing borrowed from an existing entry with the same provider.
    provider_slug = parts[1]
    for rtype in known.values():
        head = rtype.split("/")[0]
        if head.split(".", 1)[-1].lower() == provider_slug:
            return f"{head}/{'-'.join(parts[2:])}"
    return f"Microsoft.{provider_slug}/{'-'.join(parts[2:])}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="report, write nothing")
    ap.add_argument("--json", action="store_true", help="machine-readable summary")
    args = ap.parse_args()

    slugs = upstream_slugs()
    known = known_types()
    have = set(known)
    missing = [s for s in slugs if s not in have]
    gone = sorted(have - set(slugs))

    # Resolve the canonical type for anything new. Only the missing ones are
    # fetched: an entry already vendored has a reviewed string, and refetching it
    # would let an upstream title change rewrite it silently.
    opener = build_opener(ProxyHandler(getproxies()))
    opener.addheaders = [("User-Agent", "pylon-refresh-supported-logs-index")]
    resolved: dict[str, str] = {}
    unreadable: list[str] = []
    if missing and not args.check:
        for i, slug in enumerate(missing, 1):
            rtype = canonical_type(slug, opener)
            if rtype is not None:
                rtype = _repair_provider_casing(rtype, known)
            if rtype is None:
                unreadable.append(slug)
            else:
                resolved[slug] = rtype
            if i % 25 == 0 or i == len(missing):
                print(f"  read {i}/{len(missing)} pages", file=sys.stderr)

    if args.json:
        print(json.dumps({"upstream": len(slugs), "vendored": len(have),
                          "missing": missing, "gone": gone}, indent=1))
    else:
        print(f"upstream {len(slugs)}, vendored {len(have)}, missing {len(missing)}")
        for slug in missing[:20]:
            print(f"  + {resolved.get(slug, slug)}")
        if len(missing) > 20:
            print(f"  ... and {len(missing) - 20} more")
        for slug in gone:
            print(f"  - {known[slug]}  (no longer upstream)")

    if args.check:
        return 1 if missing or gone else 0

    header = _INDEX.read_text(encoding="utf-8").split("-->", 1)[0] + "-->\n\n"
    lines = []
    for slug in slugs:
        rtype = known.get(slug) or resolved.get(slug)
        if rtype is None:
            continue  # unreadable page: leave it out rather than guess a type
        lines.append(f"* [{rtype}]({_URL.format(slug=slug + '-logs')})")
    if unreadable:
        print(f"  ! {len(unreadable)} page(s) unreadable, omitted: "
              + ", ".join(unreadable[:5]), file=sys.stderr)
    _INDEX.write_text(header + "\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} entries to {_INDEX.relative_to(_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
