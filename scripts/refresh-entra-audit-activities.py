#!/usr/bin/env python3
"""Harvest the Entra audit activity vocabulary into a vendored catalog.

Fixes a gap that had been documented as filled. `docs/grounding-sources.md`
listed the Entra audit activities reference as a grounding source; no code read
it. So `AuditLogs.OperationName` -- the field every Entra detection filters on --
was the one surface with NEITHER half of the pattern the rest of the tool uses:
nothing put the real vocabulary in front of the model, and nothing checked what
came back. ARM operations have both. Data-plane operations have both. Techniques
got theirs today. Entra had neither, and the eval reported "operation warnings:
0" for the Entra target, which reads as clean and means the check never ran.

The reference publishes ~1,250 rows of `| Audit Category | Activity |` across
~48 categories -- the literal OperationName strings, grouped by the category
they belong to. The column header is the answer: those names are `Category` in
AuditLogs, NOT `LoggedByService`, which holds the service ("Core Directory",
"PIM") and never a name from this page. This file used to say LoggedByService
and the prompt block believed it, which taught the model a filter that can never
match.

    python scripts/refresh-entra-audit-activities.py

Writes src/pylon/catalog/entra-audit-activities.json.gz. Deliberate refresh, not
a live fetch: the vendored snapshot is a reviewed artifact, like the other
catalogs, so a doc edit never silently changes what the tool asserts.
"""

from __future__ import annotations

import gzip
import json
import re
import sys
import urllib.request
from pathlib import Path

# The page a person reads, and the citation that goes in the catalog.
URL = ("https://learn.microsoft.com/en-us/entra/identity/monitoring-health/"
       "reference-audit-activities")
# What the script actually fetches: the SAME document, in the form Microsoft
# authors it. Learn renders as a single-page app, so the tables are not in the
# HTML a fetch returns -- this script had stopped parsing anything at all, which
# the >500 guard caught. The markdown source is also the form WITHOUT Learn's
# punctuation escaping, so `Group_AddMember` arrives spelled the way Entra
# writes it in a log line rather than as `Group\_AddMember`.
SOURCE = ("https://raw.githubusercontent.com/MicrosoftDocs/entra-docs/main/docs/"
          "identity/monitoring-health/reference-audit-activities.md")
OUT = Path(__file__).resolve().parent.parent / "src/pylon/catalog/entra-audit-activities.json.gz"

# Learn's renderer escapes markdown punctuation inside table cells, so an
# activity Microsoft's source spells `Group_AddMember` arrives as
# `Group\_AddMember`. Entra writes the underscore and never the backslash, so
# leaving it in ships fifty operation names that can never match a log line --
# the same failure as the Cosmos DB and LeaseBlob names before it.
_ESCAPED = re.compile(r"\\([_*`\[\]()#+\-.!])")


def _unescape(cell: str) -> str:
    return _ESCAPED.sub(r"\1", cell)


# A row is `| Category | Activity |` or `| Category | Activity | Description |`.
# The closing pipe is optional: the source has rows that omit it, and requiring
# it silently dropped them.
_ROW = re.compile(r"^\|([^|]+)\|([^|]+)(?:\|([^|]*))?\|?\s*$")
_HEADING = re.compile(r"^##\s+(.+?)\s*$")
# Header and separator rows, which look exactly like data rows.
_SKIP = {"audit category", "activity", "description", ""}


def parse(markdown: str) -> dict:
    """Rows -> {service: {activity: description}}, plus the section each came from."""
    activities: dict[str, dict[str, str]] = {}
    sections: dict[str, str] = {}
    current_section = ""

    for line in markdown.splitlines():
        if heading := _HEADING.match(line):
            current_section = heading.group(1).strip()
            continue
        match = _ROW.match(line)
        if not match:
            continue
        service = _unescape(match.group(1).strip())
        activity = _unescape(match.group(2).strip())
        description = _unescape((match.group(3) or "").strip())
        # Separator rows are all dashes; header rows repeat the column names.
        if set(service) <= set("-: ") or service.lower() in _SKIP:
            continue
        if not activity or activity.lower() in _SKIP:
            continue
        activities.setdefault(service, {})[activity] = description
        sections.setdefault(service, current_section)

    return {
        "meta": {
            "source": URL,
            "services": len(activities),
            "activities": sum(len(v) for v in activities.values()),
        },
        "sections": sections,
        "activities": activities,
    }


def main() -> int:
    print(f"Fetching {SOURCE} ...", flush=True)
    try:
        with urllib.request.urlopen(SOURCE, timeout=60) as response:
            text = response.read().decode("utf-8", "replace")
    except OSError as exc:
        print(f"Fetch failed: {exc}", file=sys.stderr)
        return 1

    # _to_markdown_tables is a no-op on markdown and still handles rendered HTML,
    # so the parser has one input shape either way.
    data = parse(_to_markdown_tables(text))
    count = data["meta"]["activities"]
    if count < 500:
        # The page has held ~1,250 for years. A sudden collapse means the layout
        # changed and the parser is now reading something else -- writing that
        # over a good catalog would quietly shrink the vocabulary the model sees.
        print(f"Only {count} activities parsed — expected >500. Page layout may have "
              "changed; NOT overwriting the catalog.", file=sys.stderr)
        return 1

    OUT.write_bytes(gzip.compress(json.dumps(data, separators=(",", ":")).encode()))
    print(f"Wrote {OUT.name}: {count} activities across {data['meta']['services']} services")
    return 0


def _to_markdown_tables(html: str) -> str:
    """Reduce the rendered page to the pipe-table rows and headings we parse.

    The docs render as HTML; the tables survive as <tr><td> pairs. Rewritten to
    pipe rows so `parse` has one input shape whether it is handed rendered HTML
    or the markdown source.
    """
    text = re.sub(r"<h2[^>]*>(.*?)</h2>", r"\n## \1\n", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<tr[^>]*>", "\n|", text, flags=re.IGNORECASE)
    text = re.sub(r"</t[dh]>\s*<t[dh][^>]*>", "|", text, flags=re.IGNORECASE)
    text = re.sub(r"<t[dh][^>]*>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"</t[dh]>", "|", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    return text


if __name__ == "__main__":
    sys.exit(main())
