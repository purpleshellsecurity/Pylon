"""Grounding — port of lib/grounding.ts.

Fetches authoritative documentation so every field name and technique ID in
generated output comes from a source, not model memory:

  1. Table schema  — MicrosoftDocs/azure-monitor-docs (GitHub raw)
  2. Sample KQL    — same repo, queries files
  3. MITRE ATT&CK  — mitre/cti enterprise-attack bundle

Plain async code with a 24h TTL cache. The engine wraps calls in @step so
results also cache across HITL resumes and checkpoint restores.
"""

import json
import re
import time
from urllib.parse import urlparse

import httpx

from .validation.sanitize import is_allowed_doc_url
from .logs import get_logger

log = get_logger(__name__)

DOCS_BASE = (
    "https://raw.githubusercontent.com/MicrosoftDocs/azure-monitor-docs/"
    "main/articles/azure-monitor/reference"
)
MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Only these path prefixes may be fetched. A host allowlist alone is not enough:
# raw.githubusercontent.com serves every user's repos, so a path-traversal slug
# ("../../../attacker/repo/main/payload") stays on-host but reaches attacker
# content that would land verbatim in the model's grounding context (SSRF ->
# prompt injection). Pin the path, and reject any ".." segment defensively.
_ALLOWED_FETCH_PREFIXES = (
    DOCS_BASE + "/",
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/",
)

_TTL_SECONDS = 60 * 60 * 24
_cache: dict[str, tuple[float, str]] = {}


def _is_allowed_fetch_url(url: str) -> bool:
    """SSRF guard for grounding fetches: allowed host (is_allowed_doc_url) AND a
    pinned path prefix with no traversal. Both layers matter — the host check
    stops off-domain SSRF, the prefix/`..` check stops on-host path traversal."""
    if not is_allowed_doc_url(url):
        return False
    if ".." in urlparse(url).path.split("/"):
        return False
    return url.startswith(_ALLOWED_FETCH_PREFIXES)


# What each remote file hashed to when it was last accepted.
#
# DOCS_BASE tracks `main` and the markdown behind it is fetched at RUN TIME and
# appended to the model's context inside <live_documentation> -- it is grounding,
# not verification, so a change upstream changes this tool's output with no
# signal. Pinning to a commit would freeze documentation we want current; a hash
# keeps it current and makes the change visible.
#
# NOT a gate. A doc page legitimately changes, and refusing to run because
# Microsoft edited a table reference would be worse than the drift. It is a line
# in the run log, which is the thing that was missing.
_SEEN: dict[str, str] = {}


def _note_drift(url: str, body: str) -> None:
    """Log when a remote grounding file differs from the last one accepted."""
    import hashlib

    digest = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()
    previous = _SEEN.get(url)
    _SEEN[url] = digest
    if previous and previous != digest:
        log.warning(
            "grounding source changed since this run last read it: %s "
            "(%s -> %s). It tracks a branch, so this is expected occasionally "
            "and worth a look when a detection changes shape.",
            url, previous[:12], digest[:12],
            extra={"event": "grounding_drift", "url": url,
                   "sha256_was": previous, "sha256_now": digest})


async def _fetch_cached(url: str) -> str:
    """GET `url` with a 24h TTL cache. Returns the body text, or '' on a non-200
    status or any HTTP error. Refuses any URL outside the pinned doc/MITRE paths
    (SSRF guard) — a rejected URL returns '' without a network call."""
    if not _is_allowed_fetch_url(url):
        return ""
    hit = _cache.get(url)
    if hit and time.time() - hit[0] < _TTL_SECONDS:
        return hit[1]
    try:
        # NO REDIRECTS. `_is_allowed_fetch_url` runs once, above, against the
        # URL we are about to request -- a 30x would leave BOTH layers behind
        # and fetch whatever the redirect names. OWASP's SSRF sheet is explicit:
        # "disable the support for the following of the redirection in your web
        # client in order to prevent the bypass of the input validation".
        #
        # raw.githubusercontent.com does not redirect valid paths off-host
        # today, so this was a hole in the guard rather than a live hole. It is
        # the guard that has to hold, not the current behaviour of one host.
        #
        # If a redirect is ever needed, follow it manually and re-run
        # `_is_allowed_fetch_url` on every hop.
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            res = await client.get(url)
            if res.status_code != 200:
                return ""
            _note_drift(url, res.text)
            _cache[url] = (time.time(), res.text)
            return res.text
    except httpx.HTTPError:
        return ""


# Every column table this repo has fetched fits inside 8k; AzureActivity's is the
# longest at ~3.9k. The old cap was 3,000, which cut it at 30 of 38 rows and lost
# TimeGenerated, SubscriptionId, Type and ResourceProvider -- the four a query is
# most likely to need. The prompt was being grounded on a truncated schema and
# nobody could see the cut, because the excerpt ends mid-table without a marker.
_COLUMN_BLOCK_CAP = 8000


def _extract_columns(md: str) -> str:
    """Column table from an Azure Monitor table doc: '| Column' to next '## '."""
    start = md.find("| Column")
    if start == -1:
        return md[:2000]
    end = md.find("\n## ", start)
    return md[start : end if end > -1 else start + _COLUMN_BLOCK_CAP].strip()


# One row of the Azure Monitor column table: `| ColumnName | type | text |`.
# The header row and the `|---|` separator are excluded by the name pattern.
_COLUMN_ROW = re.compile(r"^\s*\|\s*([A-Za-z_][A-Za-z0-9_]*)\s*\|", re.M)


async def documented_columns(log_table: str) -> frozenset[str]:
    """Every column Microsoft documents for `log_table`, or empty if unreachable.

    The validator's own `TABLE_SCHEMAS` is extracted from this repo's prompt
    assets -- the columns the prompt TEACHES, not the columns the table HAS.
    AzureActivity lists sixteen there and documents about forty. That gap is fine
    for a warning and fatal for an error: a detection filtering on `OperationId`,
    a real column the prompt does not mention, was rejected as a fabrication.

    The run already fetches this page for grounding, so the model is shown the
    real column list and then judged against a shorter one. Same fetch, same
    cache, now on both sides.

    Empty means UNREACHABLE, never "no columns" -- the caller must not read it as
    a verdict.
    """
    md = await _fetch_cached(f"{DOCS_BASE}/tables/{re.sub(r'[^a-z0-9]', '', log_table.lower())}.md")
    if not md:
        return frozenset()
    # The WHOLE table, never the grounding excerpt. The excerpt is capped for
    # prompt size and a cap that clips the list is harmless in a prompt and fatal
    # here -- the eight rows it used to drop included TimeGenerated.
    start = md.find("| Column")
    if start == -1:
        return frozenset()
    end = md.find("\n## ", start)
    block = md[start : end if end > -1 else len(md)]
    # "Column" is the header cell of the table itself, not a column.
    return frozenset(_COLUMN_ROW.findall(block)) - {"Column"}


_KQL_FENCE = re.compile(r"```(?:kusto|kql|query)[^\n]*\n(.*?)```", re.DOTALL)


def extract_kql_blocks(md: str) -> list[str]:
    """Extract KQL from ```query / ```kusto / ```kql fenced blocks in `md`,
    tolerant of CRLF line endings."""
    # The Azure Monitor query reference fences KQL as ```query (a few older docs
    # use ```kusto / ```kql). Matching only ```kusto silently dropped EVERY
    # documented sample query — e.g. azkvauditlogs/storagebloblogs (6 each),
    # signinlogs (10), azureactivity (20) — so grounding shipped a schema with no
    # examples. Match all three fences, and tolerate CRLF (`\r\n`) line endings:
    # several of these docs are CRLF, so anchoring on a bare `\n` after the tag
    # missed them too.
    return [b.strip() for b in _KQL_FENCE.findall(md)]


def _extract_kql_samples(md: str, limit: int = 3) -> str:
    """Up to `limit` fenced KQL samples from `md`, joined by blank lines."""
    return "\n\n".join(extract_kql_blocks(md)[:limit])


async def table_schema_context(log_table: str) -> str:
    """Documented columns + sample queries for a Sentinel table."""
    # Slug goes into a fetch URL path, so strip it to bare [a-z0-9] — an Azure
    # table name is alphanumeric, and this makes path traversal impossible at the
    # source (defense in depth with _fetch_cached's SSRF guard).
    slug = re.sub(r"[^a-z0-9]", "", log_table.lower())
    if not slug:
        return ""
    schema_md = await _fetch_cached(f"{DOCS_BASE}/tables/{slug}.md")
    queries_md = await _fetch_cached(f"{DOCS_BASE}/queries/{slug}.md")
    parts = []
    if schema_md:
        parts.append(
            f"### Documented {log_table} columns (azure-monitor-docs)\n"
            f"{_extract_columns(schema_md)}"
        )
    if queries_md:
        samples = _extract_kql_samples(queries_md)
        if samples:
            parts.append(f"### Sample {log_table} queries\n{samples}")
    return "\n\n".join(parts)


class MitreBundleUnavailable(RuntimeError):
    """The MITRE CTI bundle could not be fetched, so ID verification could not run.

    Distinct from 'fetched, nothing matched' (an empty dict) — the caller must NOT
    treat an unreachable bundle as 'all IDs are fabricated', but it must also not
    silently pretend verification happened. The anti-hallucination control is only
    real when the bundle is reachable; when it isn't, that has to be recorded."""


async def mitre_technique_names(technique_ids: set[str]) -> dict[str, str]:
    """Map verified technique IDs to names from the MITRE CTI bundle.

    Used to reject fabricated IDs: anything the model emitted that is not in
    the bundle gets dropped instead of shipped. Raises MitreBundleUnavailable when
    the bundle can't be fetched (an empty dict means 'reachable, none matched').
    """
    raw = await _fetch_cached(MITRE_URL)
    if not raw:
        raise MitreBundleUnavailable(
            f"MITRE CTI bundle unreachable ({MITRE_URL}); technique-ID verification "
            "could not run this pass."
        )
    bundle = json.loads(raw)
    found: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            ext_id = ref.get("external_id", "")
            if ext_id in technique_ids:
                found[ext_id] = obj.get("name", "")
    return found
