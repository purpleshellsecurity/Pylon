"""Input sanitization and URL validation — port of lib/validation/sanitize.ts."""

import re
from urllib.parse import urlparse

ALLOWED_DOC_DOMAINS = [
    "learn.microsoft.com",
    "docs.microsoft.com",
    "github.com",
    "raw.githubusercontent.com",
]


def sanitize_service(raw: str) -> str:
    """Strip characters that could affect prompt injection or cause parse
    issues. Caps at 100 characters — no legitimate service name is longer."""
    s = raw.strip()[:100]
    s = re.sub(r"[<>{}\[\]`\"';\\]", "", s)
    s = re.sub(r"[\n\r]", " ", s)
    s = re.sub(r"\s{2,}", " ", s)
    return s.strip()


def is_allowed_doc_url(url: str) -> bool:
    """SSRF guard for optional documentation-context URLs."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    hostname = parsed.hostname.lower()
    return any(hostname == d or hostname.endswith(f".{d}") for d in ALLOWED_DOC_DOMAINS)
