from pylon.grounding import DOCS_BASE, MITRE_URL, _is_allowed_fetch_url
from pylon.validation import is_allowed_doc_url, sanitize_service


def test_fetch_guard_allows_pinned_doc_and_mitre_paths():
    assert _is_allowed_fetch_url(f"{DOCS_BASE}/tables/storagebloblogs.md")
    assert _is_allowed_fetch_url(MITRE_URL)


def test_fetch_guard_blocks_path_traversal_and_off_host():
    # SSRF: a traversal slug stays on raw.githubusercontent.com but escapes the
    # pinned doc path to attacker-controlled content — must be refused.
    assert not _is_allowed_fetch_url(
        f"{DOCS_BASE}/tables/../../../../../../attacker/repo/main/payload.md"
    )
    assert not _is_allowed_fetch_url("https://raw.githubusercontent.com/attacker/repo/main/x")
    assert not _is_allowed_fetch_url("https://evil.com/x")
    assert not _is_allowed_fetch_url(DOCS_BASE.replace("https", "http") + "/tables/x.md")


def test_sanitize_strips_injection_characters():
    assert sanitize_service('Key Vault<script>"; DROP') == "Key Vaultscript DROP"


def test_sanitize_collapses_whitespace_and_newlines():
    assert sanitize_service("Key\nVault   extra") == "Key Vault extra"


def test_sanitize_caps_length():
    assert len(sanitize_service("A" * 300)) <= 100


def test_allowed_doc_url_accepts_ms_learn():
    assert is_allowed_doc_url("https://learn.microsoft.com/en-us/azure/key-vault/")


def test_allowed_doc_url_rejects_http():
    assert not is_allowed_doc_url("http://learn.microsoft.com/x")


def test_allowed_doc_url_rejects_lookalike_domain():
    assert not is_allowed_doc_url("https://learn.microsoft.com.evil.example/x")


def test_allowed_doc_url_rejects_garbage():
    assert not is_allowed_doc_url("not a url")
