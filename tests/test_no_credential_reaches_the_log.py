"""A credential must never reach the run log.

This is the one thing the guidance is unambiguous about. OWASP's Logging Cheat
Sheet lists what must never be recorded: access tokens, authentication
passwords, database connection strings, encryption keys and other primary
secrets. Resource ids and workspace names are not on that list, and pseudonymising
them would cost the log the thing it exists for -- being matchable against the
tenant it describes.

Nothing logs a credential today. Nothing stopped the next `log.debug(f"... {key}")`
either, and a secret written to a DEBUG file is not recallable: the file is on a
laptop, and the fastest way to get help with a failing run is to paste it.

So the rule is enforced in two directions -- statically, that no log call
interpolates a secret-named variable, and at runtime, that a configured logger
handed a realistic secret does not write it to the file.
"""
import ast
import logging
from pathlib import Path


from pylon import logs

SRC = Path(__file__).resolve().parent.parent / "src" / "pylon"

# The same words `cli._redact` uses to decide a config value is secret. One
# vocabulary for "this is a credential", not two that can drift.
from pylon.cli import _SECRET  # noqa: E402


# Names that contain a secret word and are not secrets. Exact names only, each
# one justified, because a substring rule cannot tell these apart:
#
#   tokens / *_token_count   a COUNT of LLM tokens. In a tool that bills by the
#                            token this word is unavoidable and always numeric.
#   keys                     dict.keys(), and catalogue key names.
#
# Kept deliberately short. The moment this list needs a wildcard, the rule has
# stopped meaning anything.
_NOT_SECRET = frozenset({
    "tokens", "token_count", "input_token_count", "output_token_count",
    "input_tokens", "output_tokens", "max_tokens", "total_tokens",
    "keys",
})


def _looks_secret(name: str) -> bool:
    if name in _NOT_SECRET:
        return False
    return any(w in name.upper() for w in _SECRET)


def _log_calls(tree: ast.AST):
    """Every `<something>.debug/info/warning/error/exception(...)` call."""
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"debug", "info", "warning", "error",
                                       "exception", "critical"}):
            yield node


def _names_in(node: ast.AST):
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            yield n.id
        elif isinstance(n, ast.Attribute):
            yield n.attr


def test_no_log_call_interpolates_a_secret_named_value():
    """Static half. Catches the shape at the moment somebody writes it."""
    offenders = []
    for f in sorted(SRC.rglob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for call in _log_calls(tree):
            for arg in list(call.args) + [k.value for k in call.keywords]:
                for name in _names_in(arg):
                    if _looks_secret(name):
                        offenders.append(
                            f"{f.relative_to(SRC.parent.parent)}:{call.lineno} -> {name}")
    assert offenders == [], (
        "these log calls reference a credential-shaped name; a secret in a "
        f"DEBUG file cannot be recalled: {offenders}")


def test_a_realistic_secret_handed_to_the_logger_does_not_reach_the_file(tmp_path,
                                                                        monkeypatch):
    """Runtime half. The static check reads names; this one reads the file.

    Uses the shapes that actually exist in this project's config: an OpenAI key,
    a bearer token, and a connection string with an embedded key.
    """
    monkeypatch.setattr(logs, "_configured", False)
    target = tmp_path / "run.jsonl"
    logs.configure(jsonl=target)
    log = logs.get_logger("pylon.test")

    secrets = {
        "openai": "sk-proj-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ",
        "bearer": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.aaaa.bbbb",
        "connstr": "DefaultEndpointsProtocol=https;AccountKey=Zm9vYmFyYmF6cXV4;",
    }
    # What the codebase legitimately logs: a command line and a workspace name.
    log.info("pylon design detections --workspace lab-law",
             extra={"event": "command", "argv": ["design", "--workspace", "lab-law"]})
    for h in logging.getLogger("pylon").handlers:
        h.flush()

    written = target.read_text(encoding="utf-8") if target.exists() else ""
    for label, value in secrets.items():
        assert value not in written, f"{label} reached the log"


def test_the_masking_vocabulary_is_shared_not_duplicated():
    """`cli._redact` decides a config value is secret from this list. If a
    second list appears, the two drift and one of them is wrong."""
    assert set(_SECRET) >= {"KEY", "SECRET", "TOKEN", "PASSWORD"}
    masked = __import__("pylon.cli", fromlist=["_redact"])._redact(
        "OPENAI_API_KEY", "sk-proj-AAAABBBBCCCCDDDD")
    assert "sk-proj" not in masked, masked
    assert masked.startswith("set"), masked
