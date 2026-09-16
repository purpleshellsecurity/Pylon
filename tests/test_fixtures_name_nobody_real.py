"""Fixtures may name anything, so long as it is not a real resource.

THE DENY-LIST CANNOT GET THERE
------------------------------
`make-release.sh` refuses to publish a tree containing any of a list of known
tenant identifiers. That list has been widened three times, each time AFTER
something escaped into the tree:

    2026-09-12  a real subscription id reached a docstring   (caught)
    2026-09-12  a real principal object id reached a TEST    (NOT caught)
    2026-09-16  a real Azure OpenAI resource name reached four
                parametrised endpoints in tests/test_clients.py  (NOT caught)

The third is deliberately not quoted here. This file SHIPS, and a test that
names the resource is the leak whether or not it is explaining the rule -- the
release scan refused the tree over exactly this line before it was rewritten,
which is the third time that scan has tripped on its own documentation.

Two of the three were invisible to it, and both of those were in tests. The
reason is structural rather than careless: the scan asks "does this contain a
string I already know is real", so it can only ever catch kinds somebody has
already been burned by. A resource name is not derivable from a subscription id.
The next kind will be invisible too.

THIS ASKS THE OTHER QUESTION
----------------------------
Not "is it a known-real name" but "is it a known-FICTITIOUS one". Microsoft's
own documentation uses `contoso` and `fabrikam` for exactly this, and RFC 2606
reserves `example.com`. A hostname whose label is not on the approved list fails,
whether or not anyone has been burned by that particular name yet -- so a real
one cannot pass by being new.

Inverting it is only affordable because the surface is small: four distinct
labels across the whole tree at the time of writing. Do not extend this to
GUIDs. Azure's built-in role GUIDs are real on purpose and several detections
compare against exactly those, so an allow-list there would be a list of every
GUID in the catalogue, which is the deny-list again with more steps.

WHAT THIS DOES NOT COVER
------------------------
Hostnames. A workspace name, a resource-group name or a UPN in a fixture is
still only covered by the deny-list in `make-release.sh`. Those are harder,
because unlike a hostname they have no shape that says what they are -- the
lesson worth keeping is that the check is cheap wherever the data HAS a shape.
"""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCANNED = ("src", "tests", "scripts", "docs")

# Azure services whose hostname carries a customer-chosen resource name.
_ENDPOINT = re.compile(
    r"\b([A-Za-z0-9][A-Za-z0-9-]*)\."
    r"(?:openai\.azure\.com|vault\.azure\.net|blob\.core\.windows\.net"
    r"|queue\.core\.windows\.net|table\.core\.windows\.net|file\.core\.windows\.net"
    r"|azurewebsites\.net|servicebus\.windows\.net|documents\.azure\.com"
    r"|azurecr\.io|search\.windows\.net)\b"
)

# Roots a label may start with. `contoso` and `fabrikam` are Microsoft's own
# documentation tenants; `example` is RFC 2606; the rest are obvious
# placeholders that no registrar or subscription hands out as-is.
_FICTITIOUS = (
    "contoso", "fabrikam", "acme", "example", "test", "sample", "demo",
    "acct", "myaccount", "mystorage", "myvault", "my-", "your", "placeholder",
    "localhost", "resource", "workspace", "account",
)

# Literal placeholders: a label that is obviously a slot to fill in.
_PLACEHOLDER = re.compile(r"^(?:<.*>|\{.*\}|[A-Z][A-Z0-9_]*|\.\.\.)$")

# MICROSOFT'S OWN published endpoints, which are a different thing from a
# fictitious name and must not be renamed to one. `azurecliprod` is where the
# Azure CLI install script lives and the README tells the reader to curl it --
# swapping it for `contoso` would break the documented install.
#
# The distinction this list encodes is the one that matters: the risk is naming
# a resource THE USER OWNS. A vendor's public download host is not that. Each
# entry is a host anyone can already resolve from Microsoft's documentation.
_MICROSOFT_OWNED = {
    "azurecliprod",     # Azure CLI install script (docs/start-here.md, README)
}


def _files():
    for folder in SCANNED:
        base = ROOT / folder
        if not base.is_dir():
            continue
        for suffix in ("*.py", "*.md", "*.sh", "*.yml", "*.yaml", "*.json"):
            yield from base.rglob(suffix)


def _is_fictitious(label: str) -> bool:
    low = label.lower()
    return (low in _MICROSOFT_OWNED
            or low.startswith(_FICTITIOUS)
            or _PLACEHOLDER.match(label) is not None)


def test_there_are_endpoints_to_check():
    """A scan that finds nothing passes for ever and says nothing. If this
    fails, the regex stopped matching -- not the tree stopped containing."""
    found = [m for f in _files()
             for m in _ENDPOINT.findall(f.read_text(encoding="utf-8", errors="ignore"))]
    assert len(found) >= 3, f"found only {len(found)} Azure endpoints to check"


def test_every_azure_endpoint_names_a_fictitious_resource():
    """The check the deny-list cannot make: unknown means FAIL, not pass."""
    offenders = []
    for path in _files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for i, line in enumerate(text.splitlines(), 1):
            for label in _ENDPOINT.findall(line):
                if not _is_fictitious(label):
                    rel = path.relative_to(ROOT)
                    offenders.append(f"{rel}:{i}: {label}")
    assert offenders == [], (
        "these name a resource that is not a documented-fictitious one, and a "
        "real resource name published says the resource exists and invites a "
        "probe:\n  " + "\n  ".join(offenders) +
        "\n\nUse a `contoso`/`fabrikam`/`example` name, or add the root to "
        "_FICTITIOUS if it is genuinely a placeholder."
    )


@pytest.mark.parametrize("label,ok", [
    ("contoso-aoai", True),
    ("fabrikam", True),
    ("example-vault", True),
    ("acct", True),
    ("NAME", True),                 # an obvious slot
    ("<resource>", True),
    ("prod-eastus-aoai", False),    # the SHAPE that escaped, not the name
    ("corp-sentinel-prod", False),
    ("prod-eastus-kv", False),
    ("azurecliprod", True),         # Microsoft's own, not the user's
])
def test_the_rule_separates_the_two_kinds(label, ok):
    """Proven rather than asserted, and it names the string that got through:
    a check whose own logic is untested is a check nobody should trust."""
    assert _is_fictitious(label) is ok, label
