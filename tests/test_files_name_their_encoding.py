"""Every text file read or written must name its encoding.

Without `encoding=`, Python uses the locale's preferred encoding. On Linux and
macOS that is UTF-8 and nothing is noticed. On Windows it is the ANSI codepage
-- cp1252 in most of Europe and the Americas -- and Pylon's own output cannot be
represented in it.

A generated playbook contains 14 distinct non-ASCII characters: the box drawing
in the attack diagram, arrows, and the status emoji in the triage sections.
Writing one on a default Windows install raised

    UnicodeEncodeError: 'charmap' codec can't encode character '\\u2502'

from `path.write_text(text)` in the playbook loop. The README gives Windows
install instructions and CI tested Ubuntu only, so nothing saw it.

Checked by AST rather than grep: `write_text(_kql_header(d) + d.detection.kql +
"\\n")` has nested parentheses that a regex closes in the wrong place.
"""
import ast
from pathlib import Path

import pytest

ROOTS = ("src", "tests", "scripts")
TEXT_CALLS = {"read_text", "write_text"}


def _offenders():
    root = Path(__file__).resolve().parent.parent
    out = []
    for folder in ROOTS:
        for f in sorted((root / folder).rglob("*.py")):
            try:
                tree = ast.parse(f.read_text(encoding="utf-8"))
            except SyntaxError:          # a file targeting a newer Python
                continue
            for n in ast.walk(tree):
                if not isinstance(n, ast.Call):
                    continue
                named = {k.arg for k in n.keywords}
                if isinstance(n.func, ast.Attribute) and n.func.attr in TEXT_CALLS:
                    # `read_text(enc)` passes it positionally, which also counts.
                    if "encoding" in named or n.args:
                        continue
                    out.append(f"{f.relative_to(root)}:{n.lineno} {n.func.attr}()")
                elif isinstance(n.func, ast.Name) and n.func.id == "open":
                    if "encoding" in named:
                        continue
                    mode = next((a.value for a in n.args[1:2]
                                 if isinstance(a, ast.Constant)
                                 and isinstance(a.value, str)), "")
                    if "b" in mode:      # binary needs no encoding
                        continue
                    out.append(f"{f.relative_to(root)}:{n.lineno} open()")
    return out


def test_no_text_file_call_relies_on_the_locale_encoding():
    offenders = _offenders()
    assert offenders == [], (
        "these fall back to the locale encoding, which is cp1252 on a default "
        f"Windows install and cannot represent Pylon's own output: {offenders}")


def test_a_generated_playbook_really_does_need_utf8():
    """Guards the premise. If the output ever became pure ASCII this test would
    be the thing that says so, rather than the rule quietly costing nothing."""
    from pylon.playbook import document_template

    doc = document_template("azure", "StorageBlobLogs", "Blob Storage",
                            operation="GetBlob", technique="T1619")
    non_ascii = sorted({c for c in doc if ord(c) > 127})
    assert non_ascii, "playbooks are ASCII now; this rule may be relaxed"
    with pytest.raises(UnicodeEncodeError):
        doc.encode("cp1252")
    doc.encode("utf-8")
