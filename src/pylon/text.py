"""Text primitives, in one place.

`library._slug` and `report.slugify` were two implementations of the same
transform that disagreed on the empty case — `_slug` returned `""` and
`slugify` returned `"unnamed"` — and only one of them was None-safe. Callers
had come to depend on BOTH behaviours: `catalog.table_techniques` filters on
`if slug(o)`, so a `"unnamed"` fallback there would silently keep every empty
operation, while `report` names files with it and cannot emit `".md"`.

So the fallback is the caller's decision and is not baked into the transform.
Moved here rather than copied beside either one: two copies of one truth is
this codebase's scar, and the same move has been made before.

`plural` arrived the same way. It lived in `reportkit`, which says of itself
that it is presentation only -- and agreeing a noun with a number is not
presentation. `cli.py` was already importing it from there for terminal output,
and the modules that write the document's own sentences (`chain`, `gapscan`,
`rulehealth`, `solutions`, `connectors`, `contenthub`) needed it too. None of
them should have to import a stylesheet to say "1 resource" instead of
"1 resource(s)".
"""

import re


def slug(value: str | None) -> str:
    """Lowercase hyphen slug of `value` (non-alphanumerics to '-'); '' if empty.

    None-safe, because `_slug` was and callers rely on it.
    """
    return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")


def slugify(value: str | None) -> str:
    """`slug`, but never empty — falls back to 'unnamed' so a filename stem is
    always usable. The naming convention for anything that becomes a path."""
    return slug(value) or "unnamed"


def plural(n, singular: str, many: str | None = None) -> str:
    """`1 window`, `3 windows`.

    The `(s)` habit is honest and it is also unmistakably machine output. A
    document a person wrote agrees its nouns with its numbers.

    The NOUN only. A sentence whose verb follows the count has to agree that
    too, and the caller is the only thing that knows the verb -- see the
    `claims`/`claim` pairs in `gapscan`.
    """
    word = singular if n == 1 else (many or singular + "s")
    return f"{n:,} {word}"


def clip(text: str, limit: int) -> str:
    """`text`, and an ellipsis if this cut it short.

    Several places sliced a string with a bare `[:n]`. A reason cut mid-word
    reads as a reason that ended there, and the reader has no way to tell that
    something dropped the rest. One character says so.

    The cut lands on a word boundary when there is one within fifteen
    characters of the limit, because "...is putting" is a sentence and
    "...is putti" is a glitch. A string with no space near the limit -- an id,
    a hash, a base64 blob -- is cut where the limit falls.

    Identifiers are not clipped at all. In the report's rule table a name cut
    at 52 characters made two rules sharing a long prefix indistinguishable in
    the one column a reader uses to go and find them.
    """
    if len(text) <= limit:
        return text
    cut = text[:limit].rstrip()
    space = cut.rfind(" ")
    # `space > 0` first. `rfind` returns -1 when there is no space at all, and
    # -1 satisfies "within fifteen characters of the limit" for any limit under
    # sixteen -- so a spaceless string cut at 10 lost its last character to a
    # word boundary that was never there.
    if space > 0 and space >= limit - 15:
        cut = cut[:space].rstrip()
    return cut + "\u2026"
