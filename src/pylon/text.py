"""Filename-slug primitives, in one place.

`library._slug` and `report.slugify` were two implementations of the same
transform that disagreed on the empty case — `_slug` returned `""` and
`slugify` returned `"unnamed"` — and only one of them was None-safe. Callers
had come to depend on BOTH behaviours: `catalog.table_techniques` filters on
`if slug(o)`, so a `"unnamed"` fallback there would silently keep every empty
operation, while `report` names files with it and cannot emit `".md"`.

So the fallback is the caller's decision and is not baked into the transform.
Moved here rather than copied beside either one, the way `style.py` was moved
out of `diagnostics.py`: two copies of one truth is this codebase's scar.
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
