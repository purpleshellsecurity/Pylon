"""Where a KQL string ends and a comment begins.

Four modules needed the same thing -- "the query with its comments gone" -- and
each wrote its own `re.sub(r"//[^\n]*", "", kql)`. That pattern is wrong in one
specific, common way: the `//` in a URL is inside a string literal.

    | where Uri has "https://acct.blob.core.windows.net/" and OperationName == "PutBlobb"

Stripping from the `//` deletes the closing quote and the rest of the line, so
everything after it leaves whatever check was reading the result. That is the
shipping direction -- the `"PutBlobb"` typo validated clean on this line and
errored on its own -- and in `contracts` it was worse: the unbalanced quote left
behind made the following string blank swallow to the NEXT quote, wherever that
was.

So the tokeniser lives here once, and the substitution stays at each call site,
because they want different fillers: a check reading identifier POSITIONS wants
`""` left standing, and one reading nothing inside the quotes wants a space.
"""

from __future__ import annotations

import re

# Strings before comments, and verbatim (`@"..."`) before plain, so the longest
# real token wins at each position. KQL doubles the quote inside a verbatim
# string and backslash-escapes it inside a plain one.
TOKEN = re.compile(
    r'@"(?:""|[^"])*"'
    r"|@'(?:''|[^'])*'"
    r'|"(?:\\.|[^"\\])*"'
    r"|'(?:\\.|[^'\\])*'"
    r"|//[^\n]*"
)


def _is_comment(text: str) -> bool:
    return text.startswith("//")


def strip_comments(kql: str) -> str:
    """Line comments removed, string literals kept exactly as written.

    For checks that read what is INSIDE the quotes -- an operation name, a
    status code -- which is most of them.
    """
    return TOKEN.sub(lambda m: "" if _is_comment(m.group(0)) else m.group(0), kql)


def blank(kql: str, *, string: str = '""', comment: str = "") -> str:
    """Comments and string CONTENTS replaced, clause shape kept.

    For checks that read identifier positions: a column-lookalike inside a value
    (`AUTHORIZATION` in `"MICROSOFT.AUTHORIZATION/..."`) is not a column
    reference, and a `|` inside a value is not a pipe.
    """
    return TOKEN.sub(lambda m: comment if _is_comment(m.group(0)) else string, kql)
