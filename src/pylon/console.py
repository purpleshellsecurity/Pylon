#!/usr/bin/env python3
"""Terminal output: colour where it helps, plain text everywhere it might not.

Colour is a convenience and never carries meaning on its own. Every heading
this module paints reads identically with the escapes stripped, because they
WILL be stripped: piped to a file, read in CI, pasted into a ticket.

Three things have to be true before an escape is written.

    The stream is a terminal.  A redirect gets clean text.
    NO_COLOR is unset or empty.  The convention at no-color.org: present and
                                 non-empty means suppress colour, whatever the
                                 value is.
    Windows agreed.             Windows 10 and later can interpret escapes, but
                                only after the console host is asked. Without
                                that the escapes print as literal garbage, and
                                a report that opens with "<-[94mMEASURED" is
                                worse than one with no colour at all.

The escapes themselves are pure ASCII -- ESC is 0x1b, the rest is `[94m` --
so they cannot repeat the cp1252 UnicodeEncodeError that a single arrow
character caused on a Windows console. That failure was about the CHARACTERS
in the text, and everything this module writes stays inside ASCII.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import textwrap

# Blue for a section, green for a label inside one. Both are the BRIGHT
# variants (94, 92) rather than the plain ones (34, 32): the plain codes render
# near-black on the default dark console and are unreadable there.
#
# Two levels and no more. A third colour would have to mean something, and
# colour is not allowed to mean anything here -- every heading reads
# identically with the escapes stripped, because they will be.
BLUE = "\033[94m"
GREEN = "\033[92m"
RESET = "\033[0m"


# STD_OUTPUT_HANDLE and STD_ERROR_HANDLE. Which one matters: the flag is set
# per console handle, so enabling it on stdout and then writing escapes to
# stderr prints "<-[94mDESIGN" in PowerShell. Half of what this tool paints
# goes to stderr.
_STD_HANDLE = {1: -11, 2: -12}


def _windows_vt(fd: int = 1) -> bool:
    """Ask the Windows console host to interpret escape sequences on `fd`.

    Microsoft's documented pattern: read the current mode, OR the flag in, set
    it back, and treat failure as a down-level system to degrade from rather
    than an error to raise. Everything is wrapped, because this runs on
    machines where there is no console attached at all.

    PowerShell 7 in Windows Terminal has VT on already and this is a no-op
    that returns True; Windows PowerShell 5.1 in conhost needs the call, and
    got it for stdout only.
    """
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        handle = ctypes.c_void_p(
            kernel32.GetStdHandle(_STD_HANDLE.get(fd, -11)))
        if not handle:
            return False
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _on_windows() -> bool:
    """Whether this is Windows, as its own function so a test can say "pretend
    it is not" WITHOUT touching `os.name`.

    A test patched `console.os.name`, and `console.os` IS the os module, so it
    set `os.name` process-wide. `pathlib` reads `os.name` to choose its Path
    flavour, so every `Path()` on Windows then tried to build a PosixPath and
    raised -- including inside pytest's own failure reporting, which turned four
    assertions into an INTERNALERROR that hid the rest of the run.
    """
    return os.name == "nt"


def supported(stream=None) -> bool:
    stream = stream if stream is not None else sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        if not stream.isatty():
            return False
    except Exception:
        return False
    if _on_windows():
        # The descriptor of the stream being painted, not stdout's. A stream
        # with no fileno -- a StringIO in a test, a captured pipe -- is asked
        # about stdout, which is what it would have got before.
        try:
            fd = stream.fileno()
        except Exception:
            fd = 1
        return _windows_vt(fd)
    return True


def heading(text: str, stream=None) -> str:
    """A section heading, blue where the terminal will take it.

    Returns the string rather than printing it, so a caller can put it in an
    f-string and a test can assert on the plain text.
    """
    return f"{BLUE}{text}{RESET}" if supported(stream) else text


def label(text: str, stream=None) -> str:
    """A label inside a section -- a field name, a table, a subheading."""
    return f"{GREEN}{text}{RESET}" if supported(stream) else text


def _wrap(line: str, width: int) -> list[str]:
    """One line, wrapped, with a bullet's continuation lines hanging under its
    text rather than under its dash."""
    if len(line) <= width:
        return [line]
    body = line.lstrip()
    indent = " " * (len(line) - len(body))
    hang = indent + ("  " if body.startswith(("- ", "* ")) else "")
    return textwrap.wrap(body, width=width, initial_indent=indent,
                         subsequent_indent=hang) or [line]


def markdown(text: str, stream=None) -> str:
    """Markdown, rendered for a terminal -- or handed back untouched.

    `design tuning` writes markdown because its output is a document: piped to
    a file, committed, pasted into a ticket. On a terminal that document reads
    as punctuation -- `## Entra RoleManagement`, `**Log table** — ...`, a fence
    around the KQL, and one 300-character paragraph per noise rule running off
    the right edge.

    So the markup is rendered where a terminal will take colour, and returned
    byte-for-byte where it will not. That keeps one rule for the whole tool:
    `pylon design tuning > x.md` and `--out x.md` produce identical, valid
    markdown, and nothing decides what a FILE contains by looking at a
    terminal.

    Nothing is dropped. The hashes, asterisks and fences go; every word stays.
    """
    if not supported(stream):
        return text

    width = max(40, min(shutil.get_terminal_size((100, 24)).columns - 2, 96))
    out: list[str] = []
    fenced = False
    for line in text.splitlines():
        if line.startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            # The query is the one thing here a reader copies verbatim, so it
            # is never wrapped -- a wrapped KQL line is a broken one.
            out.append("    " + line)
            continue
        if line.startswith("#"):
            out.append(heading(line.lstrip("# ").strip(), stream))
            continue
        bold = re.match(r"^(\s*(?:[-*] )?)\*\*(.+?)\*\*(.*)$", line)
        if bold:
            lead, name, rest = bold.groups()
            painted = lead + label(name, stream) + rest
            # Wrapped on the PLAIN text and painted after, because an escape
            # sequence counts as characters to textwrap and would shorten the
            # line it is on by nine.
            plain = lead + name + rest
            if len(plain) <= width:
                out.append(painted)
            else:
                wrapped = _wrap(plain, width)
                first = wrapped[0].replace(name, label(name, stream), 1)
                out.extend([first, *wrapped[1:]])
            continue
        out.extend(_wrap(line, width))
    return "\n".join(out)
