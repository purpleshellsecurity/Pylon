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
import sys

# Bright blue. Chosen over plain blue (SGR 34) because 34 renders near-black
# on the default dark console and is unreadable there.
BLUE = "\033[94m"
RESET = "\033[0m"


def _windows_vt() -> bool:
    """Ask the Windows console host to interpret escape sequences.

    Microsoft's documented pattern: read the current mode, OR the flag in, set
    it back, and treat failure as a down-level system to degrade from rather
    than an error to raise. Everything is wrapped, because this runs on
    machines where there is no console attached at all.
    """
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        handle = ctypes.c_void_p(kernel32.GetStdHandle(-11))  # STD_OUTPUT_HANDLE
        if not handle:
            return False
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


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
    if os.name == "nt":
        return _windows_vt()
    return True


def heading(text: str, stream=None) -> str:
    """A section heading, blue where the terminal will take it.

    Returns the string rather than printing it, so a caller can put it in an
    f-string and a test can assert on the plain text.
    """
    return f"{BLUE}{text}{RESET}" if supported(stream) else text
