# Changelog

Notable changes. Dates are the release date.

## 1.0.0 — 2026-09-14

First public release.

Pylon reads a Microsoft Sentinel tenant, says what it detects, and writes what
it does not. `analyze`, `recommend`, `tabledrift`, `validate` and `design list`
cost nothing and need no model provider. `design` generates detections and
playbooks and does.

What the release added, after a clean-room test found it:

- **A licence.** MIT. Without one nobody could legally use this.
- **Python 3.11 actually works.** It was promised in `requires-python` and the
  README, and `cli.py` did not compile on it — a backslash inside an f-string
  expression, which PEP 701 did not permit until 3.12, so every command
  including the free ones failed to import. CI tested 3.13 on Ubuntu alone.
- **Windows and macOS are tested.** The matrix is now 3 OSes x 3 Pythons, plus
  an install job that uses the README's own `uv tool install` command. Its
  first run failed six of nine cells; none of it was a regression, it was the
  first time anything but Ubuntu had looked.
- **The config file holding an API key is owner-only on Windows.**
  `chmod(0o600)` does not fail there — it succeeds, sets the read-only bit, and
  leaves the inherited ACL alone. It is an ACL now.
- **Every file read and written names its encoding.** A generated playbook
  contains fourteen characters the Windows default codepage cannot represent.
- **`design --resume` works on Windows.** Checkpoints were written through the
  locale codec rather than UTF-8.
- **A crash names the log and where to report it**, instead of printing a
  traceback. Ctrl-C exits 130 and says what the run spent.
- **The run log is bounded** at 50 runs, and a gate keeps credentials out of it
  in both directions — statically and at runtime.
- **PowerShell blocks declare the Graph modules they need**, which is both what
  the script checker wants and what a responder pasting one needs to know.
