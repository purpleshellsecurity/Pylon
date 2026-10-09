"""Exit policy for offline detection grading.

Exploratory grading can report a non-matching fixture as inconclusive.
Strict grading must never call missing behavioral evidence a pass.
"""


def grade_exit_status(
    *, noisy: int, errors: int, unreadable: int,
    known_silent: int, inconclusive: int, strict: bool = False,
) -> int:
    """Return nonzero for demonstrable failures, or any unproven strict case."""
    if any(value < 0 for value in (noisy, errors, unreadable, known_silent, inconclusive)):
        raise ValueError("grading counts cannot be negative")
    if noisy or errors or unreadable:
        return 1
    if strict and (known_silent or inconclusive):
        return 1
    return 0
