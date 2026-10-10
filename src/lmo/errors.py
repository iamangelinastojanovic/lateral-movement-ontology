"""Errors meant to be read by the person who typed the command.

Anything raised as :class:`LmoError` is caught at the top of the CLI and printed
as a single line, with no traceback. That distinction matters: a traceback tells
the reader something broke *inside* the program, and if it appears for something
as ordinary as running a command in the wrong order, it teaches them to ignore
tracebacks. Genuine defects still raise normally and still print a traceback,
which is what makes one worth reading.

Every message here follows the same shape: what went wrong, then what to do
about it.
"""

from __future__ import annotations


class LmoError(Exception):
    """A problem the user can fix, described in terms they can act on."""

    def __init__(self, problem: str, fix: str | None = None) -> None:
        self.problem = problem
        self.fix = fix
        super().__init__(problem if fix is None else f"{problem}\n  {fix}")
