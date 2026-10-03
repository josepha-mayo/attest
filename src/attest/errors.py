"""Domain error codes — handlers map ``code`` to UX; nobody sniffs text.

Raising a ``ValueError`` and having a web handler branch on the message's
wording couples an English sentence to a control-flow decision: reword the
message and a handler silently stops matching. ``DomainError`` carries a
stable machine-readable ``code`` — the message stays free for humans (logs,
CLI), the code is the contract handlers translate (localized strings, status
mapping, dead-link pages).
"""

from __future__ import annotations


class DomainError(ValueError):
    """A domain-level rejection with a stable ``code``.

    Subclasses ``ValueError`` deliberately: every existing
    ``except ValueError`` boundary (CLI exits, the ``action`` 409 wrapper,
    form re-renders) keeps holding — the code adds routing information, it
    does not change who catches what.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
