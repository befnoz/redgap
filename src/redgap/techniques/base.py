"""The shape of a benign technique."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TechniqueSpec:
    """The benign commands that emit a technique's observable artifact in the lab.

    ``commands`` run in order; ``cleanup`` runs afterwards (and is idempotent) so a
    repeated run leaves no residue. Behaviour is intentionally data — the runner
    (LIVE) executes these strings inside the disposable lab container; nothing here
    executes on import.
    """

    technique_id: str
    commands: tuple[str, ...]
    cleanup: tuple[str, ...] = ()
    note: str = ""
