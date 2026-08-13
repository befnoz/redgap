"""Core data model for RedGap.

These types are intentionally dependency-free (standard library only) so the
deterministic spine imports and tests without installing anything. Everything a
coverage run produces flows through these structures.

Trust-boundary note: a ``Verdict`` is produced only by the detection engine from
observed events and Sigma rules. Nothing here is ever set by a language model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# A normalized telemetry event is a flat mapping of Sigma-compatible field names
# (SigmaHQ Linux ``process_creation`` vocabulary: Image, CommandLine, ...) to values.
Event = dict[str, Any]


class GapType(StrEnum):
    """Why a technique was not detected.

    Making the *reason* explicit is the difference between a checklist and a
    coverage tool. See SCOPE.md for the taxonomy.
    """

    #: Detected — there is no gap.
    NONE = "none"
    #: Telemetry never carried the artifact (the sensor was blind). Roadmap: a
    #: higher-fidelity collector. Not used as an active gap in v0.1.
    VISIBILITY = "visibility"
    #: Telemetry is present but no rule matched. This is *closeable* by writing a
    #: rule — the remediation round-trip.
    RULE = "rule"
    #: A real signal exists but a single-event rule would be too noisy to ship;
    #: needs correlation (roadmap).
    BASE_RATE = "base_rate"


@dataclass(frozen=True)
class Technique:
    """A benign, MITRE ATT&CK-mapped technique in the catalog.

    Execution/cleanup behaviour lives in the ``techniques/`` modules; this record
    is pure metadata used by the planner, engine, and reports.
    """

    id: str  # ATT&CK technique id, e.g. "T1548.001"
    name: str  # current ATT&CK display name
    tactics: tuple[str, ...]  # e.g. ("Privilege Escalation", "Defense Evasion")
    description: str
    atomic_ref: str  # Atomic Red Team reference the benign test derives from
    #: What v0.1 expects for this technique. NONE means "should be detected".
    expected_gap_type: GapType = GapType.NONE

    def attack_tag(self) -> str:
        """The Sigma ``attack.tXXXX`` tag used to join rules to this technique."""
        return "attack." + self.id.lower()


@dataclass(frozen=True)
class Evidence:
    """A single, hand-verifiable reason a verdict is what it is."""

    rule_id: str
    rule_title: str
    event_id: str
    matched_fields: dict[str, str]  # field name -> the value that matched


@dataclass
class Verdict:
    """The deterministic result for one technique execution.

    ``detected`` is ``True`` iff at least one mapped rule fired on at least one
    collected event. It is a pure function of the events and rules — independent of
    the optional LLM planner and byte-identical whether or not it ran.
    """

    technique_id: str
    executed: bool
    telemetry_present: bool
    detected: bool
    gap_type: GapType
    firing_rules: tuple[str, ...] = ()
    matched_event_ids: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    #: What the catalog expected for this technique (NONE = expected detected).
    expected_gap_type: GapType = GapType.NONE
    #: How many rules were tagged to this technique and evaluated.
    candidates_evaluated: int = 0
    #: How many rules tagged to this technique were EXCLUDED at load (unsupported
    #: feature / unreadable) and therefore never got a chance to fire.
    candidates_excluded: int = 0
    #: True when a technique we expected to detect (expected_gap_type == NONE) was NOT
    #: detected — a regression, surfaced in the tool's own report, not only in pytest.
    unexpected: bool = False

    def __post_init__(self) -> None:
        # Invariant: detected and gap are mutually exclusive and exhaustive.
        if self.detected and self.gap_type is not GapType.NONE:
            raise ValueError("a detected technique must have GapType.NONE")
        if not self.detected and self.gap_type is GapType.NONE and self.executed:
            raise ValueError("an executed, undetected technique must name a gap type")


@dataclass
class CoverageRow:
    """One row of the coverage report (a technique joined to its verdict)."""

    technique_id: str
    name: str
    tactics: tuple[str, ...]
    executed: bool
    telemetry_present: bool
    detected: bool
    gap_type: GapType
    firing_rules: tuple[str, ...] = ()


@dataclass
class CoverageReport:
    """The full, engine-authored result of a run.

    This is what both planners return. The LLM narrative, if any, is carried
    separately and clearly labeled — never merged into these facts.
    """

    mode: str  # "replay" | "live"
    run_id: str
    generated_at: str  # ISO-8601, injected by the caller (no wall-clock in core)
    rows: list[CoverageRow] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)

    @property
    def summary(self) -> dict[str, Any]:
        detected = sum(1 for r in self.rows if r.detected)
        gaps: dict[str, int] = {}
        for r in self.rows:
            if not r.detected:
                gaps[r.gap_type.value] = gaps.get(r.gap_type.value, 0) + 1
        return {
            "techniques": len(self.rows),
            "detected": detected,
            "gaps": len(self.rows) - detected,
            "gaps_by_type": gaps,
        }
