"""The v0.1 technique catalog (metadata only).

Five benign, MITRE ATT&CK-mapped techniques forming a small kill-chain. Execution
and cleanup live in the ``techniques/`` modules; this file is the pure-data catalog
the engine, coverage join, and reports use. Names and IDs verified against
attack.mitre.org on 2026-08-11.

The mix is deliberate — three detections and two *different kinds* of gap — so the
coverage report demonstrates real gap intelligence rather than an all-green list.
"""

from __future__ import annotations

from redgap.models import GapType, Technique

CATALOG: tuple[Technique, ...] = (
    Technique(
        id="T1087.001",
        name="Account Discovery: Local Account",
        tactics=("Discovery",),
        description="Enumerate local accounts by reading /etc/passwd.",
        atomic_ref="T1087.001",
        expected_gap_type=GapType.NONE,  # detected
    ),
    Technique(
        id="T1057",
        name="Process Discovery",
        tactics=("Discovery",),
        description="List running processes with ps/top.",
        atomic_ref="T1057",
        # base-rate gap: ps/top are ubiquitous; a single-event rule would flood.
        # Real signal needs correlation (roadmap). We deliberately ship no rule.
        expected_gap_type=GapType.BASE_RATE,
    ),
    Technique(
        id="T1136.001",
        name="Create Account: Local Account",
        tactics=("Persistence",),
        description="Create a local account with useradd (nologin, no password).",
        atomic_ref="T1136.001",
        expected_gap_type=GapType.NONE,  # detected
    ),
    Technique(
        id="T1548.001",
        name="Abuse Elevation Control Mechanism: Setuid and Setgid",
        tactics=("Privilege Escalation", "Defense Evasion"),
        description="Set the setuid bit on an inert /bin/true copy after chown root.",
        atomic_ref="T1548.001",
        expected_gap_type=GapType.NONE,  # detected by a shipped SigmaHQ rule
    ),
    Technique(
        id="T1070.006",
        name="Indicator Removal: Timestomp",
        tactics=("Defense Evasion",),
        description="Alter file timestamps with touch -r/-t.",
        atomic_ref="T1070.006",
        # rule gap by default: telemetry is present but no rule ships. Closed in
        # the remediation round-trip (rules/roundtrip/timestomp_touch.yml).
        expected_gap_type=GapType.RULE,
    ),
)

BY_ID: dict[str, Technique] = {t.id: t for t in CATALOG}
