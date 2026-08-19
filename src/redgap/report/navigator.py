"""Emit a MITRE ATT&CK Navigator layer (v4.5) from the coverage verdicts.

Drop the resulting JSON into https://mitre-attack.github.io/attack-navigator/ to see
the coverage heatmap: green = detected, red = gap. This is the "red gaps" the tool is
named for, made visible.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from redgap.models import Technique, Verdict

DETECTED_COLOR = "#2e7d32"  # green
GAP_COLOR = "#c62828"  # red

_TACTIC_SHORTNAME = {
    "Reconnaissance": "reconnaissance",
    "Resource Development": "resource-development",
    "Initial Access": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Defense Evasion": "defense-evasion",
    "Credential Access": "credential-access",
    "Discovery": "discovery",
    "Lateral Movement": "lateral-movement",
    "Collection": "collection",
    "Command and Control": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
}


def _tactic_shortname(tactic: str) -> str:
    return _TACTIC_SHORTNAME.get(tactic, tactic.lower().replace(" ", "-"))


def navigator_layer(
    catalog: Sequence[Technique],
    verdicts: Sequence[Verdict],
    *,
    name: str = "RedGap coverage",
    attack_version: str = "16",
) -> dict[str, Any]:
    by_id = {v.technique_id: v for v in verdicts}
    techniques: list[dict[str, Any]] = []
    for tech in catalog:
        v = by_id.get(tech.id)
        if v is None:
            continue
        if v.detected:
            comment = "detected by " + ", ".join(v.firing_rules)
        else:
            comment = f"gap ({v.gap_type.value})"
        # Emit one entry PER tactic the technique maps to. Navigator scopes a colored
        # cell to its `tactic`, so a multi-tactic technique (e.g. T1548.001 = Privilege
        # Escalation + Defense Evasion) must appear once per column - otherwise it reads
        # covered in one tactic and blank in the other, contradicting coverage.md/json.
        for tactic in tech.tactics or ("",):
            techniques.append(
                {
                    "techniqueID": tech.id,
                    "tactic": _tactic_shortname(tactic) if tactic else "",
                    "color": DETECTED_COLOR if v.detected else GAP_COLOR,
                    "comment": comment,
                    "enabled": True,
                    "metadata": [
                        {"name": "gap_type", "value": v.gap_type.value},
                        {"name": "firing_rules", "value": ", ".join(v.firing_rules) or "none"},
                    ],
                }
            )

    return {
        "name": name,
        "versions": {"attack": attack_version, "navigator": "4.19.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "RedGap offense<->detection coverage. Green = detected by a Sigma rule; "
            "red = gap. Verdicts are deterministic (logs + rules), not AI-generated."
        ),
        "techniques": techniques,
        "legendItems": [
            {"label": "detected", "color": DETECTED_COLOR},
            {"label": "gap (uncovered)", "color": GAP_COLOR},
        ],
        "hideDisabled": False,
        "showTacticRowBackground": False,
        "sorting": 0,
    }
