"""Build the canonical coverage.json structure from the engine's verdicts."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from redgap.models import CoverageReport, CoverageRow, Technique, Verdict


def coverage_dict(
    catalog: Sequence[Technique],
    verdicts: Sequence[Verdict],
    *,
    mode: str,
    run_id: str,
    generated_at: str,
    tool_versions: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The full, machine-readable coverage result (what gets written to coverage.json).

    Includes the per-verdict evidence trail (firing rule id + matched event id +
    matched fields) so every ``detected: true`` is hand-verifiable.
    """
    by_id = {v.technique_id: v for v in verdicts}
    report = CoverageReport(
        mode=mode,
        run_id=run_id,
        generated_at=generated_at,
        rows=[
            CoverageRow(
                technique_id=t.id,
                name=t.name,
                tactics=t.tactics,
                executed=by_id[t.id].executed,
                telemetry_present=by_id[t.id].telemetry_present,
                detected=by_id[t.id].detected,
                gap_type=by_id[t.id].gap_type,
                firing_rules=by_id[t.id].firing_rules,
            )
            for t in catalog
            if t.id in by_id
        ],
        tool_versions=tool_versions or {},
    )

    techniques: list[dict[str, Any]] = []
    for tech in catalog:
        v = by_id.get(tech.id)
        if v is None:
            continue
        techniques.append(
            {
                "id": tech.id,
                "name": tech.name,
                "tactics": list(tech.tactics),
                "executed": v.executed,
                "telemetry_present": v.telemetry_present,
                "detected": v.detected,
                "gap_type": v.gap_type.value,
                "expected_gap_type": v.expected_gap_type.value,
                "unexpected": v.unexpected,
                "candidates_evaluated": v.candidates_evaluated,
                "candidates_excluded": v.candidates_excluded,
                "firing_rules": list(v.firing_rules),
                "matched_event_ids": list(v.matched_event_ids),
                "evidence": [
                    {
                        "rule_id": e.rule_id,
                        "rule_title": e.rule_title,
                        "event_id": e.event_id,
                        "matched_fields": dict(e.matched_fields),
                    }
                    for e in v.evidence
                ],
            }
        )

    return {
        "tool": "redgap",
        "mode": mode,
        "run_id": run_id,
        "generated_at": generated_at,
        "tool_versions": tool_versions or {},
        "summary": report.summary,
        "techniques": techniques,
    }
