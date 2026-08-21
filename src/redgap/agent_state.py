"""Adaptive-planner state and the attack-path artifact (stdlib + catalog only).

Kept out of :mod:`redgap.planner` so the offline heuristic path and the pure state
projection are unit-testable without the ``anthropic`` SDK. Nothing here computes a
verdict: :func:`state_view` reads the engine's deterministic verdict cache and catalog
metadata, and :func:`build_attack_path` *copies* the detection-authored fields
(``detected``/``gap_type``/``firing_rules``) while the planner-authored ``reason`` block is
the only thing a planner writes. The attack-path is a narrative lens over the grid, never a
competing source of truth - it and ``coverage.json`` both read the same ``engine._verdicts``,
so they cannot disagree on any ``detected``.
"""

from __future__ import annotations

from dataclasses import dataclass

from redgap.catalog import BY_ID


@dataclass(frozen=True)
class StepRecord:
    """One executed step in the order the planner chose it.

    ``chosen_by`` and ``explanation`` are set by the PLANNER (only it knows whether the
    model or the deterministic fallback picked this step); the shared ToolExecutor never
    sets them. ``detected``/``gap_type``/``firing_rules`` are copied from the deterministic
    verdict the engine already computed.
    """

    step: int  # 1-based order the planner chose
    technique_id: str
    tactics: tuple[str, ...]  # verbatim from BY_ID[id].tactics (Title-Case-with-spaces)
    detected: bool
    gap_type: str  # verdict gap_type value ("" when detected)
    firing_rules: tuple[str, ...]
    chosen_by: str  # "llm" | "heuristic" | "heuristic-fallback"
    explanation: str  # planner-authored reason text


def step_record(
    step: int, technique_id: str, result: dict, *, chosen_by: str, explanation: str
) -> StepRecord:
    """Build a StepRecord from a deterministic ``engine.run_technique`` result dict.

    ``chosen_by`` and ``explanation`` are supplied by the caller (the planner), because only
    the planner knows whether the model or the deterministic fallback chose this technique.
    """
    detected = bool(result["detected"])
    return StepRecord(
        step=step,
        technique_id=technique_id,
        tactics=tuple(BY_ID[technique_id].tactics),
        detected=detected,
        gap_type="" if detected else str(result["gap_type"]),
        firing_rules=tuple(result.get("firing_rules", ())),
        chosen_by=chosen_by,
        explanation=explanation,
    )


def state_view(engine, history: list[StepRecord]) -> dict:
    """Pure, gap-oriented projection of the deterministic verdict cache for the planner.

    Reads ``engine._verdicts`` (via ``engine.techniques()``) and ``BY_ID`` only; MUTATES
    NOTHING. Every tactic string is read verbatim from ``BY_ID[id].tactics`` - no case
    transform anywhere. The model consumes this; it never writes any of it.
    """
    remaining = [tid for tid in engine.techniques() if tid not in engine._verdicts]
    touched_tactics = {t for r in history for t in r.tactics}
    gap_tactics = {t for r in history if not r.detected for t in r.tactics}
    reachable_tactics = {t for tid in remaining for t in BY_ID[tid].tactics}
    detected_count = sum(1 for r in history if r.detected)
    return {
        "steps_taken": len(history),
        "run": [
            {
                "technique_id": r.technique_id,
                "tactics": list(r.tactics),
                "detected": r.detected,
                "gap_type": r.gap_type,
            }
            for r in history
        ],
        "remaining_techniques": remaining,  # pick-list == allowlist (catalog minus executed)
        "detected_count": detected_count,
        "gap_count": len(history) - detected_count,
        "gaps": [
            {"technique_id": r.technique_id, "tactics": list(r.tactics), "gap_type": r.gap_type}
            for r in history
            if not r.detected
        ],
        "tactics_untouched": sorted(reachable_tactics - touched_tactics),
        "tactics_with_open_gaps": sorted(gap_tactics & reachable_tactics),
        "tactics_all_detected": sorted(touched_tactics - gap_tactics),
    }


def build_attack_path(
    engine, history: list[StepRecord], planner_label: str, *, stop_reason: str = "converged"
) -> dict:
    """The ``redgap.attack_path/v1`` artifact. Detection-authored fields are COPIED from the
    deterministic verdicts; the planner-authored ``reason`` block is the only thing a planner
    wrote. A reviewer can see in the JSON that the model never touches a verdict."""
    steps = [
        {
            "step": r.step,
            "technique_id": r.technique_id,
            "name": BY_ID[r.technique_id].name,
            "tactics": list(r.tactics),
            "detected": r.detected,  # detection-authored (copied)
            "gap_type": r.gap_type,
            "firing_rules": list(r.firing_rules),
            "reason": {  # planner-authored (the ONLY block a planner writes)
                "explanation": r.explanation,
                "source": r.chosen_by,
            },
        }
        for r in history
    ]
    detected = sum(1 for r in history if r.detected)
    gap_ids = [r.technique_id for r in history if not r.detected]
    tactics_covered = len({t for r in history for t in r.tactics})
    return {
        "schema": "redgap.attack_path/v1",
        "tool": "redgap",
        "mode": engine.mode,
        "run_id": engine.run_id,
        "generated_at": engine.generated_at,
        "planner": planner_label,
        "steps": steps,
        "stop": {"reason": stop_reason, "steps_taken": len(history)},
        "summary": {
            "steps": len(history),
            "detected": detected,
            "gaps": len(gap_ids),
            "gap_techniques": gap_ids,
            "tactics_covered": tactics_covered,
        },
    }


def render_attack_path(attack_path: dict) -> str:
    """Human-readable killchain markdown over the attack-path JSON. A narrative lens; the
    authoritative full grid stays in coverage.json - both read the same verdicts."""
    out: list[str] = []
    out.append(f"# RedGap attack path ({attack_path['planner']}, {attack_path['mode']})")
    out.append("")
    chain = " -> ".join(
        dict.fromkeys(tac for s in attack_path["steps"] for tac in s["tactics"])
    )  # ordered-unique tactic chain
    out.append(f"**Chain:** {chain}" if chain else "**Chain:** (no steps)")
    out.append("")
    out.append("| # | Technique | ID | Tactic | Verdict | Rules | Why chosen (source) |")
    out.append("|---|-----------|----|--------|---------|-------|---------------------|")
    for s in attack_path["steps"]:
        verdict = "detected" if s["detected"] else f"GAP ({s['gap_type']})"
        rules = ", ".join(s["firing_rules"]) or "-"
        why = f"{s['reason']['explanation']} ({s['reason']['source']})"
        out.append(
            f"| {s['step']} | {s['name']} | {s['technique_id']} | "
            f"{' / '.join(s['tactics'])} | {verdict} | {rules} | {why} |"
        )
    out.append("")
    gap_ids = attack_path["summary"]["gap_techniques"]
    if gap_ids:
        out.append("## Gaps on this path")
        out.append("")
        out.append(
            "Techniques the chain surfaced as undetected - point `redgap audit` at your rules "
            "to see which are SILENT (tagged but never firing on real telemetry):"
        )
        out.append("")
        for s in attack_path["steps"]:
            if not s["detected"]:
                out.append(f"- **{s['technique_id']} {s['name']}** - {s['gap_type']} gap")
        out.append("")
    st = attack_path["stop"]
    out.append(
        f"_Agent stopped: {st['reason']} after {st['steps_taken']} step(s). "
        f"The verdict is engine-computed from (events, rules); the planner only ordered the "
        f"chain and decided when to stop._"
    )
    out.append("")
    return "\n".join(out)
