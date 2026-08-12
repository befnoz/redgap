"""Render a human-readable Markdown coverage report."""

from __future__ import annotations

from collections.abc import Sequence

from redgap.models import GapType, Technique, Verdict

_GAP_EXPLANATION = {
    GapType.RULE: "telemetry present, but no rule fired (closeable by writing a rule)",
    GapType.BASE_RATE: "too noisy for a single-event rule; needs correlation (roadmap)",
    GapType.VISIBILITY: "the collector saw nothing (missing data source; roadmap)",
}


def markdown_report(
    catalog: Sequence[Technique],
    verdicts: Sequence[Verdict],
    *,
    mode: str,
    run_id: str,
    generated_at: str,
) -> str:
    by_id = {v.technique_id: v for v in verdicts}
    ordered = [t for t in catalog if t.id in by_id]
    detected = sum(1 for t in ordered if by_id[t.id].detected)

    out: list[str] = []
    out.append("# RedGap coverage report")
    out.append("")
    out.append(f"- Mode: **{mode}**")
    out.append(f"- Run: `{run_id}`")
    out.append(f"- Generated: {generated_at}")
    out.append("")
    out.append(f"**{detected} / {len(ordered)} techniques detected.**")
    out.append("")
    out.append("| # | ATT&CK | Technique | Tactic | Detected | Gap | Firing rule |")
    out.append("|---|--------|-----------|--------|----------|-----|-------------|")
    for i, tech in enumerate(ordered, 1):
        v = by_id[tech.id]
        detected_cell = "yes" if v.detected else "no"
        if v.unexpected:
            detected_cell += " (regression)"
        gap_cell = "-" if v.detected else v.gap_type.value
        rules = ", ".join(v.firing_rules) if v.firing_rules else "-"
        tactic = " / ".join(tech.tactics)
        out.append(
            f"| {i} | {tech.id} | {tech.name} | {tactic} | {detected_cell} | {gap_cell} | {rules} |"
        )
    out.append("")

    gaps = [t for t in ordered if not by_id[t.id].detected]
    if gaps:
        out.append("## Gaps")
        out.append("")
        out.append("A gap is a finding, not an error — each names why detection did not fire:")
        out.append("")
        for tech in gaps:
            v = by_id[tech.id]
            reason = _GAP_EXPLANATION.get(v.gap_type, v.gap_type.value)
            line = f"- **{tech.id} {tech.name}** — {v.gap_type.value}: {reason}"
            if v.candidates_excluded:
                line += (
                    f" (note: {v.candidates_excluded} rule(s) tagged to this technique were "
                    f"excluded at load — see warnings)"
                )
            out.append(line)
        out.append("")

    out.append("## Evidence")
    out.append("")
    out.append("Every detection is traceable to a rule and the exact event fields it matched:")
    out.append("")
    any_evidence = False
    for tech in ordered:
        v = by_id[tech.id]
        for e in v.evidence:
            any_evidence = True
            fields = ", ".join(f"`{k}`={val!r}" for k, val in sorted(e.matched_fields.items()))
            out.append(f"- **{tech.id}** — rule `{e.rule_id}` on event `{e.event_id}`: {fields}")
    if not any_evidence:
        out.append("- (no detections in this run)")
    out.append("")
    return "\n".join(out)
