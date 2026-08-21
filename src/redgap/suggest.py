"""``redgap suggest`` - the thesis, made literal: an optional LLM drafts a candidate Sigma
rule for a rule-gap, and the SAME deterministic engine re-runs it to decide whether it
actually closes the gap. The model writes rule *text*; only the engine grants green.

Two layers, cleanly split:

* :func:`judge_candidate` - PURE and deterministic. Given a candidate rule (from anywhere)
  it re-evaluates it against the real captured telemetry and labels it
  ``closes`` / ``no_fire`` / ``over_broad`` / ``untagged`` / ``unevaluable``. No LLM, fully
  testable offline. This is the honesty-critical half.
* :func:`draft_rule` - the OPT-IN LLM half (lazy ``anthropic``). It only produces candidate
  text; it never decides the label.
"""

from __future__ import annotations

import os

from redgap.detection.engine import UnsupportedFeature, rule_matches
from redgap.detection.sigma_ast import RuleError, parse_rule
from redgap.target import Target

DEFAULT_MODEL = "claude-haiku-4-5"

SYSTEM = (
    "You are a detection engineer. Given a benign ATT&CK technique and the REAL process-"
    "creation telemetry it produced, write ONE minimal Sigma rule (YAML only) that would fire "
    "on that telemetry. Use only these fields: Image, CommandLine, ParentImage, User. Tag it "
    "with the exact ATT&CK technique id. Output ONLY the YAML - no prose, no code fences. Your "
    "rule is a CANDIDATE: RedGap's engine, not you, decides whether it actually fires."
)


def _parent(tid: str) -> str:
    return tid.split(".")[0]


def judge_candidate(candidate_yaml: str, technique_id: str, events_by_technique: dict) -> dict:
    """Re-evaluate a candidate rule against real telemetry and label it. Pure/deterministic.

    ``closes``      - fires on the target technique, on nothing else, tagged to it.
    ``over_broad``  - fires on the target BUT also on unrelated techniques' telemetry.
    ``untagged``    - fires only on the target but the draft omitted the ATT&CK tag, so a real
                      coverage run would not credit it.
    ``no_fire``     - does not fire on the target technique's telemetry.
    ``unevaluable`` - the candidate is malformed or uses a feature outside RedGap's subset.
    """
    try:
        rule = parse_rule(candidate_yaml, path="<llm-draft>")
    except RuleError as exc:
        return {"status": "unevaluable", "technique_id": technique_id, "reason": str(exc)}

    def fires(events: list) -> bool | None:
        try:
            return any(rule_matches(rule, e) is not None for e in events)
        except UnsupportedFeature:
            return None  # a value leaf hit an unsupported feature at eval time

    on_target = fires(events_by_technique.get(technique_id, []))
    if on_target is None:
        return {
            "status": "unevaluable",
            "technique_id": technique_id,
            "reason": "eval-time unsupported feature",
        }

    also_fires = sorted(
        tid
        for tid, evs in events_by_technique.items()
        if tid != technique_id and fires(evs) is True
    )
    tagged = technique_id in rule.technique_ids or any(
        _parent(rid) == technique_id for rid in rule.technique_ids
    )

    if not on_target:
        status = "no_fire"
    elif also_fires:
        status = "over_broad"
    elif not tagged:
        status = "untagged"
    else:
        status = "closes"

    return {
        "status": status,
        "technique_id": technique_id,
        "rule_id": rule.id,
        "rule_title": rule.title,
        "tagged": tagged,
        "fires_target": bool(on_target),
        "also_fires": also_fires,
    }


def draft_rule(
    technique_id: str,
    technique_name: str,
    events: list,
    *,
    client=None,
    model: str | None = None,
) -> str:
    """OPT-IN: ask an Anthropic model to draft a candidate Sigma rule. Returns YAML text; it
    is never trusted as a verdict - hand it straight to :func:`judge_candidate`."""
    model = model or os.getenv("REDGAP_LLM_MODEL", DEFAULT_MODEL)
    sample = "\n".join(
        f"- Image: {e.get('Image', '')}\n  CommandLine: {e.get('CommandLine', '')}"
        for e in events[:6]
    )
    prompt = (
        f"Technique: {technique_id} {technique_name}\n"
        f"Real captured telemetry:\n{sample}\n\n"
        f"Write one Sigma rule (YAML only) tagged attack.{technique_id.lower()} that fires on it."
    )
    if client is None:
        import anthropic  # lazy: only the opt-in draft path needs the SDK

        client = anthropic.Anthropic()
    resp = client.messages.create(
        model=model,
        max_tokens=800,
        system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    parts = []
    for block in getattr(resp, "content", []):
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    text = "".join(parts).strip()
    # strip accidental code fences if the model added them despite instructions
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    return text.strip()


def suggest_for_gaps(target: Target, gaps: list[tuple[str, str]], *, client=None) -> list[dict]:
    """For each (technique_id, name) rule-gap: draft a rule (LLM) then judge it (engine).
    Returns one record per gap with the drafted YAML and the engine's deterministic label."""
    events_by_technique = target.events_by_technique()
    out: list[dict] = []
    for tid, name in gaps:
        yaml_text = draft_rule(tid, name, events_by_technique.get(tid, []), client=client)
        verdict = judge_candidate(yaml_text, tid, events_by_technique)
        out.append(
            {"technique_id": tid, "name": name, "candidate_yaml": yaml_text, "verdict": verdict}
        )
    return out
