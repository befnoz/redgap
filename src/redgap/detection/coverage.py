"""Coverage: join rules to techniques and compute the deterministic verdict.

For each technique we gather the events its execution produced, find the rules
tagged to that technique, and ask the engine whether any rule fires on any event.
``detected`` is a pure boolean from that. The whole ``Verdict`` is a pure function of
``(events, rules)`` — independent of any planner and byte-identical whether or not the
optional LLM ran.

Rules that were EXCLUDED at load (unsupported feature / unreadable) are threaded in so a
dropped closing rule cannot masquerade as a "no rule shipped" base-rate gap — the report
distinguishes "you wrote a rule we could not evaluate" from "there is no rule".
"""

from __future__ import annotations

from collections.abc import Sequence

from redgap.detection.engine import Event, rule_matches
from redgap.detection.sigma_ast import LoadedRule
from redgap.models import Evidence, GapType, Technique, Verdict

#: Excluded rule as returned by load_rules_detailed: (path, reason, technique_ids).
ExcludedRule = tuple[str, str, tuple[str, ...]]


def _parent(technique_id: str) -> str:
    return technique_id.split(".")[0]


def rule_covers(rule: LoadedRule, technique: Technique) -> bool:
    """True if ``rule`` is tagged to ``technique`` (exact, or a sub-technique rule
    covering its parent). A parent-only tag is NOT credited to a child sub-technique."""
    for rid in rule.technique_ids:
        if rid == technique.id:
            return True
        if _parent(rid) == technique.id:  # a sub-technique rule covers its parent
            return True
    return False


def _exact_tagged(technique_ids: Sequence[str], technique: Technique) -> bool:
    """A rule/exclusion is tagged EXACTLY to this technique (not merely via sub->parent)."""
    return technique.id in technique_ids


def _gap_type(
    technique: Technique,
    detected: bool,
    telemetry_present: bool,
    exact_rule_present: bool,
) -> GapType:
    if detected:
        return GapType.NONE
    if not telemetry_present:
        # Executed but the collector saw nothing: a visibility/data-source gap.
        return GapType.VISIBILITY
    if exact_rule_present:
        # A rule specifically for THIS technique exists (loaded-but-not-firing, or
        # excluded at load) — a rule gap, regardless of what the catalog expected. This
        # is the remediation round-trip's signal and it must not be masked as base-rate.
        return GapType.RULE
    # No rule is tagged to this technique at all; the catalog says why (rule vs base-rate).
    if technique.expected_gap_type in (GapType.RULE, GapType.BASE_RATE):
        return technique.expected_gap_type
    return GapType.RULE


def evaluate_technique(
    technique: Technique,
    events: list[Event],
    rules: list[LoadedRule],
    excluded: Sequence[ExcludedRule] = (),
) -> Verdict:
    """Compute the deterministic verdict for one technique execution."""
    telemetry_present = len(events) > 0
    candidates = [r for r in rules if rule_covers(r, technique)]
    excluded_for_technique = [x for x in excluded if _exact_tagged(x[2], technique)]

    firing_rules: list[str] = []
    matched_event_ids: list[str] = []
    evidence: list[Evidence] = []

    for rule in candidates:
        for event in events:
            match = rule_matches(rule, event)
            if match is None:
                continue
            if rule.id not in firing_rules:
                firing_rules.append(rule.id)
            if match.event_id not in matched_event_ids:
                matched_event_ids.append(match.event_id)
            evidence.append(
                Evidence(
                    rule_id=match.rule_id,
                    rule_title=match.rule_title,
                    event_id=match.event_id,
                    matched_fields=match.matched_fields,
                )
            )

    detected = len(firing_rules) > 0
    # Gap typing keys on EXACT-tagged rules (loaded or excluded), so a sub->parent credit
    # cannot downgrade a base-rate technique and an excluded closing rule still reads RULE.
    exact_present = any(_exact_tagged(r.technique_ids, technique) for r in candidates) or bool(
        excluded_for_technique
    )
    gap_type = _gap_type(technique, detected, telemetry_present, exact_present)
    return Verdict(
        technique_id=technique.id,
        executed=True,
        telemetry_present=telemetry_present,
        detected=detected,
        gap_type=gap_type,
        firing_rules=tuple(firing_rules),
        matched_event_ids=tuple(matched_event_ids),
        evidence=tuple(evidence),
        expected_gap_type=technique.expected_gap_type,
        candidates_evaluated=len(candidates),
        candidates_excluded=len(excluded_for_technique),
        unexpected=(not detected and technique.expected_gap_type is GapType.NONE),
    )


def evaluate_all(
    techniques: list[Technique],
    events_by_technique: dict[str, list[Event]],
    rules: list[LoadedRule],
    excluded: Sequence[ExcludedRule] = (),
) -> list[Verdict]:
    """Verdicts for every technique, in catalog order (deterministic)."""
    return [
        evaluate_technique(t, events_by_technique.get(t.id, []), rules, excluded)
        for t in techniques
    ]
