"""Adaptive gap-driven chaining keeps the SAME trust boundary as the batch planners.

Whatever the adaptive LLM does - pick a valid technique, name a bogus one, repeat an
already-run one, or stop immediately - the committed coverage is byte-identical to the
deterministic run, because it always comes from ``engine.coverage()``. The only extra
artifact is the attack-path, and every ``detected`` in it is COPIED from the engine, never
authored by the model. The offline ``AdaptiveHeuristicPlanner`` makes ``--adaptive`` a real
demo with no key.
"""

from __future__ import annotations

import json
from pathlib import Path

from redgap.agent_state import state_view
from redgap.detection.sigma_ast import load_rules_detailed
from redgap.engine_facade import CoverageEngine
from redgap.planner import (
    AdaptiveHeuristicPlanner,
    AdaptivePlanner,
    HeuristicPlanner,
    make_planner,
    select_technique_tool,
)
from redgap.target import ReplayTarget

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
WHEN = "2026-08-11T00:00:00Z"


def _engine():
    rules, excluded = load_rules_detailed(RULES_DIR)
    return CoverageEngine(ReplayTarget(), rules, excluded, generated_at=WHEN)


def _canon(coverage: dict) -> str:
    return json.dumps(coverage, sort_keys=True)


# --- minimal fake Anthropic client scripting select_next_technique turns ------
class _Block:
    def __init__(self, name, inp):
        self.type = "tool_use"
        self.name = name
        self.input = inp


class _Resp:
    def __init__(self, content):
        self.content = content


def _decision(next_technique_id, *, stop, reasoning="because"):
    return _Resp(
        [
            _Block(
                "select_next_technique",
                {"next_technique_id": next_technique_id, "reasoning": reasoning, "stop": stop},
            )
        ]
    )


class _ScriptedClient:
    """Returns pre-scripted decisions, one per create() call."""

    def __init__(self, script):
        self.messages = self
        self.script = script
        self.calls = 0

    def create(self, **_kwargs):
        resp = self.script[self.calls]
        self.calls += 1
        return resp


class _GreedyClient:
    """A realistic 'greedy' LLM: always picks the first remaining candidate from the state it
    is given, never stops. Deterministic, always valid, never a duplicate -> lets us drive a
    pure LLM-chosen run to the step cap."""

    def __init__(self):
        self.messages = self
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        payload = json.loads(kwargs["messages"][0]["content"].split("\n", 1)[1])
        remaining = payload["state"]["remaining_techniques"]
        return _decision(remaining[0], stop=False, reasoning="greedy")


# --- the offline deterministic adaptive planner -------------------------------
def test_adaptive_heuristic_coverage_is_byte_identical_to_batch():
    adaptive = _canon(AdaptiveHeuristicPlanner(_engine()).run())
    assert adaptive == _canon(HeuristicPlanner(_engine()).run())


def test_adaptive_heuristic_writes_a_consistent_attack_path():
    planner = AdaptiveHeuristicPlanner(_engine(), max_steps=12)
    planner.run()
    ap = planner.attack_path
    assert ap is not None
    assert ap["schema"] == "redgap.attack_path/v1"
    assert 1 <= len(ap["steps"]) <= 12
    # every step's detected/gap_type is the engine's verdict, and the narrative summary agrees
    detected = sum(1 for s in ap["steps"] if s["detected"])
    gaps = [s["technique_id"] for s in ap["steps"] if not s["detected"]]
    assert ap["summary"]["detected"] == detected
    assert ap["summary"]["gap_techniques"] == gaps
    for s in ap["steps"]:
        assert (s["gap_type"] == "") == s["detected"]  # gap_type set iff undetected
        # the deterministic offline planner never falls back - every pick is its own
        assert s["reason"]["source"] == "heuristic"


def test_adaptive_heuristic_respects_the_step_cap():
    planner = AdaptiveHeuristicPlanner(_engine(), max_steps=4)
    planner.run()
    assert len(planner.attack_path["steps"]) <= 4


def test_both_adaptive_planners_agree_at_degenerate_step_cap():
    # max_steps <= 0 is degenerate but reachable programmatically; both adaptive planners
    # must produce a zero-step path (the seed must honor the cap too), so the attack-path
    # never depends on which adaptive planner ran.
    heuristic = AdaptiveHeuristicPlanner(_engine(), max_steps=0)
    heuristic.run()
    llm = AdaptivePlanner(_engine(), client=_ScriptedClient([]), max_steps=0)
    llm.run()
    assert heuristic.attack_path["steps"] == []
    assert llm.attack_path["steps"] == []
    assert heuristic.attack_path["stop"]["steps_taken"] == 0
    # and coverage is still the full deterministic report despite zero planner steps
    assert _canon(heuristic.run()) == _canon(HeuristicPlanner(_engine()).run())


# --- the opt-in LLM adaptive planner (offline, fake client) -------------------
def test_adaptive_llm_pick_then_stop_is_byte_identical():
    script = [
        _decision("T1548.001", stop=False),
        _decision(None, stop=True, reasoning="nothing left worth running"),
    ]
    planner = AdaptivePlanner(_engine(), client=_ScriptedClient(script))
    report = planner.run()
    assert _canon(report) == _canon(HeuristicPlanner(_engine()).run())
    ap = planner.attack_path
    assert [s["technique_id"] for s in ap["steps"]] == ["T1548.001"]
    assert ap["steps"][0]["reason"]["source"] == "llm"
    assert ap["stop"]["reason"] == "planner_stop"


def test_adaptive_llm_bogus_id_falls_back_never_crashes():
    script = [
        _decision("NOT_A_TECHNIQUE", stop=False),  # invalid -> MalformedDecision -> fallback
        _decision(None, stop=True),
    ]
    planner = AdaptivePlanner(_engine(), client=_ScriptedClient(script))
    report = planner.run()
    assert _canon(report) == _canon(HeuristicPlanner(_engine()).run())
    ap = planner.attack_path
    # the bogus pick did not execute a non-catalog technique; the fallback chose a real one
    assert ap["steps"], "the fallback should still have produced a step"
    assert ap["steps"][0]["reason"]["source"] == "heuristic-fallback"
    from redgap.catalog import BY_ID

    assert all(s["technique_id"] in BY_ID for s in ap["steps"])


def test_adaptive_llm_duplicate_id_falls_back_no_infinite_loop():
    # The model keeps naming the SAME already-run technique; each repeat is malformed and the
    # deterministic fallback advances the chain, so the run still terminates at the cap.
    script = [_decision("T1548.001", stop=False)] * 20
    planner = AdaptivePlanner(_engine(), client=_ScriptedClient(script), max_steps=6)
    report = planner.run()
    assert _canon(report) == _canon(HeuristicPlanner(_engine()).run())
    ids = [s["technique_id"] for s in planner.attack_path["steps"]]
    assert len(ids) == len(set(ids)), "a technique must never be run twice"
    assert len(ids) <= 6


def test_adaptive_llm_stop_immediately_still_full_coverage():
    planner = AdaptivePlanner(_engine(), client=_ScriptedClient([_decision(None, stop=True)]))
    report = planner.run()
    assert _canon(report) == _canon(HeuristicPlanner(_engine()).run())
    assert planner.attack_path["steps"] == []
    assert planner.attack_path["stop"]["reason"] == "planner_stop"


def test_adaptive_llm_greedy_run_hits_cap_all_steps_llm():
    planner = AdaptivePlanner(_engine(), client=_GreedyClient(), max_steps=5)
    report = planner.run()
    assert _canon(report) == _canon(HeuristicPlanner(_engine()).run())
    ap = planner.attack_path
    assert len(ap["steps"]) == 5
    assert ap["stop"]["reason"] == "max_steps"
    assert all(s["reason"]["source"] == "llm" for s in ap["steps"])


def test_make_planner_auto_offline_is_the_deterministic_adaptive(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("COVERAGE_LLM", raising=False)
    assert isinstance(make_planner(_engine(), auto=True), AdaptiveHeuristicPlanner)
    # flag on but no key -> still the offline deterministic adaptive planner
    assert isinstance(make_planner(_engine(), auto=True, use_llm=True), AdaptiveHeuristicPlanner)


def test_make_planner_non_auto_is_unchanged(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("COVERAGE_LLM", raising=False)
    assert isinstance(make_planner(_engine()), HeuristicPlanner)


def test_select_tool_schema_has_no_verdict_field():
    """The model's ONLY tool cannot carry a 'detected' verdict - it can order and stop, and
    that is the whole trust boundary."""
    schema = select_technique_tool()["input_schema"]
    props = set(schema["properties"])
    assert props == {"next_technique_id", "reasoning", "stop"}
    assert "detected" not in props and "gap_type" not in props
    assert schema.get("additionalProperties") is False  # no smuggling extra fields


def test_state_view_reads_but_never_mutates_the_engine():
    engine = _engine()
    engine.run_technique("T1548.001")
    before = dict(engine._verdicts)
    view = state_view(engine, [])
    assert engine._verdicts == before  # projection is read-only
    assert "T1548.001" not in view["remaining_techniques"]  # executed drops off the pick-list
