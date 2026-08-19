"""The planner is orchestration only. These tests pin the trust boundary: whatever the
LLM does - finish immediately, run a subset, request a bogus technique - the committed
coverage is byte-identical to the deterministic run, because it always comes from
engine.coverage(), never from the model.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from redgap.detection.sigma_ast import load_rules_detailed
from redgap.engine_facade import CoverageEngine
from redgap.planner import HeuristicPlanner, LLMPlanner, ToolExecutor, make_planner
from redgap.target import ReplayTarget

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
WHEN = "2026-08-11T00:00:00Z"


def _engine():
    rules, excluded = load_rules_detailed(RULES_DIR)
    return CoverageEngine(ReplayTarget(), rules, excluded, generated_at=WHEN)


def _canon(coverage: dict) -> str:
    return json.dumps(coverage, sort_keys=True)


# --- A minimal fake Anthropic client that scripts tool_use turns -------------
class _Block:
    def __init__(self, name, input, id):
        self.type = "tool_use"
        self.name = name
        self.input = input
        self.id = id


class _Resp:
    def __init__(self, content, stop_reason="tool_use"):
        self.content = content
        self.stop_reason = stop_reason


class _FakeMessages:
    def __init__(self, script):
        self.script = script
        self.calls = 0

    def create(self, **_kwargs):
        resp = self.script[self.calls]
        self.calls += 1
        return resp


class _FakeClient:
    def __init__(self, script):
        self.messages = _FakeMessages(script)


def _tool(name, **inp):
    return _Block(name, inp, f"tu_{name}")


def test_heuristic_matches_direct_evaluation():
    heuristic = _canon(HeuristicPlanner(_engine()).run())
    # A fresh engine's full coverage() must equal the planner's output.
    assert heuristic == _canon(_engine().coverage())


def test_llm_finish_immediately_still_produces_full_coverage():
    # The model finishes without running anything - coverage must still be complete.
    llm = LLMPlanner(_engine(), client=_FakeClient([_Resp([_tool("finish")])]))
    assert _canon(llm.run()) == _canon(HeuristicPlanner(_engine()).run())


def test_llm_partial_run_is_byte_identical_to_heuristic():
    script = [
        _Resp([_tool("run_technique", technique_id="T1548.001")]),
        _Resp([_tool("run_technique", technique_id="T1087.001")]),
        _Resp([_tool("finish")]),
    ]
    llm = LLMPlanner(_engine(), client=_FakeClient(script))
    assert _canon(llm.run()) == _canon(HeuristicPlanner(_engine()).run())


def test_llm_bogus_technique_id_is_rejected_not_crash():
    script = [
        _Resp([_tool("run_technique", technique_id="NOT_A_TECHNIQUE")]),
        _Resp([_tool("finish")]),
    ]
    llm = LLMPlanner(_engine(), client=_FakeClient(script))
    # No exception, and coverage is still the full deterministic report.
    assert _canon(llm.run()) == _canon(HeuristicPlanner(_engine()).run())


def test_tool_executor_validates_and_never_sets_verdict():
    executor = ToolExecutor(_engine())
    assert "error" in executor.run("run_technique", {"technique_id": "NOPE"})
    assert "error" in executor.run("frobnicate", {})
    setuid = executor.run("run_technique", {"technique_id": "T1548.001"})
    assert setuid["detected"] is True  # produced by the engine, not settable by the caller
    assert executor.run("finish", {}) == {"ok": True}
    assert executor.done is True


def test_make_planner_needs_both_the_flag_and_a_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("COVERAGE_LLM", raising=False)
    assert isinstance(make_planner(_engine()), HeuristicPlanner)
    # Flag set but no key -> still deterministic.
    assert isinstance(make_planner(_engine(), use_llm=True), HeuristicPlanner)


def test_make_planner_env_toggle(monkeypatch):
    monkeypatch.setenv("COVERAGE_LLM", "1")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Env says on, but without a key it must stay deterministic (offline-safe).
    assert isinstance(make_planner(_engine()), HeuristicPlanner)
    assert os.getenv("COVERAGE_LLM") == "1"
