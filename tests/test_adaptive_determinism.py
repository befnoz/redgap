"""The attack-path is a committed artifact, so it must be deterministic: the same inputs
produce a byte-identical chain every time. The deterministic core (``_pick`` /
``killchain_rank``) is what guarantees it, and a fixed fake client makes even the LLM path
reproducible in CI.
"""

from __future__ import annotations

import json
from pathlib import Path

from redgap.detection.sigma_ast import load_rules_detailed
from redgap.engine_facade import CoverageEngine
from redgap.planner import (
    KILLCHAIN_ORDER,
    AdaptiveHeuristicPlanner,
    _pick,
    killchain_rank,
)
from redgap.target import ReplayTarget

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
WHEN = "2026-08-11T00:00:00Z"


def _engine():
    rules, excluded = load_rules_detailed(RULES_DIR)
    return CoverageEngine(ReplayTarget(), rules, excluded, generated_at=WHEN)


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True)


def test_adaptive_heuristic_attack_path_is_deterministic():
    a = AdaptiveHeuristicPlanner(_engine())
    a.run()
    b = AdaptiveHeuristicPlanner(_engine())
    b.run()
    assert _canon(a.attack_path) == _canon(b.attack_path)


def test_killchain_rank_orders_known_and_sinks_unknown():
    assert killchain_rank("Reconnaissance") == 0  # pre-compromise tactic ranks first
    assert killchain_rank("Initial Access") < killchain_rank("Impact")
    assert killchain_rank("Execution") < killchain_rank("Exfiltration")
    # an unknown tactic sorts strictly after every known one and never raises
    assert killchain_rank("No Such Tactic") == len(KILLCHAIN_ORDER)
    assert killchain_rank("No Such Tactic") > killchain_rank("Impact")


def test_pick_prefers_breadth_then_depth_deterministically():
    # breadth: an untouched tactic beats a tactic that only has an open gap
    state = {
        "remaining_techniques": ["T_gap", "T_new"],
        "tactics_untouched": ["Execution"],
        "tactics_with_open_gaps": ["Discovery"],
    }
    # patch a tiny catalog view via a stand-in: build the mapping _pick reads
    import redgap.planner as planner_mod

    saved = planner_mod.BY_ID
    try:
        planner_mod.BY_ID = {
            "T_new": type("T", (), {"tactics": ("Execution",)})(),
            "T_gap": type("T", (), {"tactics": ("Discovery",)})(),
        }
        assert _pick(state) == "T_new"  # breadth wins
        # with no untouched tactic left, depth (open gap) is chosen
        state["tactics_untouched"] = []
        assert _pick(state) == "T_gap"
        # nothing untouched and no open gap -> converged
        state["tactics_with_open_gaps"] = []
        assert _pick(state) is None
    finally:
        planner_mod.BY_ID = saved


def test_pick_tie_break_is_killchain_then_id():
    import redgap.planner as planner_mod

    saved = planner_mod.BY_ID
    try:
        # id order and killchain order DISAGREE: the killchain-earlier tactic (Execution)
        # belongs to the id-LARGER candidate (T_zeta). If the tie-break were plain id, it would
        # pick T_alpha; killchain rank must override that and pick T_zeta.
        planner_mod.BY_ID = {
            "T_zeta": type("T", (), {"tactics": ("Execution",)})(),  # killchain-earlier, id-larger
            "T_alpha": type("T", (), {"tactics": ("Impact",)})(),  # killchain-later, id-smaller
        }
        state = {
            "remaining_techniques": ["T_alpha", "T_zeta"],
            "tactics_untouched": ["Impact", "Execution"],
            "tactics_with_open_gaps": [],
        }
        assert _pick(state) == "T_zeta"  # Execution precedes Impact -> killchain beats id order
    finally:
        planner_mod.BY_ID = saved
