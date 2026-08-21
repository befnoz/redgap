"""Detection depth: coverage.json carries, per technique, how many rules independently catch
it. It is a pure count over firing_rules (never a verdict), so `detected` is unchanged; depth
just makes 'green' stop being binary - depth 1 is a single point of failure, 2+ is redundant.
"""

from __future__ import annotations

from pathlib import Path

from redgap.detection.sigma_ast import load_rules_detailed
from redgap.engine_facade import CoverageEngine
from redgap.target import ReplayTarget

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
WHEN = "2026-08-11T00:00:00Z"


def _coverage():
    rules, excluded = load_rules_detailed(RULES_DIR, exclude=("roundtrip",))
    return CoverageEngine(ReplayTarget(), rules, excluded, generated_at=WHEN).coverage()


def test_depth_equals_firing_rule_count_and_tracks_detected():
    cov = _coverage()
    for t in cov["techniques"]:
        assert t["depth"] == len(t["firing_rules"])  # a pure derivation, nothing more
        assert (t["depth"] >= 1) == t["detected"]  # detected iff at least one rule fires


def test_every_demo_detection_is_a_single_point_of_failure():
    # An honest property of RedGap's OWN shipped demo rules: one rule per technique, zero
    # redundancy. This is exactly the fragility `redgap audit` surfaces on a real ruleset.
    cov = _coverage()
    detected = [t for t in cov["techniques"] if t["detected"]]
    assert detected, "sanity: the demo run detects something"
    assert all(t["depth"] == 1 for t in detected)


def test_blast_radius_is_derivable_from_depth_and_firing_rules():
    # A rule's blast radius = the techniques it is the SOLE detector for (depth 1). Pure
    # derivation over the committed fields; removing that rule blinds exactly those.
    cov = _coverage()
    blast: dict[str, list[str]] = {}
    for t in cov["techniques"]:
        if t["detected"] and t["depth"] == 1:
            blast.setdefault(t["firing_rules"][0], []).append(t["id"])
    assert blast, "there should be at least one single-rule detection to attribute"
    assert all(len(v) >= 1 for v in blast.values())
