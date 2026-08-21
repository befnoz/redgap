"""``redgap verify`` - a one-command, offline honesty proof a skeptic can run themselves.

It re-proves the three load-bearing claims from scratch, with no API key and no network:

  1. FIXTURE AUTHENTICITY - every committed fixture's sha256 still matches its
     ``provenance.json`` (``ReplayTarget`` fails closed on any tampering).
  2. DETERMINISM - re-running coverage yields a byte-identical report.
  3. PLANNER INDEPENDENCE - the batch and the adaptive planner produce byte-identical
     coverage, so the orchestration layer (the only place an LLM ever acts) cannot move a
     single ``detected`` verdict.

Pure and dependency-light (no typer/rich/anthropic): the CLI is a thin shell over this.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from redgap._resources import rules_dir as _rules_dir
from redgap.detection.sigma_ast import load_rules_detailed
from redgap.engine_facade import CoverageEngine
from redgap.planner import make_planner
from redgap.target import ReplayTarget


@dataclass(frozen=True)
class VerifyResult:
    fixtures_checked: int
    techniques: int
    detected: int
    deterministic: bool
    planner_independent: bool

    @property
    def ok(self) -> bool:
        return self.deterministic and self.planner_independent and self.fixtures_checked > 0


def _canon(coverage: dict) -> str:
    return json.dumps(coverage, sort_keys=True, ensure_ascii=False)


def run_verification(*, generated_at: str) -> VerifyResult:
    """Recompute everything from source and check the three invariants. Raises
    ``FixtureError`` (a ``TargetError``) if any fixture fails its integrity check."""
    # 1. Authenticity: constructing the events map re-hashes every fixture vs provenance and
    #    raises on the first mismatch - so a successful call IS the authenticity proof.
    events = ReplayTarget().events_by_technique()
    fixtures_checked = len(events)

    rules, excluded = load_rules_detailed(_rules_dir(), exclude=("roundtrip",))

    def coverage(auto: bool) -> dict:
        engine = CoverageEngine(ReplayTarget(), rules, excluded, generated_at=generated_at)
        return make_planner(engine, auto=auto).run()

    batch_a = coverage(False)
    batch_b = coverage(False)
    adaptive = coverage(True)

    deterministic = _canon(batch_a) == _canon(batch_b)
    planner_independent = _canon(batch_a) == _canon(adaptive)
    summary = batch_a["summary"]
    return VerifyResult(
        fixtures_checked=fixtures_checked,
        techniques=summary["techniques"],
        detected=summary["detected"],
        deterministic=deterministic,
        planner_independent=planner_independent,
    )
