"""A per-technique coverage engine the planners drive.

Whether a planner runs the techniques in catalog order, in an LLM-chosen order, or not
at all, :meth:`coverage` evaluates every technique deterministically before returning -
so the committed report is byte-identical regardless of the planner. This is what makes
"the coverage is the same with and without the LLM" literally true.
"""

from __future__ import annotations

from collections.abc import Sequence

from redgap.catalog import BY_ID, CATALOG
from redgap.detection.coverage import evaluate_technique
from redgap.detection.sigma_ast import LoadedRule
from redgap.models import Technique, Verdict
from redgap.report import coverage_dict
from redgap.target import Target

ExcludedRule = tuple[str, str, tuple[str, ...]]


class CoverageEngine:
    def __init__(
        self,
        target: Target,
        rules: list[LoadedRule],
        excluded: Sequence[ExcludedRule] = (),
        *,
        generated_at: str,
    ):
        self._events = target.events_by_technique()
        self._rules = rules
        self._excluded = excluded
        self.mode = target.mode
        self.run_id = target.run_id
        self.generated_at = generated_at
        self._verdicts: dict[str, Verdict] = {}

    def techniques(self) -> list[str]:
        return [t.id for t in CATALOG]

    def _evaluate(self, technique: Technique) -> Verdict:
        verdict = evaluate_technique(
            technique, self._events.get(technique.id, []), self._rules, self._excluded
        )
        self._verdicts[technique.id] = verdict
        return verdict

    def run_technique(self, technique_id: str) -> dict:
        """Evaluate one technique and return a compact, LLM-facing verdict summary.

        The ``detected`` field is produced by the deterministic engine and handed to the
        caller as immutable data - a planner can sequence calls but cannot change it.
        """
        verdict = self._evaluate(BY_ID[technique_id])
        return {
            "technique_id": technique_id,
            "executed": True,
            "detected": verdict.detected,
            "gap_type": verdict.gap_type.value,
            "firing_rules": list(verdict.firing_rules),
        }

    def verdicts(self) -> list[Verdict]:
        return [self._verdicts.get(t.id) or self._evaluate(t) for t in CATALOG]

    def coverage(self) -> dict:
        return coverage_dict(
            CATALOG,
            self.verdicts(),
            mode=self.mode,
            run_id=self.run_id,
            generated_at=self.generated_at,
        )
