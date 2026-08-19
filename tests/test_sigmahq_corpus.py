"""RedGap's engine, validated against the FULL real-world SigmaHQ corpus.

This is the reproducible backing for the README's headline: every rule in SigmaHQ's
``linux/process_creation`` ruleset - vendored verbatim under
``tests/corpus/sigmahq_linux_process_creation/`` (see its README for the exact source
commit and license) - is loaded and evaluated by RedGap's own pySigma-based parser and
AST evaluator with **zero parser errors and zero evaluator crashes**, fully offline.

It deliberately does not assert a ground-truth verdict for each third-party rule (that
would need an oracle we do not have); the golden tests do that for the shipped rules.
What it proves is robustness and determinism over real-world input at scale.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from redgap.detection.engine import RuleMatch, rule_matches
from redgap.detection.sigma_ast import LoadedRule, load_rules_detailed, parse_rule
from redgap.target import ReplayTarget

CORPUS = Path(__file__).parent / "corpus" / "sigmahq_linux_process_creation"
EXPECTED_RULE_COUNT = 122


def _corpus_files() -> list[Path]:
    return sorted(CORPUS.glob("*.yml"))


def test_corpus_is_vendored() -> None:
    files = _corpus_files()
    assert len(files) == EXPECTED_RULE_COUNT, (
        f"expected {EXPECTED_RULE_COUNT} vendored SigmaHQ rules, found {len(files)} - "
        f"re-vendor from SigmaHQ (see the corpus README)"
    )


def test_whole_corpus_loads_with_zero_crashes() -> None:
    files = _corpus_files()
    rules, excluded = load_rules_detailed(CORPUS, exclude=())
    # Every file is accounted for as either loaded or cleanly excluded - never a crash.
    assert len(rules) + len(excluded) == len(files)
    # RedGap's engine supports the entire real corpus outright (no exclusions).
    assert len(rules) == len(files), "unexpectedly excluded: " + ", ".join(
        f"{Path(str(p)).name}: {reason}" for p, reason, _ in excluded
    )


@pytest.mark.parametrize("path", _corpus_files(), ids=lambda p: p.name)
def test_each_rule_parses_to_a_loaded_rule(path: Path) -> None:
    # Every corpus rule must parse to a real LoadedRule. The corpus is fully supported
    # today, so a RuleError here means a newly-unsupported rule and fails loudly rather
    # than passing vacuously - this is a meaningful per-rule assertion, not a no-op.
    rule = parse_rule(path.read_text(encoding="utf-8"), path=str(path))
    assert isinstance(rule, LoadedRule)


def test_engine_evaluates_whole_corpus_over_real_events_deterministically() -> None:
    rules, _ = load_rules_detailed(CORPUS, exclude=())
    events = [e for evs in ReplayTarget().events_by_technique().values() for e in evs]
    assert events, "no fixture events to evaluate against"
    for rule in rules:
        for event in events:
            first = rule_matches(rule, event)
            second = rule_matches(rule, event)
            # Never raises; returns a RuleMatch or None; and is deterministic.
            assert first is None or isinstance(first, RuleMatch)
            assert (first is None) == (second is None)
