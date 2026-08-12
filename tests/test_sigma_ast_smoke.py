"""Drift guard: assert pySigma still lowers rules into the node/leaf types the
evaluator walks. A breaking pySigma upgrade fails here, loudly, in CI.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionOR,
)
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCompareExpression,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
)

from redgap.detection.sigma_ast import load_rules, parse_rule

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
SETUID = RULES_DIR / "proc_creation_lnx_setgid_setuid.yml"


def test_shipped_setuid_rule_lowers_as_expected() -> None:
    rule = parse_rule(SETUID.read_text(encoding="utf-8"), str(SETUID))
    # Tag extraction picks up the sub-technique id.
    assert rule.technique_ids == ("T1548.001",)
    assert rule.id == "c21c4eaa-ba2e-419a-92b2-8371703cbe21"
    # `all of selection_*` -> AND over the two selections.
    assert isinstance(rule.ast, ConditionAND)
    # selection_perm is a value list -> an OR of leaves; selection_root is one leaf.
    assert any(isinstance(a, ConditionOR) for a in rule.ast.args)
    assert any(isinstance(a, ConditionFieldEqualsValueExpression) for a in rule.ast.args)
    # Every leaf value is a SigmaString here.
    or_node = next(a for a in rule.ast.args if isinstance(a, ConditionOR))
    for leaf in or_node.args:
        assert isinstance(leaf, ConditionFieldEqualsValueExpression)
        assert isinstance(leaf.value, SigmaString)


def test_all_default_rules_parse_and_have_technique_tags() -> None:
    rules = load_rules(RULES_DIR)  # excludes roundtrip/ by default
    assert rules, "expected at least the vendored + authored default rules"
    for rule in rules:
        assert rule.technique_ids, f"{rule.path}: rule must carry an attack.tXXXX tag"
        assert rule.ast is not None


def _first_leaf_value(rule):
    def walk(node):
        args = getattr(node, "args", None)
        if args:
            for arg in args:
                found = walk(arg)
                if found is not None:
                    return found
            return None
        return getattr(node, "value", None)

    return walk(rule.ast)


@pytest.mark.parametrize(
    ("detection", "expected_type"),
    [
        ("  sel: {Pid: 1000}\n", SigmaNumber),
        ("  sel: {Flag: true}\n", SigmaBool),
        ("  sel: {CommandLine|re: 'x'}\n", SigmaRegularExpression),
        ("  sel: {User|cased: 'R'}\n", SigmaCasedString),
        ("  sel: {CommandLine|contains: 'x'}\n", SigmaString),
        ("  sel: {Pid|lt: 5}\n", SigmaCompareExpression),
    ],
)
def test_value_leaf_types_are_pinned(detection, expected_type) -> None:
    # If pySigma renames a value class or lowers a modifier differently, this fails
    # loudly in CI instead of silently breaking the evaluator at runtime.
    rule = parse_rule(
        "title: t\nid: 22222222-2222-2222-2222-222222222222\n"
        "logsource: {category: process_creation, product: linux}\n"
        f"detection:\n{detection}  condition: sel\ntags: [attack.t1548.001]\n",
        "<pin>",
    )
    assert isinstance(_first_leaf_value(rule), expected_type)
