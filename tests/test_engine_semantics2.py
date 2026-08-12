"""Second-wave semantics tests: pin the fixes from the re-verification swarm so none
can regress — nested-list allowlist bypass, loader robustness, catastrophic-regex
rejection, satisfied-path evidence, numeric keywords, compare hardening, and the
excluded-rule-vs-base-rate distinction.
"""

from __future__ import annotations

import pytest

from redgap.catalog import BY_ID
from redgap.detection.coverage import evaluate_technique
from redgap.detection.engine import rule_matches
from redgap.detection.sigma_ast import RuleError, load_rules_detailed, parse_rule
from redgap.models import GapType
from redgap.telemetry.schema import make_event


def _rule(detection: str, tags: str = "attack.t1548.001", condition: str = "sel"):
    return parse_rule(
        f"title: probe\nid: 44444444-4444-4444-4444-444444444444\n"
        f"logsource: {{category: process_creation, product: linux}}\n"
        f"detection:\n{detection}  condition: {condition}\ntags: [{tags}]\n",
        "<probe>",
    )


def _ev(**fields):
    return dict(fields)


# --- Nested-list must NOT tunnel an unsupported modifier past the allowlist ---
def test_nested_list_base64_is_still_excluded():
    with pytest.raises(RuleError):
        parse_rule(
            "title: nested\nid: 11111111-1111-1111-1111-111111111111\n"
            "logsource: {category: process_creation, product: linux}\n"
            "detection:\n  sel:\n    - - CommandLine|base64: 'x'\n  condition: sel\n"
            "tags: [attack.t1548.001]\n",
            "<nested>",
        )


# --- Loader robustness: one bad file/dir never aborts the whole load ---
def test_loader_isolates_non_utf8_file(tmp_path):
    good = (
        "title: good\nid: aaaaaaaa-0000-0000-0000-000000000001\n"
        "logsource: {category: process_creation, product: linux}\n"
        "detection:\n  sel: {Image|endswith: '/cat'}\n  condition: sel\n"
        "tags: [attack.t1087.001]\n"
    )
    (tmp_path / "good.yml").write_text(good, encoding="utf-8")
    (tmp_path / "latin1.yml").write_bytes(b"title: caf\xe9\ndetection: {sel: {Image: x}}\n")
    with pytest.warns(UserWarning):
        rules, excluded = load_rules_detailed(tmp_path)
    assert len(rules) == 1
    assert any("latin1.yml" in x[0] for x in excluded)


def test_loader_skips_directory_matching_glob(tmp_path):
    good = (
        "title: good\nid: aaaaaaaa-0000-0000-0000-000000000002\n"
        "logsource: {category: process_creation, product: linux}\n"
        "detection:\n  sel: {Image|endswith: '/cat'}\n  condition: sel\n"
        "tags: [attack.t1087.001]\n"
    )
    (tmp_path / "good.yml").write_text(good, encoding="utf-8")
    (tmp_path / "collection.yml").mkdir()  # a directory that matches *.yml
    rules = load_rules_detailed(tmp_path)[0]
    assert len(rules) == 1


# --- Catastrophic |re is rejected at load; a safe bounded regex is not ---
def test_catastrophic_regex_rejected_at_load():
    with pytest.raises(RuleError):
        _rule("  sel:\n    CommandLine|re: '(a+)+$'\n")


def test_bounded_regex_is_allowed():
    # The real SigmaHQ (.){200,} long-line pattern must NOT be falsely excluded.
    rule = _rule("  sel:\n    CommandLine|re: '(.){200,}'\n")
    assert rule_matches(rule, _ev(CommandLine="a" * 250)) is not None


# --- Evidence reports only the satisfied path ---
def test_evidence_excludes_not_filter_field():
    rule = _rule(
        "  selection:\n    Image|endswith: '/cat'\n"
        "  filter:\n    CommandLine|contains: '/etc/hosts'\n",
        tags="attack.t1087.001",
        condition="selection and not filter",
    )
    match = rule_matches(rule, _ev(Image="/usr/bin/cat", CommandLine="cat /etc/passwd"))
    assert match is not None
    assert set(match.matched_fields) == {"Image"}


def test_evidence_excludes_unsatisfied_or_branch():
    rule = _rule(
        "  selection:\n    - Image|endswith: '/cat'\n    - CommandLine|contains: 'secret'\n",
        tags="attack.t1087.001",
        condition="selection",
    )
    match = rule_matches(rule, _ev(Image="/usr/bin/cat", CommandLine="ps aux"))
    assert match is not None
    assert set(match.matched_fields) == {"Image"}


# --- Numeric value-only keyword substring-matches like its quoted form ---
def test_numeric_keyword_substring():
    rule = _rule("  keywords:\n    - 1234\n", tags="attack.t1057", condition="keywords")
    assert rule_matches(rule, _ev(CommandLine="process pid 1234 started")) is not None


def test_string_keyword_sees_numeric_field():
    rule = _rule("  keywords:\n    - '1000'\n", tags="attack.t1057", condition="keywords")
    assert rule_matches(rule, _ev(CommandLine="x", Pid=1000)) is not None


# --- Compare hardening: no crash on huge ints, no bool over-match ---
def test_compare_no_overflow_crash():
    rule = _rule("  sel:\n    Pid|gt: 5\n")
    assert rule_matches(rule, _ev(Pid=10**400)) is None  # must not raise


def test_compare_rejects_boolean():
    rule = _rule("  sel:\n    Pid|gte: 0\n")
    assert rule_matches(rule, _ev(Pid=False)) is None


# --- An excluded closing rule must not masquerade as a base-rate gap ---
def test_excluded_rule_distinct_from_no_rule():
    ev = make_event(run_id="r", technique_id="T1057", image="/usr/bin/ps", command_line="ps aux")
    # No rule at all -> honest base-rate gap.
    plain = evaluate_technique(BY_ID["T1057"], [ev], [], excluded=())
    assert plain.gap_type is GapType.BASE_RATE
    assert plain.candidates_excluded == 0
    # A rule the user wrote for T1057 but that got excluded at load -> RULE gap + flagged.
    excluded = [("rules/ps.yml", "unsupported modifier ['base64']", ("T1057",))]
    dropped = evaluate_technique(BY_ID["T1057"], [ev], [], excluded=excluded)
    assert dropped.gap_type is GapType.RULE
    assert dropped.candidates_excluded == 1


# --- sub->parent credit must not downgrade a base-rate parent's gap type ---
def test_sub_tag_does_not_downgrade_base_rate_parent():
    from redgap.models import Technique

    parent = Technique(
        "T1548",
        "Abuse Elevation Control Mechanism",
        ("Privilege Escalation",),
        "",
        "T1548",
        expected_gap_type=GapType.BASE_RATE,
    )
    sub_rule = _rule("  sel:\n    CommandLine|contains: 'nomatch-xyz'\n", tags="attack.t1548.001")
    ev = _ev(Image="/usr/bin/sh", CommandLine="sh -c true")
    verdict = evaluate_technique(parent, [ev], [sub_rule])
    assert verdict.detected is False
    assert verdict.gap_type is GapType.BASE_RATE  # not downgraded to RULE by the sub tag
