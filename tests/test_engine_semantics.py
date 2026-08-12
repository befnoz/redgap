"""Semantics tests derived from the adversarial engine review.

Each test pins a specific Sigma-faithfulness fix so a regression fails loudly:
regex flags, keyword substring search, unsupported-modifier exclusion, boolean and
numeric string semantics, cased matching, the parent-tag no-bleed join, condition
grammar errors, the not-filter pattern, endswith anchoring, the ReDoS length cap,
and the spec->rule flagship linkage.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest

from redgap.catalog import BY_ID
from redgap.detection.coverage import evaluate_technique, rule_covers
from redgap.detection.engine import MAX_MATCH_LEN, rule_matches
from redgap.detection.sigma_ast import RuleError, parse_rule
from redgap.models import GapType, Technique
from redgap.techniques.registry import SPECS
from redgap.telemetry.schema import make_event

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def _ev(**fields):
    """A bare event dict for value-type tests (exact control over str vs int)."""
    return dict(fields)


def _rule(detection: str, tags: str = "attack.t1548.001", condition: str = "sel"):
    return parse_rule(
        f"""
title: probe
id: 44444444-4444-4444-4444-444444444444
logsource: {{category: process_creation, product: linux}}
detection:
{detection}  condition: {condition}
tags: [{tags}]
""",
        "<probe>",
    )


# --- Regex flags -------------------------------------------------------------
def test_regex_i_flag_is_case_insensitive():
    rule = _rule("  sel:\n    CommandLine|re|i: 'CHMOD'\n")
    assert rule_matches(rule, _ev(CommandLine="run chmod x")) is not None


def test_regex_without_flag_is_case_sensitive():
    rule = _rule("  sel:\n    CommandLine|re: 'CHMOD'\n")
    assert rule_matches(rule, _ev(CommandLine="run chmod x")) is None
    assert rule_matches(rule, _ev(CommandLine="run CHMOD x")) is not None


# --- Keyword / value-only substring semantics --------------------------------
def test_keyword_is_substring_not_whole_value():
    rule = _rule("  keywords:\n    - 'nmap'\n", tags="attack.t1057", condition="keywords")
    assert rule_matches(rule, _ev(CommandLine="nmap -sV 10.0.0.1")) is not None
    assert rule_matches(rule, _ev(CommandLine="ping 10.0.0.1")) is None


def test_keyword_does_not_read_internal_bookkeeping():
    rule = _rule("  keywords:\n    - 'secretrun'\n", tags="attack.t1057", condition="keywords")
    ev = make_event(
        run_id="secretrun", technique_id="T1057", image="/usr/bin/ps", command_line="ps aux"
    )
    # 'secretrun' lives only in the internal _run_id key, which rules cannot see.
    assert rule_matches(rule, ev) is None


# --- Unsupported modifiers are excluded at parse, never silently mismatched ---
@pytest.mark.parametrize("modifier", ["base64", "base64offset", "windash", "utf16", "exists"])
def test_unsupported_modifier_raises_ruleerror(modifier):
    with pytest.raises(RuleError):
        _rule(f"  sel:\n    CommandLine|{modifier}: 'x'\n")


# --- Boolean matched as a string, both directions ----------------------------
def test_bool_false_matches_string_false():
    rule = _rule("  sel:\n    Suspicious: false\n")
    assert rule_matches(rule, _ev(Suspicious="false")) is not None
    assert rule_matches(rule, _ev(Suspicious="true")) is None


def test_bool_true_does_not_match_string_false():
    rule = _rule("  sel:\n    Suspicious: true\n")
    assert rule_matches(rule, _ev(Suspicious="false")) is None
    assert rule_matches(rule, _ev(Suspicious="true")) is not None


# --- Numbers matched as strings (no float over-match) ------------------------
def test_number_no_float_overmatch():
    rule = _rule("  sel:\n    Pid: 1000\n")
    assert rule_matches(rule, _ev(Pid=1000)) is not None
    assert rule_matches(rule, _ev(Pid="1000")) is not None
    assert rule_matches(rule, _ev(Pid="  1000  ")) is None
    assert rule_matches(rule, _ev(Pid="1e3")) is None
    assert rule_matches(rule, _ev(Pid=True)) is None


# --- Numeric compare (lt/lte/gt/gte) -----------------------------------------
def test_numeric_compare_lt():
    rule = _rule("  sel:\n    Pid|lt: 100\n")
    assert rule_matches(rule, _ev(Pid=50)) is not None
    assert rule_matches(rule, _ev(Pid=100)) is None
    assert rule_matches(rule, _ev(Pid="notnum")) is None


# --- cased is case-sensitive -------------------------------------------------
def test_cased_is_case_sensitive():
    rule = _rule("  sel:\n    User|cased: 'ROOT'\n")
    assert rule_matches(rule, _ev(User="ROOT")) is not None
    assert rule_matches(rule, _ev(User="root")) is None


# --- Parent-tag join must not bleed onto a sibling sub-technique --------------
def test_parent_tag_does_not_credit_sibling():
    rule = _rule(
        "  selection:\n    CommandLine|contains: '/etc/hostname'\n",
        tags="attack.defense-evasion, attack.t1070, attack.t1070.004",
        condition="selection",
    )
    # Exact-tag sibling IS covered ...
    t1070_004 = Technique("T1070.004", "File Deletion", ("Defense Evasion",), "", "T1070.004")
    assert rule_covers(rule, t1070_004) is True
    # ... but the distinct sibling T1070.006 is NOT (no parent bleed).
    assert rule_covers(rule, BY_ID["T1070.006"]) is False
    ev = make_event(
        run_id="r",
        technique_id="T1070.006",
        image="/usr/bin/touch",
        command_line="touch -r /etc/hostname /tmp/x",
    )
    verdict = evaluate_technique(BY_ID["T1070.006"], [ev], [rule])
    assert verdict.detected is False
    assert verdict.gap_type is GapType.RULE


# --- Condition grammar errors surface as RuleError, not raw pySigma ----------
def test_numeric_of_them_is_ruleerror():
    with pytest.raises(RuleError):
        parse_rule(
            """
title: bad count
id: 77777777-7777-7777-7777-777777777777
logsource: {product: linux, category: process_creation}
detection:
  selection_a: {Image|endswith: '/a'}
  selection_b: {Image|endswith: '/b'}
  condition: 2 of them
tags: [attack.t1548.001]
""",
            "<bad>",
        )


def test_empty_of_pattern_is_ruleerror():
    with pytest.raises(RuleError):
        _rule("  selection_a:\n    Image|endswith: '/a'\n", condition="1 of filter_*")


# --- not-filter pattern ------------------------------------------------------
def test_selection_and_not_filter():
    rule = _rule(
        "  selection:\n    Image|endswith: '/cat'\n"
        "  filter:\n    CommandLine|contains: '/etc/hosts'\n",
        tags="attack.t1087.001",
        condition="selection and not filter",
    )
    assert rule_matches(rule, _ev(Image="/usr/bin/cat", CommandLine="cat /etc/passwd")) is not None
    assert rule_matches(rule, _ev(Image="/usr/bin/cat", CommandLine="cat /etc/hosts")) is None


# --- endswith is right-anchored ----------------------------------------------
def test_endswith_is_anchored():
    rule = _rule("  sel:\n    Image|endswith: '/cat'\n", tags="attack.t1087.001")
    assert rule_matches(rule, _ev(Image="/usr/bin/cat")) is not None
    assert rule_matches(rule, _ev(Image="/usr/bin/catx")) is None


# --- touch remediation rule fires on standard getopt spellings ---------------
@pytest.mark.parametrize(
    "cmd",
    [
        "touch -r /etc/hostname /tmp/x",
        "touch -amt 202001010000 /tmp/x",
        "touch -t202001010000 /tmp/x",
        "touch -r/etc/hostname /tmp/x",
        "touch --reference=/etc/hostname /tmp/x",
        "touch --date='2020-01-01' /tmp/x",
    ],
)
def test_touch_rule_covers_getopt_forms(cmd):
    rule = parse_rule((RULES_DIR / "roundtrip" / "timestomp_touch.yml").read_text(encoding="utf-8"))
    assert rule_matches(rule, _ev(Image="/usr/bin/touch", CommandLine=cmd)) is not None


def test_touch_rule_ignores_plain_touch():
    rule = parse_rule((RULES_DIR / "roundtrip" / "timestomp_touch.yml").read_text(encoding="utf-8"))
    assert rule_matches(rule, _ev(Image="/usr/bin/touch", CommandLine="touch /tmp/x")) is None


# --- ReDoS length cap --------------------------------------------------------
def test_oversized_value_is_capped_not_matched():
    rule = _rule("  sel:\n    CommandLine|contains: 'needle'\n")
    huge = "needle" + "a" * (MAX_MATCH_LEN + 10)  # contains needle but exceeds the cap
    assert rule_matches(rule, _ev(CommandLine=huge)) is None


# --- Flagship: the offense spec, rendered as snoopy would, matches the rule ---
def test_flagship_spec_matches_shipped_rule_and_misses_halves():
    rule = parse_rule(
        (RULES_DIR / "proc_creation_lnx_setgid_setuid.yml").read_text(encoding="utf-8")
    )
    suid_cmd = next(c for c in SPECS["T1548.001"].commands if "chmod" in c and "+s" in c)
    rendered = " ".join(shlex.split(suid_cmd))  # snoopy joins argv with spaces
    assert rule_matches(rule, _ev(Image="/usr/bin/sh", CommandLine=rendered)) is not None
    # Each half in isolation must NOT match (proves the rule needs both, not a marker).
    chown_only = "sh -c chown root /tmp/redgap_demo_suid"
    chmod_only = "sh -c chmod u+s /tmp/redgap_demo_suid"
    assert rule_matches(rule, _ev(Image="/usr/bin/sh", CommandLine=chown_only)) is None
    assert rule_matches(rule, _ev(Image="/usr/bin/sh", CommandLine=chmod_only)) is None


# --- Canonical-bytes determinism (stronger than order-blind dict==) ----------
def _canonical(verdict):
    return json.dumps(
        {
            "t": verdict.technique_id,
            "d": verdict.detected,
            "g": verdict.gap_type.value,
            "fr": list(verdict.firing_rules),
            "ev": [
                [e.rule_id, e.event_id, sorted(e.matched_fields.items())] for e in verdict.evidence
            ],
        },
        sort_keys=True,
    )


def test_verdict_serialization_is_stable():
    from redgap.catalog import CATALOG
    from redgap.detection.coverage import evaluate_all
    from redgap.detection.sigma_ast import load_rules

    rules = load_rules(RULES_DIR)
    events = {
        "T1548.001": [
            make_event(
                run_id="r",
                technique_id="T1548.001",
                image="/usr/bin/sh",
                command_line="sh -c chown root /x && chmod u+s /x",
            )
        ]
    }
    a = [_canonical(v) for v in evaluate_all(list(CATALOG), events, rules)]
    b = [_canonical(v) for v in evaluate_all(list(CATALOG), events, rules)]
    assert a == b
