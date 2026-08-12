"""Golden positive/near-miss tests for every rule.

The positive proves the rule fires on the real technique artifact; the near-miss
proves the rule is specific (not an over-broad rule that "detects" everything and
inflates coverage). This is the SigmaHQ-standard way to trust a rule.
"""

from __future__ import annotations

from pathlib import Path

from redgap.detection.engine import rule_matches
from redgap.detection.sigma_ast import parse_rule
from redgap.telemetry.schema import make_event

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def _load(relpath: str):
    path = RULES_DIR / relpath
    return parse_rule(path.read_text(encoding="utf-8"), str(path))


def _ev(**kw):
    kw.setdefault("run_id", "t")
    kw.setdefault("technique_id", "T0000")
    return make_event(**kw)


# --- Shipped SigmaHQ setuid rule (the flagship: proves ground truth is real) ---
def test_setuid_positive_single_shell_line():
    rule = _load("proc_creation_lnx_setgid_setuid.yml")
    ev = _ev(
        image="/usr/bin/sh",
        command_line="sh -c chown root /tmp/demo_suid && chmod u+s /tmp/demo_suid",
    )
    match = rule_matches(rule, ev)
    assert match is not None
    assert "CommandLine" in match.matched_fields


def test_setuid_positive_gsuid_variant():
    rule = _load("proc_creation_lnx_setgid_setuid.yml")
    ev = _ev(image="/usr/bin/sh", command_line="sh -c chown root /x && chmod g+s /x")
    assert rule_matches(rule, ev) is not None


def test_setuid_negative_missing_chown():
    rule = _load("proc_creation_lnx_setgid_setuid.yml")
    ev = _ev(image="/usr/bin/chmod", command_line="chmod u+s /tmp/demo_suid")
    assert rule_matches(rule, ev) is None


def test_setuid_negative_missing_chmod():
    rule = _load("proc_creation_lnx_setgid_setuid.yml")
    ev = _ev(image="/usr/bin/chown", command_line="chown root /tmp/demo_suid")
    assert rule_matches(rule, ev) is None


# --- Authored: account discovery via /etc/passwd (T1087.001) -------------------
def test_passwd_positive():
    rule = _load("redgap/account_discovery_etc_passwd.yml")
    ev = _ev(image="/usr/bin/cat", command_line="cat /etc/passwd")
    assert rule_matches(rule, ev) is not None


def test_passwd_negative_other_file():
    rule = _load("redgap/account_discovery_etc_passwd.yml")
    ev = _ev(image="/usr/bin/cat", command_line="cat /etc/hosts")
    assert rule_matches(rule, ev) is None


def test_passwd_positive_editor():
    # Parity with the shipped SigmaHQ reader set: editors reading /etc/passwd match too.
    rule = _load("redgap/account_discovery_etc_passwd.yml")
    ev = _ev(image="/usr/bin/vim", command_line="vim /etc/passwd")
    assert rule_matches(rule, ev) is not None


def test_passwd_negative_unlisted_binary():
    rule = _load("redgap/account_discovery_etc_passwd.yml")
    ev = _ev(image="/usr/bin/logger", command_line="logger reading /etc/passwd")
    assert rule_matches(rule, ev) is None


# --- Authored: create account (T1136.001) --------------------------------------
def test_useradd_positive():
    rule = _load("redgap/create_account_useradd.yml")
    ev = _ev(image="/usr/sbin/useradd", command_line="useradd -M -N -s /usr/sbin/nologin svc_demo")
    assert rule_matches(rule, ev) is not None


def test_useradd_negative():
    rule = _load("redgap/create_account_useradd.yml")
    ev = _ev(image="/usr/bin/id", command_line="id")
    assert rule_matches(rule, ev) is None


# --- Round-trip closing rule: timestomp (T1070.006) ----------------------------
def test_touch_positive_reference_flag():
    rule = _load("roundtrip/timestomp_touch.yml")
    ev = _ev(image="/usr/bin/touch", command_line="touch -r /etc/hostname /tmp/agent_file")
    assert rule_matches(rule, ev) is not None


def test_touch_negative_plain_touch():
    rule = _load("roundtrip/timestomp_touch.yml")
    ev = _ev(image="/usr/bin/touch", command_line="touch /tmp/agent_file")
    assert rule_matches(rule, ev) is None


# --- Regex modifier support (|re) is exercised so it is not dead, untested code -
def test_regex_modifier_supported():
    rule = parse_rule(
        """
title: re modifier probe
id: 33333333-3333-3333-3333-333333333333
logsource: {category: process_creation, product: linux}
detection:
  sel:
    CommandLine|re: 'chmod\\s+u\\+s'
  condition: sel
tags: [attack.privilege-escalation, attack.t1548.001]
""",
        "<re-probe>",
    )
    assert rule_matches(rule, _ev(command_line="run chmod  u+s /x")) is not None
    assert rule_matches(rule, _ev(command_line="run chmodu+s /x")) is None
