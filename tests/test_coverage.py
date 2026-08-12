"""End-to-end coverage: the default run must show 3 detections + 2 different gaps,
and the remediation round-trip must flip the timestomp rule-gap red->green.
"""

from __future__ import annotations

from pathlib import Path

from redgap.catalog import BY_ID, CATALOG
from redgap.detection.coverage import evaluate_all, evaluate_technique
from redgap.detection.sigma_ast import load_rules
from redgap.models import GapType
from redgap.telemetry.schema import make_event

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def _events():
    def ev(tid, **kw):
        return make_event(run_id="r", technique_id=tid, **kw)

    return {
        "T1087.001": [ev("T1087.001", image="/usr/bin/cat", command_line="cat /etc/passwd")],
        "T1057": [ev("T1057", image="/usr/bin/ps", command_line="ps aux")],
        "T1136.001": [
            ev(
                "T1136.001",
                image="/usr/sbin/useradd",
                command_line="useradd -M -N -s /usr/sbin/nologin svc_demo",
            )
        ],
        "T1548.001": [
            ev(
                "T1548.001",
                image="/usr/bin/sh",
                command_line="sh -c chown root /tmp/demo_suid && chmod u+s /tmp/demo_suid",
            )
        ],
        "T1070.006": [
            ev(
                "T1070.006",
                image="/usr/bin/touch",
                command_line="touch -r /etc/hostname /tmp/agent_file",
            )
        ],
    }


def test_default_coverage_three_detected_two_gaps():
    rules = load_rules(RULES_DIR)  # excludes roundtrip/
    verdicts = {v.technique_id: v for v in evaluate_all(list(CATALOG), _events(), rules)}

    assert verdicts["T1087.001"].detected
    assert verdicts["T1087.001"].gap_type is GapType.NONE
    assert verdicts["T1136.001"].detected
    assert verdicts["T1548.001"].detected
    # The setuid detection is the real, shipped SigmaHQ rule.
    assert "c21c4eaa-ba2e-419a-92b2-8371703cbe21" in verdicts["T1548.001"].firing_rules

    assert not verdicts["T1057"].detected
    assert verdicts["T1057"].gap_type is GapType.BASE_RATE
    assert not verdicts["T1070.006"].detected
    assert verdicts["T1070.006"].gap_type is GapType.RULE

    assert sum(1 for v in verdicts.values() if v.detected) == 3


def test_every_detected_verdict_carries_evidence():
    rules = load_rules(RULES_DIR)
    for verdict in evaluate_all(list(CATALOG), _events(), rules):
        if verdict.detected:
            assert verdict.evidence, f"{verdict.technique_id}: detected but no evidence trail"
            assert verdict.firing_rules
            assert verdict.matched_event_ids


def test_roundtrip_closes_the_rule_gap():
    events = _events()["T1070.006"]
    before = evaluate_technique(BY_ID["T1070.006"], events, load_rules(RULES_DIR))
    after = evaluate_technique(BY_ID["T1070.006"], events, load_rules(RULES_DIR, exclude=()))
    assert before.detected is False
    assert before.gap_type is GapType.RULE
    assert after.detected is True
    assert after.gap_type is GapType.NONE
