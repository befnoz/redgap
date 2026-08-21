"""`redgap suggest`: the LLM drafts a rule, the ENGINE judges it. Only the deterministic
judge is honesty-critical, and it is fully testable offline - given a candidate rule (from
anywhere), does RedGap's own engine agree it fires on the real telemetry? These tests feed
hand-built candidates so no API key is needed.
"""

from __future__ import annotations

from redgap.suggest import judge_candidate
from redgap.target import ReplayTarget

RULE_GAP_TID = "T1070.006"  # timestomp: telemetry present, no shipped rule -> a rule-gap


def _events():
    return ReplayTarget().events_by_technique()


def _rule(*, tags: str, detection: str) -> str:
    return (
        "title: candidate\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "logsource:\n    product: linux\n    category: process_creation\n"
        f"detection:\n{detection}    condition: selection\n"
        f"{tags}"
    )


def test_judge_labels_a_matching_tagged_rule_as_closing_or_broad():
    events = _events()
    cmd = events[RULE_GAP_TID][0]["CommandLine"]
    # a candidate that matches the FULL real command line (contains) is highly specific
    candidate = _rule(
        tags=f"tags:\n    - attack.{RULE_GAP_TID.lower()}\n",
        detection=f"    selection:\n        CommandLine|contains: {cmd!r}\n",
    )
    v = judge_candidate(candidate, RULE_GAP_TID, events)
    assert v["fires_target"] is True
    assert v["status"] in {"closes", "over_broad"}  # it fires on the target's real telemetry


def test_judge_flags_an_overbroad_rule():
    events = _events()
    # Image contains "/" matches essentially every process event -> fires far beyond target.
    candidate = _rule(
        tags=f"tags:\n    - attack.{RULE_GAP_TID.lower()}\n",
        detection="    selection:\n        Image|contains: '/'\n",
    )
    v = judge_candidate(candidate, RULE_GAP_TID, events)
    assert v["status"] == "over_broad"
    assert v["also_fires"]  # names the unrelated techniques it also fires on


def test_judge_flags_a_non_firing_rule():
    events = _events()
    candidate = _rule(
        tags=f"tags:\n    - attack.{RULE_GAP_TID.lower()}\n",
        detection="    selection:\n        CommandLine|contains: 'zzz_this_never_appears_zzz'\n",
    )
    v = judge_candidate(candidate, RULE_GAP_TID, events)
    assert v["status"] == "no_fire"
    assert v["fires_target"] is False


def test_judge_flags_a_specific_but_untagged_rule():
    events = _events()
    cmd = events[RULE_GAP_TID][0]["CommandLine"]
    candidate = _rule(  # fires only on target (full command), but no attack tag
        tags="",
        detection=f"    selection:\n        CommandLine|contains: {cmd!r}\n",
    )
    v = judge_candidate(candidate, RULE_GAP_TID, events)
    assert v["tagged"] is False
    assert v["status"] in {"untagged", "over_broad"}


def test_judge_rejects_a_malformed_candidate_as_unevaluable():
    v = judge_candidate("this: is: not: a: sigma: rule", RULE_GAP_TID, _events())
    assert v["status"] == "unevaluable"
    assert "reason" in v
