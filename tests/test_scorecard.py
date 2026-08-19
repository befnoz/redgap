"""The rule scorecard is a pure reduction of (loaded, excluded, verdicts, catalog).

These tests build the inputs by hand - no fixtures, no engine - so they pin the bucketing
contract (firing / silent / out-of-corpus / unevaluable) and its determinism directly.
"""

from __future__ import annotations

import json

from redgap.detection.sigma_ast import LoadedRule
from redgap.models import Evidence, GapType, Technique, Verdict
from redgap.report.scorecard import rule_scorecard, rule_scorecard_markdown

WHEN = "2026-08-11T00:00:00Z"

T_A = Technique(
    id="T1000", name="Alpha", tactics=("Discovery",), description="", atomic_ref="T1000"
)
T_B = Technique(id="T2000", name="Beta", tactics=("Impact",), description="", atomic_ref="T2000")
CATALOG = (T_A, T_B)


def _rule(rid: str, path: str, tech_ids: tuple[str, ...]) -> LoadedRule:
    return LoadedRule(
        id=rid,
        title=f"{rid} title",
        level="low",
        path=path,
        technique_ids=tech_ids,
        ast=object(),
        source="",
    )


R_FIRE = _rule("R-FIRE", "/x/fire.yml", ("T1000",))
R_SILENT = _rule("R-SILENT", "/x/silent.yml", ("T1000",))
R_OOC = _rule("R-OOC", "/x/ooc.yml", ("T9999",))

V_A = Verdict(
    technique_id="T1000",
    executed=True,
    telemetry_present=True,
    detected=True,
    gap_type=GapType.NONE,
    firing_rules=("R-FIRE",),
    matched_event_ids=("ev1",),
    evidence=(Evidence("R-FIRE", "R-FIRE title", "ev1", {"Image": "/x"}, "/x/fire.yml"),),
)
V_B = Verdict(
    technique_id="T2000",
    executed=True,
    telemetry_present=True,
    detected=False,
    gap_type=GapType.RULE,
    unexpected=True,
)

EXCLUDED = [("/x/bad.yml", "unsupported Sigma modifier(s) ['base64']", ("T1000",))]


def _card():
    return rule_scorecard(
        [R_FIRE, R_SILENT, R_OOC],
        EXCLUDED,
        [V_A, V_B],
        CATALOG,
        mode="replay",
        run_id="test",
        generated_at=WHEN,
        rules_dir="/x",
    )


def test_buckets_are_total_and_disjoint():
    sc = _card()
    s = sc["summary"]
    assert s["loaded"] == 3
    assert s["firing"] + s["silent"] + s["out_of_corpus"] == s["loaded"]
    assert s["unevaluable"] == len(EXCLUDED) == 1
    assert s["detected"] == 1
    statuses = {r["id"]: r["status"] for r in sc["rules"]}
    assert statuses == {"R-FIRE": "firing", "R-SILENT": "silent", "R-OOC": "out_of_corpus"}


def test_firing_rule_carries_real_evidence():
    sc = _card()
    row = next(r for r in sc["rules"] if r["id"] == "R-FIRE")
    assert row["fired_on"] == [
        {"technique_id": "T1000", "event_id": "ev1", "matched_fields": {"Image": "/x"}}
    ]
    assert row["covered_but_not_fired"] == []


def test_silent_rule_names_covered_technique_with_telemetry_flag():
    sc = _card()
    row = next(r for r in sc["rules"] if r["id"] == "R-SILENT")
    assert row["status"] == "silent"
    assert row["silent_detail"] == [{"technique_id": "T1000", "telemetry_present": True}]


def test_out_of_corpus_when_no_covered_technique():
    sc = _card()
    row = next(r for r in sc["rules"] if r["id"] == "R-OOC")
    assert row["status"] == "out_of_corpus"
    assert row["in_corpus_techniques"] == []


def test_unevaluable_is_verbatim_excluded():
    sc = _card()
    assert len(sc["unevaluable"]) == 1
    u = sc["unevaluable"][0]
    assert u["reason"] == EXCLUDED[0][1]  # verbatim
    assert u["technique_ids"] == ["T1000"]
    assert u["targets_in_corpus"] is True


def test_markdown_has_sections_and_is_ascii():
    md = rule_scorecard_markdown(_card())
    for header in ("## FIRING", "## SILENT", "## OUT-OF-CORPUS", "## UNEVALUABLE"):
        assert header in md
    assert "R-FIRE" in md
    # Our scaffolding (and these ASCII test titles) must carry no emoji / arrows.
    assert all(ord(ch) < 0x2190 for ch in md)


def test_scorecard_is_deterministic():
    a = json.dumps(_card(), sort_keys=True)
    b = json.dumps(_card(), sort_keys=True)
    assert a == b


def test_duplicate_id_does_not_flip_a_silent_rule_to_firing():
    # Two rule FILES share one Sigma id: A (covers T1000) fires; B (covers T2000) is silent.
    # An id-keyed join would credit B with A's firing and hide it; the path-keyed join must not.
    a = _rule("DUP", "/x/a.yml", ("T1000",))
    b = _rule("DUP", "/x/b.yml", ("T2000",))
    va = Verdict(
        technique_id="T1000",
        executed=True,
        telemetry_present=True,
        detected=True,
        gap_type=GapType.NONE,
        firing_rules=("DUP",),
        evidence=(Evidence("DUP", "A", "ev1", {"Image": "/x"}, "/x/a.yml"),),
    )
    vb = Verdict(
        technique_id="T2000",
        executed=True,
        telemetry_present=True,
        detected=False,
        gap_type=GapType.RULE,
    )
    sc = rule_scorecard(
        [a, b], [], [va, vb], CATALOG, mode="replay", run_id="t", generated_at=WHEN, rules_dir="/x"
    )
    # Paths are relativized in the artifact (no absolute-path leak); "/x/a.yml" is outside
    # cwd so it renders as its basename. The path-keyed JOIN still uses the absolute
    # in-memory path, so A and B stay correctly distinguished.
    status = {r["path"]: r["status"] for r in sc["rules"]}
    assert status["a.yml"] == "firing"
    assert status["b.yml"] == "silent"  # NOT hidden as firing by its sibling's id
    assert sc["summary"]["silent"] == 1 and sc["summary"]["firing"] == 1
