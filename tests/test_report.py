"""The report renderers turn deterministic verdicts into the CES proof artifacts:
coverage.json, coverage.md, and an ATT&CK Navigator layer. All must be pure functions
of the verdicts (no wall clock, no AI) and reflect the 3-detected / 2-gap demo.
"""

from __future__ import annotations

import json
from pathlib import Path

from redgap.catalog import BY_ID
from redgap.detection.coverage import evaluate_all
from redgap.detection.sigma_ast import load_rules
from redgap.report import coverage_dict, markdown_report, navigator_layer
from redgap.report.navigator import DETECTED_COLOR, GAP_COLOR
from redgap.telemetry.schema import make_event

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
WHEN = "2026-08-11T00:00:00Z"

# A fixed 5-technique slice (the original kill-chain) so the report renderers are tested
# against a known 3-detected / 2-gap scenario independent of the full DEMO size.
DEMO = tuple(BY_ID[i] for i in ("T1087.001", "T1057", "T1136.001", "T1548.001", "T1070.006"))


def _verdicts():
    def ev(tid, **kw):
        return make_event(run_id="r", technique_id=tid, **kw)

    events = {
        "T1087.001": [ev("T1087.001", image="/usr/bin/cat", command_line="cat /etc/passwd")],
        "T1057": [ev("T1057", image="/usr/bin/ps", command_line="ps aux")],
        "T1136.001": [ev("T1136.001", image="/usr/sbin/useradd", command_line="useradd -M svc")],
        "T1548.001": [
            ev(
                "T1548.001",
                image="/usr/bin/sh",
                command_line="sh -c chown root /x && chmod u+s /x",
            )
        ],
        "T1070.006": [
            ev("T1070.006", image="/usr/bin/touch", command_line="touch -r /etc/hostname /x")
        ],
    }
    return evaluate_all(list(DEMO), events, load_rules(RULES_DIR))


def test_coverage_dict_shape_and_evidence():
    d = coverage_dict(DEMO, _verdicts(), mode="replay", run_id="r", generated_at=WHEN)
    assert d["summary"]["detected"] == 3
    assert d["summary"]["gaps"] == 2
    assert d["summary"]["gaps_by_type"] == {"rule": 1, "base_rate": 1}
    # It must be JSON-serializable and carry evidence for the flagship.
    text = json.dumps(d)
    assert "c21c4eaa-ba2e-419a-92b2-8371703cbe21" in text
    setuid = next(t for t in d["techniques"] if t["id"] == "T1548.001")
    assert setuid["detected"] is True
    assert setuid["evidence"] and setuid["evidence"][0]["matched_fields"]


def test_navigator_layer_colors_and_spec():
    layer = navigator_layer(DEMO, _verdicts())
    assert layer["versions"]["layer"] == "4.5"
    assert layer["domain"] == "enterprise-attack"
    colors = {t["techniqueID"]: t["color"] for t in layer["techniques"]}
    assert colors["T1548.001"] == DETECTED_COLOR
    assert colors["T1070.006"] == GAP_COLOR
    assert colors["T1057"] == GAP_COLOR
    # Sub-technique ids are used verbatim (Navigator nests them under the parent).
    assert any(t["techniqueID"] == "T1087.001" for t in layer["techniques"])


def test_navigator_multi_tactic_technique_appears_in_every_tactic_column():
    # T1548.001 maps to two tactics; it must be emitted (and colored) for BOTH, so the
    # heatmap agrees with coverage.md/json rather than reading blank in one column.
    layer = navigator_layer(DEMO, _verdicts())
    tactics = {t["tactic"] for t in layer["techniques"] if t["techniqueID"] == "T1548.001"}
    assert tactics == {"privilege-escalation", "defense-evasion"}, tactics


def test_markdown_has_table_gaps_and_evidence():
    md = markdown_report(DEMO, _verdicts(), mode="replay", run_id="r", generated_at=WHEN)
    assert "3 / 5 techniques detected" in md
    assert "| T1548.001 |" in md
    assert "## Gaps" in md
    assert "## Evidence" in md
    assert "c21c4eaa-ba2e-419a-92b2-8371703cbe21" in md
    # No emoji clutter in the report.
    assert all(ord(ch) < 0x2190 for ch in md)


def test_reports_are_deterministic():
    a = coverage_dict(DEMO, _verdicts(), mode="replay", run_id="r", generated_at=WHEN)
    b = coverage_dict(DEMO, _verdicts(), mode="replay", run_id="r", generated_at=WHEN)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
