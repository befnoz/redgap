"""End-to-end BYOR audit over the committed real-telemetry fixtures and tmp user rule dirs.

Every verdict here is engine-computed against the shipped fixtures; the tests only assert
how a user's own rules are scored (coverage grid + rule-health buckets), never a fabricated
number.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from redgap._resources import rules_dir as _rules_dir
from redgap.audit import run_audit
from redgap.pipeline import run_coverage
from redgap.target import ReplayTarget

WHEN = "2026-08-11T00:00:00Z"
ROUNDTRIP_RULE = _rules_dir() / "roundtrip" / "timestomp_touch.yml"

SILENT_RULE = """\
title: Silent probe
id: 11111111-0000-0000-0000-000000000001
status: experimental
tags:
    - attack.t1082
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/zzz_nonexistent_binary'
    condition: selection
"""

FOREIGN_RULE = """\
title: Foreign windows rule
id: 22222222-0000-0000-0000-000000000002
status: experimental
tags:
    - attack.t1218.011
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\rundll32.exe'
    condition: selection
"""

BASE64_RULE = """\
title: Unsupported base64 modifier rule
id: 33333333-0000-0000-0000-000000000003
status: experimental
tags:
    - attack.t1548.001
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|base64: 'chmod u+s'
    condition: selection
"""


def _dir(tmp_path, **rules):
    d = tmp_path / "rules"
    d.mkdir()
    for name, text in rules.items():
        (d / f"{name}.yml").write_text(text, encoding="utf-8")
    return d


def _shipped_detected() -> int:
    # audit loads the shipped dir WHOLE (exclude=()), so the comparable baseline is
    # run_coverage(fix=True), which also loads the roundtrip closing rule.
    _, cov = run_coverage(ReplayTarget(), generated_at=WHEN, fix=True)
    return cov["summary"]["detected"]


def test_audit_on_shipped_rules_matches_full_load_coverage():
    detected = _shipped_detected()
    ar = run_audit(ReplayTarget(), rules_dir=_rules_dir(), generated_at=WHEN)
    assert ar.coverage["summary"]["detected"] == detected
    assert ar.scorecard["summary"]["detected"] == detected
    # Anti-divergence: the scorecard's firing set == the coverage grid's firing set.
    grid_firing = {rid for v in ar.verdicts for rid in v.firing_rules}
    card_firing = {r["id"] for r in ar.scorecard["rules"] if r["status"] == "firing"}
    assert card_firing == grid_firing


def test_audit_silent_flags_a_tagged_but_nonfiring_rule(tmp_path):
    d = _dir(tmp_path, silent=SILENT_RULE)
    ar = run_audit(ReplayTarget(), rules_dir=d, generated_at=WHEN)
    rows = ar.scorecard["rules"]
    assert len(rows) == 1 and rows[0]["status"] == "silent"
    assert rows[0]["silent_detail"] == [{"technique_id": "T1082", "telemetry_present": True}]
    v = next(v for v in ar.verdicts if v.technique_id == "T1082")
    assert v.detected is False  # a silent rule closes nothing


def test_audit_closing_rule_fires_and_flips_the_gap(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    shutil.copy(ROUNDTRIP_RULE, d / "timestomp_touch.yml")
    ar = run_audit(ReplayTarget(), rules_dir=d, generated_at=WHEN)
    row = ar.scorecard["rules"][0]
    assert row["status"] == "firing"
    assert row["fired_on"] and row["fired_on"][0]["technique_id"] == "T1070.006"
    assert row["fired_on"][0]["event_id"]  # real captured event id, not blank
    v = next(v for v in ar.verdicts if v.technique_id == "T1070.006")
    assert v.detected is True
    assert ar.scorecard["summary"]["firing"] >= 1


def test_audit_foreign_rule_is_out_of_corpus(tmp_path):
    d = _dir(tmp_path, foreign=FOREIGN_RULE)
    ar = run_audit(ReplayTarget(), rules_dir=d, generated_at=WHEN)
    row = ar.scorecard["rules"][0]
    assert row["status"] == "out_of_corpus"
    # Neither detected nor counted as a gap-closer anywhere.
    assert ar.coverage["summary"]["detected"] == 0


def test_audit_unsupported_modifier_is_unevaluable(tmp_path):
    d = _dir(tmp_path, b64=BASE64_RULE)
    ar = run_audit(ReplayTarget(), rules_dir=d, generated_at=WHEN)
    assert ar.scorecard["summary"]["loaded"] == 0
    assert len(ar.scorecard["unevaluable"]) == 1
    u = ar.scorecard["unevaluable"][0]
    assert "base64" in u["reason"]
    assert u["targets_in_corpus"] is True
    v = next(v for v in ar.verdicts if v.technique_id == "T1548.001")
    assert v.candidates_excluded >= 1  # the engine also saw the exclusion


def test_audit_fail_under_gate_uses_own_detected_count():
    detected = _shipped_detected()

    def _exit(fail_under):
        return run_audit(
            ReplayTarget(), rules_dir=_rules_dir(), generated_at=WHEN, fail_under=fail_under
        ).exit_code

    assert _exit(detected + 1) == 1
    assert _exit(detected) == 0
    assert _exit(None) == 0


def test_audit_does_not_inherit_unexpected_exit(tmp_path):
    # A single foreign rule makes most shipped-expected techniques gaps; exit_code_for would
    # flag them 'unexpected' and exit 1. audit must NOT - gaps are findings, not failures.
    d = _dir(tmp_path, foreign=FOREIGN_RULE)
    ar = run_audit(ReplayTarget(), rules_dir=d, generated_at=WHEN, fail_under=None)
    assert ar.exit_code == 0


def test_examples_demo_stays_honest():
    # The README's runnable demo must keep producing exactly one of each bucket.
    demo = Path(__file__).resolve().parents[1] / "examples" / "my-sigma"
    ar = run_audit(ReplayTarget(), rules_dir=demo, generated_at=WHEN)
    s = ar.scorecard["summary"]
    assert (s["firing"], s["silent"], s["out_of_corpus"]) == (1, 1, 1)


def test_audit_missing_dir_raises(tmp_path):
    with pytest.raises(ValueError):
        run_audit(ReplayTarget(), rules_dir=tmp_path / "does_not_exist", generated_at=WHEN)


def test_audit_writes_all_five_artifacts(tmp_path):
    out = tmp_path / "byor-out"
    run_audit(ReplayTarget(), rules_dir=_rules_dir(), generated_at=WHEN, out_dir=out)
    for name in (
        "coverage.json",
        "coverage.md",
        "navigator-layer.json",
        "rules-scorecard.json",
        "rules-scorecard.md",
    ):
        assert (out / name).is_file(), name
