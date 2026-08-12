"""The REPLAY pipeline over the committed real fixtures: the default run detects 26/38
with the flagship on a shipped rule, --fix closes the timestomp gap, and the result is
deterministic — all offline, no Docker, no API key.
"""

from __future__ import annotations

import json

from redgap.models import GapType
from redgap.pipeline import exit_code_for, run_coverage
from redgap.target import ReplayTarget

WHEN = "2026-08-11T00:00:00Z"


def test_replay_default_detected_count(tmp_path):
    verdicts, report = run_coverage(ReplayTarget(), generated_at=WHEN, out_dir=tmp_path)
    by = {v.technique_id: v for v in verdicts}
    assert report["summary"]["detected"] == 26
    assert report["summary"]["techniques"] == 38
    assert by["T1548.001"].detected
    assert "c21c4eaa-ba2e-419a-92b2-8371703cbe21" in by["T1548.001"].firing_rules
    assert by["T1057"].gap_type is GapType.BASE_RATE
    assert by["T1070.006"].gap_type is GapType.RULE
    assert exit_code_for(verdicts) == 0
    for name in ("coverage.json", "coverage.md", "navigator-layer.json"):
        assert (tmp_path / name).exists()


def test_fix_closes_the_timestomp_gap(tmp_path):
    verdicts, report = run_coverage(ReplayTarget(), generated_at=WHEN, out_dir=tmp_path, fix=True)
    by = {v.technique_id: v for v in verdicts}
    assert by["T1070.006"].detected
    assert report["summary"]["detected"] == 27
    assert report["summary"]["gaps_by_type"] == {"base_rate": 5, "rule": 6}


def test_replay_is_deterministic():
    _, a = run_coverage(ReplayTarget(), generated_at=WHEN)
    _, b = run_coverage(ReplayTarget(), generated_at=WHEN)
    # The machine-varying generated_at is excluded; the coverage facts must be identical.
    assert json.dumps(a["techniques"], sort_keys=True) == json.dumps(
        b["techniques"], sort_keys=True
    )
    assert a["summary"] == b["summary"]
