"""``redgap run --adaptive`` must write the attack-path artifacts AND leave the coverage
grid byte-identical to a plain run. The narrative (attack-path) and the authoritative grid
(coverage) both read the same deterministic verdicts, so they can never disagree on any
``detected`` - this pins that cross-consistency at the file level.
"""

from __future__ import annotations

import json
from pathlib import Path

from redgap.pipeline import run_coverage
from redgap.target import ReplayTarget

WHEN = "2026-08-11T00:00:00Z"


def _run(tmp_path: Path, *, auto: bool):
    out = tmp_path / ("auto" if auto else "batch")
    run_coverage(ReplayTarget(), generated_at=WHEN, out_dir=out, auto=auto)
    return out


def test_adaptive_run_writes_attack_path_artifacts(tmp_path: Path):
    out = _run(tmp_path, auto=True)
    assert (out / "coverage.json").is_file()
    assert (out / "attack-path.json").is_file()
    assert (out / "attack-path.md").is_file()
    ap = json.loads((out / "attack-path.json").read_text(encoding="utf-8"))
    assert ap["schema"] == "redgap.attack_path/v1"
    assert ap["planner"] == "adaptive-heuristic"
    assert ap["steps"], "an offline adaptive run must produce at least one step"


def test_plain_run_does_not_write_attack_path(tmp_path: Path):
    out = _run(tmp_path, auto=False)
    assert (out / "coverage.json").is_file()
    assert not (out / "attack-path.json").exists()
    assert not (out / "attack-path.md").exists()


def test_coverage_grid_is_byte_identical_with_and_without_adaptive(tmp_path: Path):
    auto = _run(tmp_path, auto=True)
    batch = _run(tmp_path, auto=False)
    for name in ("coverage.json", "coverage.md", "navigator-layer.json"):
        assert (auto / name).read_bytes() == (batch / name).read_bytes(), name


def test_attack_path_never_contradicts_the_coverage_grid(tmp_path: Path):
    out = _run(tmp_path, auto=True)
    coverage = json.loads((out / "coverage.json").read_text(encoding="utf-8"))
    grid = {t["id"]: t for t in coverage["techniques"]}
    ap = json.loads((out / "attack-path.json").read_text(encoding="utf-8"))
    for step in ap["steps"]:
        assert step["detected"] == grid[step["technique_id"]]["detected"]


def test_attack_path_md_renders_the_killchain_and_stop_note(tmp_path: Path):
    out = _run(tmp_path, auto=True)
    md = (out / "attack-path.md").read_text(encoding="utf-8")
    assert "# RedGap attack path" in md
    assert "| # | Technique |" in md
    assert "Agent stopped:" in md
    assert "the planner only ordered the chain" in md


def test_lf_newlines_in_committed_artifacts(tmp_path: Path):
    out = _run(tmp_path, auto=True)
    for name in ("attack-path.json", "attack-path.md"):
        assert b"\r\n" not in (out / name).read_bytes(), name  # LF-only on every OS
