"""`redgap verify` re-proves the three load-bearing claims offline. These tests pin that the
proof actually passes on the committed tree, and that it is honest - i.e. it genuinely
recomputes rather than rubber-stamping.
"""

from __future__ import annotations

from redgap.verify import run_verification

WHEN = "2026-08-11T00:00:00+00:00"


def test_verify_passes_on_the_committed_tree():
    r = run_verification(generated_at=WHEN)
    assert r.fixtures_checked == 51  # every committed fixture re-hashed vs provenance
    assert r.techniques == 51
    assert r.detected == 34
    assert r.deterministic is True
    assert r.planner_independent is True
    assert r.ok is True


def test_verify_fixture_authenticity_fails_closed_on_tamper(tmp_path, monkeypatch):
    # Point the ReplayTarget at a copy with one fixture's raw log edited; verify must raise
    # (authenticity is the first, fail-closed step) rather than quietly reporting OK.
    import shutil

    from redgap import verify as verify_mod
    from redgap._resources import fixtures_dir

    src = fixtures_dir()
    dst = tmp_path / "fixtures"
    shutil.copytree(src, dst)
    victim = next(dst.glob("*/raw/exec.log"))
    victim.write_text(victim.read_text(encoding="utf-8") + "\nTAMPERED\n", encoding="utf-8")

    real_target = verify_mod.ReplayTarget

    def _tampered(*a, **k):
        return real_target(fixtures_dir=dst)

    monkeypatch.setattr(verify_mod, "ReplayTarget", _tampered)
    from redgap.target import FixtureError

    try:
        run_verification(generated_at=WHEN)
        raise AssertionError("verify must fail closed on a tampered fixture")
    except FixtureError:
        pass
