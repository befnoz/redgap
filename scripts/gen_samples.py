#!/usr/bin/env python3
"""Regenerate the committed sample reports under ``docs/samples/``.

These are the *offline REPLAY* reports a reviewer gets from ``redgap run`` - checked in
so the repo shows its own output without anyone having to run it. They are byte-stable:
the target is the committed fixtures, the run_id is fixed ("replay"), and the timestamp
is pinned below, so re-running this script produces no diff unless the engine or the
fixtures actually changed.

    python scripts/gen_samples.py     # writes docs/samples/{baseline,fixed}/

`baseline` is the plain run (one rule gap left open); `fixed` adds the round-trip rule
via --fix, flipping the timestomp gap green; `adaptive` is `run --adaptive`, adding the
deterministic attack-path artifacts. All three are real engine output, not authored - and
the `coverage.json` under `adaptive` is byte-identical to `baseline`'s.
"""

from __future__ import annotations

from pathlib import Path

from redgap.audit import run_audit
from redgap.pipeline import run_coverage
from redgap.target import ReplayTarget

# Pinned so the committed samples are reproducible (no wall-clock churn in git).
FIXED_GENERATED_AT = "2026-08-11T00:00:00+00:00"
REPO = Path(__file__).resolve().parents[1]
SAMPLES = REPO / "docs" / "samples"


def main() -> None:
    for name, fix in (("baseline", False), ("fixed", True)):
        out = SAMPLES / name
        run_coverage(
            ReplayTarget(),
            generated_at=FIXED_GENERATED_AT,
            out_dir=out,
            fix=fix,
        )
        print(f"wrote {out}/coverage.json, coverage.md, navigator-layer.json")

    # The adaptive run: identical coverage grid PLUS the deterministic attack-path.
    adaptive_out = SAMPLES / "adaptive"
    run_coverage(
        ReplayTarget(),
        generated_at=FIXED_GENERATED_AT,
        out_dir=adaptive_out,
        auto=True,
    )
    print(f"wrote {adaptive_out}/coverage.json + attack-path.json, attack-path.md")

    # The BYOR rule-health sample: `redgap audit` over examples/my-sigma (1 firing / 1 SILENT
    # / 1 out-of-corpus) - the committed scorecard the dashboard's rule-health card renders.
    byor_out = SAMPLES / "byor"
    run_audit(
        ReplayTarget(),
        rules_dir=REPO / "examples" / "my-sigma",
        generated_at=FIXED_GENERATED_AT,
        out_dir=byor_out,
    )
    print(f"wrote {byor_out}/rules-scorecard.json (+ coverage.json, navigator-layer.json)")


if __name__ == "__main__":
    main()
