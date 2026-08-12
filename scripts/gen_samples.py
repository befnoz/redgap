#!/usr/bin/env python3
"""Regenerate the committed sample reports under ``docs/samples/``.

These are the *offline REPLAY* reports a reviewer gets from ``redgap run`` — checked in
so the repo shows its own output without anyone having to run it. They are byte-stable:
the target is the committed fixtures, the run_id is fixed ("replay"), and the timestamp
is pinned below, so re-running this script produces no diff unless the engine or the
fixtures actually changed.

    python scripts/gen_samples.py     # writes docs/samples/{baseline,fixed}/

`baseline` is the plain run (one rule gap left open); `fixed` adds the round-trip rule
via --fix, flipping the timestomp gap green. Both are real engine output, not authored.
"""

from __future__ import annotations

from pathlib import Path

from redgap.pipeline import run_coverage
from redgap.target import ReplayTarget

# Pinned so the committed samples are reproducible (no wall-clock churn in git).
FIXED_GENERATED_AT = "2026-08-11T00:00:00+00:00"
SAMPLES = Path(__file__).resolve().parents[1] / "docs" / "samples"


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


if __name__ == "__main__":
    main()
