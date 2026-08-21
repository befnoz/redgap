#!/usr/bin/env python3
"""Benchmark RedGap against the FULL public SigmaHQ Linux ``process_creation`` ruleset.

This runs ``redgap audit`` over the 122 real community rules vendored under
``tests/corpus/`` (a pinned SigmaHQ snapshot) and commits the result under
``docs/benchmarks/`` - a citable, third-party, adversarial-to-self measurement: of the
community Linux process-creation ruleset, how many rules actually FIRE on RedGap's real
captured telemetry, how many are SILENT (tagged to a technique yet never firing), how many
are out-of-corpus, and how many ATT&CK techniques the community ruleset covers.

    python scripts/gen_benchmark.py     # writes docs/benchmarks/ (coverage + scorecard + README)

Every number is engine-computed from real telemetry; nothing is authored. Re-running
produces no diff unless the engine, the fixtures, or the vendored corpus changed.
"""

from __future__ import annotations

from pathlib import Path

from redgap.audit import run_audit
from redgap.target import ReplayTarget

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "tests" / "corpus" / "sigmahq_linux_process_creation"
OUT = REPO / "docs" / "benchmarks"
# Pinned so the committed benchmark is reproducible (no wall-clock churn in git).
FIXED_GENERATED_AT = "2026-08-11T00:00:00+00:00"
# The upstream SigmaHQ commit this corpus was vendored from (see tests/corpus provenance).
SIGMAHQ_COMMIT = "8eaafff"


def main() -> None:
    res = run_audit(
        ReplayTarget(),
        rules_dir=CORPUS,
        generated_at=FIXED_GENERATED_AT,
        out_dir=OUT,
    )
    s = res.scorecard["summary"]
    c = res.coverage["summary"]
    readme = f"""# Benchmark: RedGap vs. the full public SigmaHQ Linux ruleset

RedGap's own parser + evaluator run `redgap audit` over **all {s["loaded"] + s["excluded"]} real
SigmaHQ `linux/process_creation` rules** (vendored under
[`tests/corpus/`](../../tests/corpus/sigmahq_linux_process_creation), pinned at SigmaHQ commit
`{SIGMAHQ_COMMIT}`) against RedGap's real captured telemetry. Everything below is
engine-computed from real logs + rules - no authored numbers, no language model.

## Headline

| Metric | Count |
|--------|------:|
| Rules loaded (evaluable) | **{s["loaded"]}** |
| Rules unevaluable (features outside RedGap's v1 Sigma subset) | {s["excluded"]} |
| Rules **firing** on RedGap's real telemetry | **{s["firing"]}** |
| Rules **SILENT** (valid, tagged to a technique, but never fire) | **{s["silent"]}** |
| Rules out-of-corpus (technique RedGap does not exercise) | {s["out_of_corpus"]} |
| ATT&CK techniques the community ruleset covers here | **{c["detected"]}** / {c["techniques"]} |

The **SILENT** count is the point: these are real, valid community rules that pass
`sigma-cli` validation and are tagged to a technique RedGap exercises, yet fire on *zero*
real events - a false-confidence blind spot a static linter cannot see. That is exactly what
`redgap audit` surfaces on your own rules.

## Reproduce

```bash
python scripts/gen_benchmark.py
# or directly:
redgap audit --rules tests/corpus/sigmahq_linux_process_creation --out docs/benchmarks
```

Artifacts: `coverage.json` / `coverage.md` (per-technique), `rules-scorecard.json` /
`rules-scorecard.md` (per-rule health), `navigator-layer.json` (drop into ATT&CK Navigator).
"""
    (OUT / "README.md").write_text(readme, encoding="utf-8", newline="\n")
    print(
        f"wrote {OUT}: loaded={s['loaded']} firing={s['firing']} silent={s['silent']} "
        f"out_of_corpus={s['out_of_corpus']} unevaluable={s['excluded']} "
        f"techniques_detected={c['detected']}/{c['techniques']}"
    )


if __name__ == "__main__":
    main()
