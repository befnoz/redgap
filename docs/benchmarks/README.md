# Benchmark: RedGap vs. the full public SigmaHQ Linux ruleset

RedGap's own parser + evaluator run `redgap audit` over **all 122 real
SigmaHQ `linux/process_creation` rules** (vendored under
[`tests/corpus/`](../../tests/corpus/sigmahq_linux_process_creation), pinned at SigmaHQ commit
`8eaafff`) against RedGap's real captured telemetry. Everything below is
engine-computed from real logs + rules - no authored numbers, no language model.

## Headline

| Metric | Count |
|--------|------:|
| Rules loaded (evaluable) | **122** |
| Rules unevaluable (features outside RedGap's v1 Sigma subset) | 0 |
| Rules **firing** on RedGap's real telemetry | **34** |
| Rules **SILENT** (valid, tagged to a technique, but never fire) | **50** |
| Rules out-of-corpus (technique RedGap does not exercise) | 38 |
| ATT&CK techniques the community ruleset covers here | **33** / 51 |

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
