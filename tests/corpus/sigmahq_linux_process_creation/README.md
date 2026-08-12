# SigmaHQ `linux/process_creation` corpus (vendored)

These **122** `.yml` files are the complete `rules/linux/process_creation/` ruleset from
the upstream [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) project, vendored verbatim
so RedGap's engine can be validated against real-world detection rules **offline and
reproducibly** — no network fetch in CI.

## Provenance

| | |
|---|---|
| Source | https://github.com/SigmaHQ/sigma — `rules/linux/process_creation/` |
| Commit | `8eaafff1f2845a696050e05e72ba1140ee190698` |
| Vendored on | 2026-08-11 |
| File count | 122 rules |
| License | Detection Rule License (DRL) 1.1 — see [LICENSE](LICENSE) |

The rules are unmodified. They are used here **only as test input** to prove that RedGap's
own parser + AST evaluator ingests the full real-world ruleset without a single parser
error or evaluator crash — see [`tests/test_sigmahq_corpus.py`](../../test_sigmahq_corpus.py).
RedGap ships and evaluates its own small rule set under `rules/`; this corpus is not
loaded at runtime.

## Refreshing the corpus

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma /tmp/sigma
git -C /tmp/sigma sparse-checkout set rules/linux/process_creation
cp /tmp/sigma/rules/linux/process_creation/*.yml tests/corpus/sigmahq_linux_process_creation/
```

Then update the commit hash and count above, and re-run `pytest tests/test_sigmahq_corpus.py`.
