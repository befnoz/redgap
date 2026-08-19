# Contributing to RedGap

Thanks for your interest. RedGap is a small, deliberately-scoped tool; contributions that
keep it focused, honest, and safe are welcome.

## Dev setup

```bash
pip install -e ".[dev]"
```

Then:

- `make test` (or `pytest`) - the full suite, fully offline
- `make lint` (or `ruff check . && ruff format --check .`)
- `pre-commit install` - run the hooks before each commit

## Scope (important)

RedGap attacks only its own disposable local lab. Do **not** submit weaponized code, real
exploits, off-box techniques, or anything aimed at systems you do not own - see
[SCOPE.md](SCOPE.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Every technique must stay
a benign, published, detection-test-grade procedure.

## Rules and techniques

- New detection rules go under `rules/` as standard Sigma and must fire on real captured
  telemetry - add the fixture that proves it.
- New techniques are data-driven: add a `TechDef` to
  `src/redgap/techniques/catalog_data.py`, capture real telemetry with `redgap capture`,
  and let the engine compute the verdict - never hand-author a fixture.

## Security

Report anything sensitive privately - see [SECURITY.md](SECURITY.md) - not via a public
issue or pull request.
