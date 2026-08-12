# RedGap

**Find the red gaps in your detection coverage.**

RedGap is an automated, MITRE ATT&CK-mapped **offense↔detection coverage harness**. It runs a small set of *benign* ATT&CK techniques against its own disposable local lab, collects real telemetry with an **independent collector**, and then **deterministically** — from logs and Sigma rules, with no AI in the loop — decides whether each technique was *detected* or is a *gap*. The output is a coverage report (`technique → detected? → gap type`) plus an ATT&CK Navigator layer.

The name is the output: in the coverage grid, detected techniques are green and gaps are **red**. RedGap finds the red.

[![CI](https://github.com/befnoz/redgap/actions/workflows/ci.yml/badge.svg)](https://github.com/befnoz/redgap/actions/workflows/ci.yml)
<!-- Uncomment once Pages is enabled / the package is on PyPI: -->
<!-- [![Live demo](https://img.shields.io/badge/demo-live-2e7d32)](https://befnoz.github.io/redgap/) -->
<!-- [![PyPI](https://img.shields.io/pypi/v/redgap)](https://pypi.org/project/redgap/) -->

> **v0.1 — what this is and is not.** RedGap v0.1 is a deterministic harness over a *fixed* set of techniques. It is **not** an autonomous agent that continuously attacks and adapts. Adaptive, gap-driven technique chaining (the agent choosing its next attack from the last result) is the honest **next step**, tracked on the roadmap. Precise scope on purpose.

**Status.** RedGap's own parser + evaluator ingests **all 122 real SigmaHQ `linux/process_creation` rules** with zero parser errors and zero evaluator crashes — that ruleset is vendored under [`tests/corpus/`](tests/corpus/sigmahq_linux_process_creation/) and checked by [`test_sigmahq_corpus.py`](tests/test_sigmahq_corpus.py), so the claim is reproducible, not asserted. **290 tests** run fully offline in CI. Coverage is computed from **5 committed real-telemetry captures** — one per technique, each with a raw log + parsed events + sha256 provenance — not authored logs. See [docs/architecture.md](docs/architecture.md) · committed output in [docs/samples/](docs/samples/).

---

## The one idea: the verdict is not the AI's to make

Every `detected` verdict is a **pure function of `(logs, rules)`**, computed and written to disk **before** any language model is ever called. An optional LLM planner may (a) choose the order of techniques and decide when to stop, and (b) narrate the report. It **cannot** decide whether something was detected — both the deterministic and the LLM planner return the engine's coverage, never model text. A test asserts the coverage report is byte-identical with and without the LLM.

This is deliberate. LLMs hallucinate confident verdicts; a coverage tool whose ground truth an LLM can fabricate is worthless. RedGap draws the trust boundary in code.

![RedGap architecture — the deterministic pipeline, with the optional LLM planner drawn outside the verdict path](docs/architecture.svg)

The verdict is a pure function of logs and rules, written to disk **before** any model runs. The LLM (dashed red) can only order techniques and narrate — it sits **outside** the verdict path.

---

## Quickstart (offline, no API key, no cloud)

The default path is `REPLAY`: it re-evaluates **real telemetry captured from a prior live run** (committed as fixtures with provenance) through the exact same engine used in LIVE mode. No Docker, no key, no network.

```bash
pip install redgap
redgap run            # REPLAY: prints the coverage table + writes out/coverage.{json,md} + navigator-layer.json
```

From source instead (or before the first PyPI release):

```bash
git clone https://github.com/befnoz/redgap && cd redgap
pip install -e .
redgap run
```

**Live dashboard:** the same coverage, as an interactive web page — `https://befnoz.github.io/redgap/` (see [docs/DEPLOY.md](docs/DEPLOY.md) to switch it on).

To run the real thing against the local Docker lab:

```bash
redgap run --live     # brings up the disposable lab, executes techniques, captures fresh telemetry
```

To try the optional LLM planner (needs the `llm` extra and `ANTHROPIC_API_KEY`):

```bash
pip install -e ".[llm]"    # adds the optional anthropic SDK
redgap run --llm           # equivalently: COVERAGE_LLM=1 redgap run
```

The committed `coverage.json` is identical whichever planner ran — a test asserts it.

---

## What a run shows

A v0.1 run is a five-technique mini kill-chain that deliberately produces **both** detections and gaps — and two *different kinds* of gap, because a coverage tool that is all-green is just a checklist:

| # | ATT&CK | Tactic | Result |
|---|--------|--------|--------|
| 1 | T1087.001 Account Discovery: Local | Discovery | detected |
| 2 | T1057 Process Discovery | Discovery | **gap (base-rate)** — too noisy for a single-event rule; needs correlation (roadmap) |
| 3 | T1136.001 Create Account: Local | Persistence | detected |
| 4 | T1548.001 Setuid/Setgid | Priv. Esc / Defense Evasion | detected (matches a shipped SigmaHQ rule) |
| 5 | T1070.006 Timestomp | Defense Evasion | **gap (rule)** → closed live in the remediation round-trip |

**The remediation round-trip** is the point: technique 5 fires but no rule catches it (a *rule gap*). Write one Sigma rule, re-run the same command, and watch the verdict flip red→green. Both the before and after coverage reports are committed — RedGap is a tool that finds a real blind spot and closes it, not a status printer.

---

## Ethics & scope

⚠️ **RedGap attacks only its own disposable local lab.** There is deliberately no free-form target flag; the live lab runs with **no network**, and every container launch is gated at runtime by an allowlist (`assert_lab_only`) that the test suite proves cannot be widened. Every technique is a benign, published Atomic-Red-Team-derived detection test with no exploit payload, no off-box action, and no runtime downloads. See [ETHICS.md](ETHICS.md), [SCOPE.md](SCOPE.md), and [SECURITY.md](SECURITY.md).

Not shipped: weaponizable breadth, real exploits, credential material, or anything that runs against a system you do not own.

---

## Roadmap (honest next steps)

- Adaptive, gap-driven technique chaining (agent picks the next attack from the last verdict).
- Effect / syscall-level detection (e.g. `utimensat` for timestomp) via a higher-fidelity collector.
- Correlation rules (turn the base-rate gap into a real detection).
- Portability: the rules are standard Sigma, so they already run unchanged in Zircolite or any SIEM.

---

## License

MIT — see [LICENSE](LICENSE). Third-party attributions in [NOTICE](NOTICE). ATT&CK® is a registered trademark of The MITRE Corporation.
