# Architecture

![RedGap architecture](architecture.svg)

RedGap runs a small set of benign, MITRE ATT&CK-mapped techniques against a disposable
lab, collects real process-execution telemetry with an **independent** collector, and
decides - deterministically, from logs and Sigma rules - whether each technique was
*detected* or is a *gap*.

## The trust boundary

The single load-bearing property is that the `detected` verdict is a **pure function of
`(events, rules)`**, computed and written to disk **before** any language model is
called. The optional LLM planner may choose the order of techniques and narrate the
report; it drives the same validated tool executor the deterministic planner uses and
**cannot** produce or change a verdict. `tests/test_planner.py` asserts the coverage is
byte-identical with and without the LLM - even when the model finishes early, runs a
subset, or requests a technique that does not exist.

## The pieces

| Component | File | Role |
|-----------|------|------|
| Technique catalog | `src/redgap/catalog.py`, `techniques/catalog_data.py` | 51 benign techniques + their commands and cleanup |
| Lab | `lab/`, `src/redgap/lab.py` | Disposable Docker container + a ~40-line `LD_PRELOAD` execve collector |
| Target | `src/redgap/target.py` | `ReplayTarget` (committed real fixtures, offline) / `LiveDockerTarget` |
| Telemetry | `src/redgap/telemetry/` | snoopy-format parser → SigmaHQ `process_creation` events |
| Detection | `src/redgap/detection/` | pySigma parser + RedGap's own AST evaluator; coverage join |
| Planner | `src/redgap/planner.py` | Batch{heuristic default / LLM} × adaptive{heuristic / LLM}, one `ToolExecutor` |
| Agent state | `src/redgap/agent_state.py` | Pure verdict-cache projection + the `attack-path` artifact (stdlib + catalog only) |
| Report | `src/redgap/report/` | `coverage.json`, `coverage.md`, ATT&CK Navigator layer, `attack-path.json` |

## Planners: batch and adaptive, deterministic and LLM

The planner layer is a 2×2. The **batch** planners run the whole catalog; the **adaptive**
planners (`--adaptive`) chase coverage - open an untested tactic first (breadth), then pile
onto a tactic already showing a gap (depth). Each row has a deterministic default and an
opt-in LLM variant (`--llm`):

|            | deterministic (default)     | LLM (`--llm`)         |
|------------|-----------------------------|-----------------------|
| batch      | `HeuristicPlanner`          | `LLMPlanner`          |
| adaptive   | `AdaptiveHeuristicPlanner`  | `AdaptivePlanner`     |

All four drive the **same** `ToolExecutor` and return `engine.coverage()`. The adaptive
LLM path is one *stateless, forced* call per step to a single `select_next_technique` tool
whose schema has **no verdict field** - the model can order and stop, nothing else. Every
technique's verdict is computed and cached **before** the next model call. `attack-path.json`
copies each `detected` from that cache; the planner authors only the order and the reason,
so `tests/test_adaptive_pipeline.py` can assert the path never contradicts the grid, and the
grid itself stays byte-identical to a plain run.

## Two modes, one engine

- **REPLAY** (default): re-evaluate committed real-telemetry fixtures. Offline, no key,
  no Docker - what CI runs and what a reviewer reproduces in one command.
- **LIVE** (`--live`): bring up the Docker lab, execute the techniques, capture fresh
  telemetry, and run the **same** engine.

Fixtures are verbatim captures with `provenance.json` (sha256, kernel, image id, exact
commands, timestamp) and are regenerable via `redgap capture`; the nightly LIVE CI job
re-captures on a clean runner so the fixtures are auditable, not hand-authored.
