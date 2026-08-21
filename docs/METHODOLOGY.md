# RedGap methodology

A short, formal statement of what RedGap measures and how, so the numbers are reproducible
and falsifiable rather than asserted. Definitions are quoted from the code they live in.

## 1. The measured property

For a technique `t` with captured event set `E(t)` and a rule set `R`:

```
detected(t)  :=  ∃ r ∈ R, ∃ e ∈ E(t)  such that  eval(r, e) = true
```

i.e. the coverage verdict is a **pure function** `verdict = f(events, rules)`. It is computed
by the deterministic engine and written to disk *before* any language model is invoked. The
optional LLM planner may order the techniques and decide when to stop; it cannot evaluate
`eval`. This is enforced structurally (see [THREAT-MODEL.md](THREAT-MODEL.md)), not by
convention.

**Determinism claim.** For fixed `(events, rules)`, `f` is deterministic and independent of
the planner. Proven at runtime by `redgap verify` and in CI by the byte-identical tests
([`test_planner.py`](../tests/test_planner.py),
[`test_adaptive_planner.py`](../tests/test_adaptive_planner.py)) and a cross-process
hash-seed test.

## 2. Evaluation protocol

- **REPLAY (default).** Re-evaluate committed real-telemetry fixtures. Offline, no Docker, no
  key - this is what CI runs and what a reviewer reproduces in one command.
- **LIVE (`--live`).** Bring up a disposable Docker lab, execute the benign techniques,
  capture fresh telemetry with the same collector and parser, then run the same engine. A
  nightly job re-captures on a clean runner so the committed fixtures are auditable, not
  hand-authored.
- **One capture per technique.** Each fixture is a verbatim capture with a `provenance.json`
  sidecar (sha256 of the raw log, kernel, image id, exact commands, timestamp). Integrity is
  mandatory and fail-closed: a missing/blank hash or a mismatch is refused, never trusted.
- **Field handling.** RedGap-internal bookkeeping (run id, technique id, timestamp, the raw
  line) is kept under underscore-prefixed keys that are invisible to Sigma rules. Sigma-visible
  fields use the SigmaHQ `process_creation` names (`Image`, `CommandLine`, `ProcessId`, ...) and
  are **retained** verbatim - `ProcessId` deliberately so, so real SigmaHQ rules match. The one
  thing dropped is the container's PID-1 init event, so a rule cannot fire on scaffolding. The
  raw log is never mutated; its hash still validates. (Because `ProcessId` is retained and PIDs
  vary between captures, the content-addressed event id is stable within a capture but a fresh
  LIVE re-capture legitimately re-derives it.)

## 3. The detection engine

RedGap ships its own pySigma parser plus a hand-written AST evaluator (not a SIEM backend),
so the offense->detection->coverage loop has no heavyweight runtime dependency. It implements
a documented subset of Sigma; rules using features outside that subset are **excluded with a
warning at load** rather than silently mismatched (see [SCOPE.md](../SCOPE.md)). The subset is
validated against the full public SigmaHQ Linux `process_creation` ruleset - all 122 rules
parse with zero crashes; see the committed [benchmark](benchmarks/README.md).

## 4. Gap taxonomy

A non-detection is classified deterministically from what was observed, never editorialized:

| Gap type | Meaning | Closeable? |
|----------|---------|------------|
| `rule` | Telemetry was captured, but no rule is tagged to the technique - a missing rule. | Yes - write one Sigma rule; `redgap run --fix` demonstrates the round-trip (34/51 -> 46/51). |
| `base_rate` | The signal is real but too common for a single-event rule; it needs correlation. | Not with a standalone rule - correlation is roadmap. |
| `visibility` | **Reserved / roadmap.** The collector saw no telemetry for the technique (an effect below its field of view). | Needs a higher-fidelity collector. |

`visibility` is a declared, reserved class: the current process-creation corpus does not
exercise it, so it never appears as an accidental gap; it exists so effect/syscall-level
detection has a home when a richer collector lands.

## 5. Datasheet - the technique corpus

- **Population.** 51 benign, MITRE ATT&CK-mapped techniques across 11 of the 14 enterprise
  tactics. Each is a real command run in the lab, with cleanup, and a captured telemetry
  fixture.
- **Collection instrument.** An independent ~40-line `LD_PRELOAD` execve collector emits one
  record per process creation, mapped to the SigmaHQ Linux `process_creation` field vocab
  (`Image`, `CommandLine`, `ParentImage`, `User`, ...). This is the instrument's **field of
  view**: process execution, not file writes or raw syscalls.
- **Known biases / out of scope.** (a) Windows-only rules cannot fire on Linux telemetry -
  correctly reported out-of-corpus, not as failures. (b) Techniques whose signal is a file or
  syscall effect rather than a distinct process are visibility-limited by design. (c) The demo
  rule set has one rule per technique (detection depth 1) - honest, and exactly the single
  point of failure `redgap audit` surfaces on real rulesets.
- **Provenance.** Every fixture is regenerable via `redgap capture` and carries sha256 +
  environment provenance; nothing is authored.

## 6. Reproduce

```bash
pip install redgap
redgap run           # REPLAY coverage over the committed fixtures
redgap verify        # re-prove authenticity + determinism + planner-independence, offline
redgap audit --rules tests/corpus/sigmahq_linux_process_creation --out docs/benchmarks
```

The committed samples under [docs/samples/](samples) and the third-party
[benchmark](benchmarks/README.md) are the exact outputs of the above.
