# Scope

## In scope (v1.0)

- Executing a **fixed, curated set of benign, MITRE ATT&CK-mapped techniques** against a disposable local Linux lab that RedGap starts and tears down itself.
- Collecting **process-execution telemetry** with an independent collector and normalizing it to a Sigma-compatible event schema.
- **Deterministically** evaluating Sigma rules against that telemetry (pySigma as parser, RedGap's own AST evaluator) to produce a per-technique verdict: `executed`, `telemetry_present`, `detected`, `gap_type`.
- A **coverage report** (`coverage.json`, `coverage.md`) and an **ATT&CK Navigator layer** (green = detected, red = gap).
- A **REPLAY** mode that re-evaluates committed real-telemetry fixtures fully offline, and a **LIVE** mode that runs the lab.
- An **optional** LLM planner (orchestration and narration only), disabled by default.
- A **Bring Your Own Rules** mode (`redgap audit --rules <DIR>`) that scores a user's own Sigma rules against the same real telemetry, producing their coverage grid plus a per-rule health scorecard (firing / SILENT / out-of-corpus / unevaluable).

## Out of scope (v1.0) - deliberately, and stated honestly

- **Adaptive multi-step orchestration / attack chaining.** The planner runs each technique and stops; it does not choose the next attack from the last result. This is the primary roadmap item.
- **Effect / syscall-level detection** (e.g. observing the `utimensat` call behind a timestomp). v1.0 detects at the process-invocation layer. Higher-fidelity collection (auditd, Sysmon for Linux) is an opt-in / roadmap path.
- **Correlation / aggregation rules** (`count() by`, temporal, `near`). The base-rate gaps (such as T1057, T1033, T1005) stay gaps for exactly this reason.
- **Any target that is not RedGap's own lab.** No arbitrary hosts, no cloud accounts, no external services.
- Non-Linux targets, Kubernetes / multi-container labs, streaming / "continuous" scheduling, and a web dashboard.

## The Sigma subset RedGap evaluates

RedGap supports a documented subset of the Sigma specification:

- **Field modifiers:** default (case-insensitive equals), `contains`, `startswith`, `endswith`, `re` (regex, with the `i`/`m`/`s` flags), `all` (list AND), `cased` (case-sensitive), and numeric `lt`/`lte`/`gt`/`gte`.
- **Value wildcards:** `*` (zero-or-more), `?` (single char).
- **Keyword / value-only** search: a bare value list is matched as a **substring** across the event's fields (Sigma keyword semantics), not whole-value equality.
- **Value typing:** booleans and numbers are matched as **case-insensitive strings** (Sigma matches all values as strings), so `Suspicious: false` matches the string `"false"` and `Pid: 1000` does not over-match `" 1000 "` or `"1e3"`. The numeric compare modifiers (`lt`/`lte`/`gt`/`gte`) likewise only compare when the field value is a **canonical** number, so `1_0`, `" 10 "`, `inf`/`nan`, or `0x10` are not treated as numbers (plain scientific notation like `1e2` **is** accepted).
- **Conditions:** `and` / `or` / `not`, parentheses, `1 of ...`, `all of ...`, `1 of them`, `all of them`, and wildcard selection names (`1 of selection_*`).
- **Explicitly not supported:** `base64`/`base64offset`, `windash`, `utf16`/wide encodings, `cidr`, `fieldref`, `exists`, and aggregation/correlation. A rule using any of these is **excluded from the run at load time with a warning** - never silently treated as a non-match (which would fabricate a gap) and never left to crash the run mid-evaluation. Numeric `N of them` (N ≥ 2) is not valid Sigma and is rejected as a condition error.
- **Robustness bounds:** field values longer than 64 K characters are treated as a non-match rather than fed to the regex engine (an input-length bound, not a matching-time bound). Known caveat: that non-match is a safe under-match for a positive selection, but under an odd number of enclosing `not`s (a `... and not filter` idiom with a >64 K field) it can flip to an over-match; the process-creation fields RedGap handles are far under 64 K. Separately, a `|re` pattern with the classic nested-unbounded-quantifier ReDoS shape (e.g. `(a+)+`) is **rejected at load** so no single rule can hang the run. This is a targeted static guard, not a general ReDoS proof; for untrusted adversarial rulesets, evaluating `|re` under a linear-time engine (RE2) is a roadmap item.

Stating the boundary is part of the design: silently ignoring an unsupported feature would produce a false gap and undermine trust in the report. The detection verdict is a pure function of the events, the rules, and this fixed, checked-in evaluation policy - no language model, no wall clock, no randomness.
