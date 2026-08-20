# Changelog

All notable changes to RedGap are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-08-20

### Fixed
- README images now use absolute `raw.githubusercontent.com` URLs so they render on the
  PyPI project page - PyPI does not resolve repository-relative image paths, so the demo
  GIFs, architecture diagram, and dashboard screenshots showed as broken images there.

## [1.0.1] - 2026-08-20

### Fixed
- `redgap audit` (Bring Your Own Rules): the written `coverage.md` no longer marks a
  user's uncovered techniques as "(regression)" or asserts RedGap's own base-rate/roadmap
  rationale - those are relative to RedGap's shipped catalog, not a foreign ruleset.
- Corrected two ATT&CK tactic mappings to match MITRE: T1497.001 (+Discovery) and
  T1098.004 (+Privilege Escalation).
- Light-theme WCAG AA contrast on the dashboard's inline red/green body text; the hero
  terminal reserves its height so it no longer grows during the type-in animation.
- The rule scorecard distinguishes a SILENT rule (telemetry present, never matched) from
  one that had no telemetry to fire against.
- Pinned the buildx builder to the local docker driver in the capture path.

### Added
- `[project.urls]` (Homepage / Repository / Documentation / Changelog / Issues) so the
  PyPI page links back to the project.
- `CONTRIBUTING.md`, issue / pull-request templates, and a `rules/` provenance README.

## [1.0.0] - 2026-08-19

First stable release.

### Added
- **Bring Your Own Rules** - `redgap audit --rules <DIR>` scores your own Sigma rules
  against RedGap's real-telemetry techniques and emits a per-rule health scorecard,
  bucketing every rule as firing / SILENT / out-of-corpus / unevaluable. The SILENT
  bucket surfaces a rule that is tagged to a technique yet never fires on real telemetry
  - false confidence that static rule validation cannot surface, because it never runs
  the rule against real events.
- `--fail-under N` gate for `redgap audit`, so coverage can guard a CI build.
- Interactive Detection Playground on the dashboard: click any technique for its real
  captured telemetry, the firing rule, the matched fields, or the gap reason.
- Drop your own `out/coverage.json` on the dashboard to render your gap grid entirely in
  the browser - nothing is uploaded.
- `--fix` now ships a closing rule for every rule-gap, taking a run from 34/51 to 46/51
  and leaving only the 5 base-rate gaps that honestly need correlation.
- Animated terminal demo (`docs/demo.gif`) generated deterministically from the run.

### Changed
- Grew the technique set to **51** benign ATT&CK techniques across 11 tactics, each with
  a committed real-telemetry capture (raw log + parsed events + sha256 provenance).
- Aligned the telemetry field vocabulary to the SigmaHQ standard (`ProcessId`); the
  parser drops the container-init PID so a rule cannot false-fire on it.
- Report `rule_path` is emitted relative to the working directory, never as an absolute
  build path.
- Corrected three ATT&CK tactic mappings to match MITRE (T1548, T1567, T1653).

### Fixed
- Scorecard firing/evidence join keyed on the rule's unique file path, so a duplicate
  Sigma `id` can no longer flip a SILENT rule to firing.
- Hardened the Sigma AST loader: catastrophic-regex and deeply-nested-YAML rules are
  excluded per file instead of aborting the run; the walk is case-insensitive and
  symlink-safe.
- setuid / setcap safety guard rewritten as a fail-closed allowlist that validates every
  privilege-granting spec, not just the flagship.

## [0.2.0] - 2026-08-13

### Added
- Grew from 5 to 38 techniques, each with a real Docker capture; vendored 23 SigmaHQ
  `linux/process_creation` rules.
- Dashboard rendering of an uploaded coverage report.

### Changed
- Data-driven catalog: `techniques/catalog_data.py` is the single source that builds the
  catalog and the technique registry.

## [0.1.0] - 2026-08-12

Initial public release.

### Added
- Deterministic offense / detection coverage harness: an own Sigma parser and AST
  evaluator, with the verdict a pure function of `(events, rules)` and no model in the
  loop - proven by a test asserting the coverage is byte-identical with and without the
  optional LLM planner.
- Five seed techniques including the setuid flagship and the timestomp remediation
  round-trip (write the missing rule, re-run, watch red flip green).
- REPLAY mode over committed telemetry fixtures and LIVE mode over a disposable,
  no-network Docker lab.
- ATT&CK Navigator layer, `coverage.json` / `coverage.md` reports, CI, PyPI packaging,
  and the GitHub Pages dashboard.

[1.0.0]: https://github.com/befnoz/redgap/releases/tag/v1.0.0
[0.2.0]: https://github.com/befnoz/redgap/releases/tag/v0.2.0
[0.1.0]: https://github.com/befnoz/redgap/releases/tag/v0.1.0
