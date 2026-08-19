# RedGap detection rules

These are the Sigma rules RedGap loads and evaluates at runtime.

- `rules/redgap/` and `rules/roundtrip/` - first-party rules authored for RedGap (MIT,
  same license as the project). Each carries its own `id`, `author: RedGap`, and `date`.
- `rules/sigmahq/` - real SigmaHQ community rules for `linux/process_creation`, vendored
  **verbatim** under the Detection Rule License (DRL-1.1). Each file retains its upstream
  `id`, `author`, and `modified`/`date` fields, which are the per-rule provenance. RedGap
  claims no ownership of them; see [NOTICE](../NOTICE).

The complete upstream `linux/process_creation` ruleset is also vendored for engine testing
under [`tests/corpus/`](../tests/corpus/sigmahq_linux_process_creation/), pinned to a fixed
SigmaHQ commit (recorded in that directory's README). The runtime rules under
`rules/sigmahq/` are a subset copied verbatim from that same upstream ruleset; to refresh
them, re-copy the desired files from that pinned revision and keep their headers intact so
the "verbatim" claim stays auditable against a single reference commit.
