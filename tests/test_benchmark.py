"""Regression gate for the committed SigmaHQ benchmark (docs/benchmarks/).

`redgap audit` over the full 122-rule vendored SigmaHQ Linux process_creation corpus is a
third-party, adversarial-to-self measurement; these counts are the headline the docs cite,
so they are pinned here. If the engine, the fixtures, or the vendored corpus change and move
a number, this fails loudly instead of letting the published benchmark rot.
"""

from __future__ import annotations

from pathlib import Path

from redgap.audit import run_audit
from redgap.target import ReplayTarget

CORPUS = Path(__file__).resolve().parents[1] / "tests" / "corpus" / "sigmahq_linux_process_creation"
WHEN = "2026-08-11T00:00:00+00:00"


def test_sigmahq_benchmark_counts_are_pinned():
    res = run_audit(ReplayTarget(), rules_dir=CORPUS, generated_at=WHEN)
    s = res.scorecard["summary"]
    c = res.coverage["summary"]
    # loaded + unevaluable = the whole vendored corpus
    assert s["loaded"] + s["excluded"] == 122
    assert s["loaded"] == 122 and s["excluded"] == 0
    # every loaded rule falls into exactly one health bucket
    assert s["firing"] + s["silent"] + s["out_of_corpus"] == s["loaded"]
    assert s["firing"] == 34
    assert s["silent"] == 50  # the headline: valid, tagged, yet never fire on real telemetry
    assert s["out_of_corpus"] == 38
    assert c["detected"] == 33 and c["techniques"] == 51
