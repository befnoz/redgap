"""The coverage pipeline: target -> engine -> report artifacts.

Stdlib + core only (no typer/rich/anthropic), so the whole offense->detection->coverage
loop runs offline with no API key. The CLI is a thin shell over this.
"""

from __future__ import annotations

import json
from pathlib import Path

from redgap._resources import rules_dir
from redgap.catalog import CATALOG
from redgap.detection.sigma_ast import load_rules_detailed
from redgap.engine_facade import CoverageEngine
from redgap.models import Verdict
from redgap.planner import make_planner
from redgap.report import markdown_report, navigator_layer
from redgap.target import Target

DEFAULT_RULES = rules_dir()


def run_coverage(
    target: Target,
    *,
    generated_at: str,
    rules_dir: str | Path = DEFAULT_RULES,
    out_dir: str | Path | None = None,
    fix: bool = False,
    use_llm: bool | None = None,
) -> tuple[list[Verdict], dict]:
    """Evaluate coverage for ``target`` and (optionally) write the report artifacts.

    A planner (deterministic by default, optionally LLM) sequences the techniques, but the
    report is always ``engine.coverage()`` — byte-identical whichever planner ran.
    ``fix=True`` also loads the ``rules/roundtrip`` closing rule, which flips the timestomp
    gap (T1070.006) from red to green — the remediation round-trip.
    """
    exclude = () if fix else ("roundtrip",)
    rules, excluded = load_rules_detailed(rules_dir, exclude=exclude)
    engine = CoverageEngine(target, rules, excluded, generated_at=generated_at)

    report = make_planner(engine, use_llm=use_llm).run()
    verdicts = engine.verdicts()
    if out_dir is not None:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "coverage.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        (out / "coverage.md").write_text(
            markdown_report(
                CATALOG, verdicts, mode=target.mode, run_id=target.run_id, generated_at=generated_at
            ),
            encoding="utf-8",
        )
        (out / "navigator-layer.json").write_text(
            json.dumps(navigator_layer(CATALOG, verdicts), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    return verdicts, report


def exit_code_for(verdicts: list[Verdict]) -> int:
    """0 = a coverage report (gaps are findings, not failures). 1 = a regression:
    a technique we expected to detect was not detected."""
    return 1 if any(v.unexpected for v in verdicts) else 0
