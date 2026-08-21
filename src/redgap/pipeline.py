"""The coverage pipeline: target -> engine -> report artifacts.

Stdlib + core only (no typer/rich/anthropic), so the whole offense->detection->coverage
loop runs offline with no API key. The CLI is a thin shell over this.
"""

from __future__ import annotations

import json
from pathlib import Path

from redgap._resources import rules_dir as _rules_dir
from redgap.agent_state import render_attack_path
from redgap.catalog import CATALOG
from redgap.detection.sigma_ast import load_rules_detailed
from redgap.engine_facade import CoverageEngine
from redgap.models import Verdict
from redgap.planner import make_planner
from redgap.report import markdown_report, navigator_layer
from redgap.target import Target

# Aliased on import so the run_coverage `rules_dir` parameter below does not shadow the
# resource helper (a later call to the helper inside the function would otherwise hit the
# str|Path argument instead).
DEFAULT_RULES = _rules_dir()


def run_coverage(
    target: Target,
    *,
    generated_at: str,
    rules_dir: str | Path = DEFAULT_RULES,
    out_dir: str | Path | None = None,
    fix: bool = False,
    use_llm: bool | None = None,
    exclude: tuple[str, ...] | None = None,
    loaded: tuple[list, list] | None = None,
    audit_mode: bool = False,
    auto: bool = False,
    max_steps: int = 12,
) -> tuple[list[Verdict], dict]:
    """Evaluate coverage for ``target`` and (optionally) write the report artifacts.

    A planner (deterministic by default, optionally LLM) sequences the techniques, but the
    report is always ``engine.coverage()`` - byte-identical whichever planner ran.
    ``fix=True`` also loads the ``rules/roundtrip`` closing rule, which flips the timestomp
    gap (T1070.006) from red to green - the remediation round-trip.

    ``exclude`` overrides which path components are skipped when loading rules. It defaults
    to skipping ``roundtrip`` (unless ``fix``); ``redgap audit`` passes ``()`` so a user's
    own rule directory is loaded whole and its coverage grid cannot diverge from its
    rule scorecard. ``loaded`` lets a caller pass a pre-computed ``(rules, excluded)`` split
    so the same directory is not walked and parsed twice (``redgap audit`` uses this so the
    coverage grid and the scorecard are built from the identical objects).
    """
    if exclude is None:
        exclude = () if fix else ("roundtrip",)
    if loaded is None:
        rules, excluded = load_rules_detailed(rules_dir, exclude=exclude)
    else:
        rules, excluded = loaded
    engine = CoverageEngine(target, rules, excluded, generated_at=generated_at)

    # The planner sequences techniques; whichever one runs, ``report`` is engine.coverage()
    # (byte-identical). When ``auto`` the adaptive planner ALSO records the ordered chain it
    # walked in ``planner.attack_path`` - a narrative lens, never a competing verdict source.
    planner = make_planner(engine, use_llm=use_llm, auto=auto, max_steps=max_steps)
    report = planner.run()
    verdicts = engine.verdicts()
    if out_dir is not None:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        # newline="\n": emit LF on every OS so the committed artifacts are byte-identical
        # across Windows/Linux (no CRLF translation).
        (out / "coverage.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
        )
        (out / "coverage.md").write_text(
            markdown_report(
                CATALOG,
                verdicts,
                mode=target.mode,
                run_id=target.run_id,
                generated_at=generated_at,
                show_regression=not audit_mode,
            ),
            encoding="utf-8",
            newline="\n",
        )
        (out / "navigator-layer.json").write_text(
            json.dumps(navigator_layer(CATALOG, verdicts), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        attack_path = getattr(planner, "attack_path", None)
        if attack_path is not None:
            (out / "attack-path.json").write_text(
                json.dumps(attack_path, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            (out / "attack-path.md").write_text(
                render_attack_path(attack_path), encoding="utf-8", newline="\n"
            )
    return verdicts, report


def exit_code_for(verdicts: list[Verdict]) -> int:
    """0 = a coverage report (gaps are findings, not failures). 1 = a regression:
    a technique we expected to detect was not detected."""
    return 1 if any(v.unexpected for v in verdicts) else 0
