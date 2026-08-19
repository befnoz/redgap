"""Bring Your Own Rules: score a user's own Sigma directory against RedGap's real
telemetry, offline.

``run_audit`` runs the normal coverage pipeline against a REPLAY target but loads the
user's rule directory WHOLE (``exclude=()``), then reduces the same verdicts into a rule
scorecard. It writes the standard coverage artifacts (so the user's posture drops straight
into ATT&CK Navigator) plus the new ``rules-scorecard.{json,md}``.

Deterministic and dependency-light: imports only the pipeline, the rule loader, the
catalog, and the pure scorecard renderer - no typer/rich/anthropic. Every number is
engine-computed; no language model touches a classification.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from redgap.catalog import CATALOG
from redgap.detection.sigma_ast import load_rules_detailed
from redgap.models import Verdict
from redgap.pipeline import run_coverage
from redgap.report.scorecard import rule_scorecard, rule_scorecard_markdown
from redgap.target import Target


@dataclass(frozen=True)
class AuditResult:
    """The full result of a BYOR audit: the per-technique coverage of the user's rules,
    the per-rule health scorecard, and the CI exit code."""

    verdicts: list[Verdict]
    coverage: dict
    scorecard: dict
    exit_code: int


def run_audit(
    target: Target,
    *,
    rules_dir: str | Path,
    generated_at: str,
    out_dir: str | Path | None = None,
    fail_under: int | None = None,
) -> AuditResult:
    """Score the Sigma rules under ``rules_dir`` against ``target``'s real telemetry.

    ``fail_under`` is the ONLY exit gate: exit 1 iff fewer than ``fail_under`` of the
    catalog techniques are detected by the user's rules; ``None`` never fails. This
    deliberately does NOT reuse :func:`pipeline.exit_code_for`, whose ``unexpected`` flag is
    defined against RedGap's SHIPPED catalog expectations and would misfire on a foreign
    ruleset that legitimately doesn't cover a shipped-expected technique.
    """
    if not Path(rules_dir).is_dir():
        raise ValueError(f"rules_dir is not a directory: {rules_dir}")

    # Load the user's directory ONCE (exclude=() so it is loaded whole) and pass the same
    # (loaded, excluded) split into both the coverage grid and the scorecard, so they are
    # provably built from identical objects and cannot diverge - no second walk/parse.
    loaded, excluded = load_rules_detailed(rules_dir, exclude=())
    verdicts, coverage = run_coverage(
        target,
        generated_at=generated_at,
        rules_dir=rules_dir,
        out_dir=out_dir,
        use_llm=None,
        exclude=(),
        loaded=(loaded, excluded),
        audit_mode=True,
    )
    scorecard = rule_scorecard(
        loaded,
        excluded,
        verdicts,
        CATALOG,
        mode=target.mode,
        run_id=target.run_id,
        generated_at=generated_at,
        rules_dir=str(rules_dir),
    )

    if out_dir is not None:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        # newline="\n": LF on every OS so the artifacts are byte-reproducible cross-platform.
        (out / "rules-scorecard.json").write_text(
            json.dumps(scorecard, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        (out / "rules-scorecard.md").write_text(
            rule_scorecard_markdown(scorecard), encoding="utf-8", newline="\n"
        )

    detected = coverage["summary"]["detected"]
    exit_code = 0 if fail_under is None else (0 if detected >= fail_under else 1)
    return AuditResult(
        verdicts=verdicts, coverage=coverage, scorecard=scorecard, exit_code=exit_code
    )
