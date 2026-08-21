"""The ``redgap`` command - the only module that imports typer/rich.

Default run is REPLAY: re-evaluate the committed real-telemetry fixtures fully offline,
with no Docker and no API key. ``--live`` captures fresh telemetry from the Docker lab;
``--fix`` loads the closing rule that flips the timestomp gap red -> green.
"""

from __future__ import annotations

import json as _json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from redgap import __version__
from redgap.pipeline import exit_code_for, run_coverage
from redgap.target import ReplayTarget, TargetError

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="RedGap - automated MITRE ATT&CK offense<->detection coverage harness.",
)
console = Console()

_LIVE_BANNER = "LIVE - capturing real telemetry from the disposable lab"
_REPLAY_BANNER = "REPLAY - re-evaluating real captured telemetry; no live attack run"


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _render(verdicts, report: dict, mode: str, *, show_regression: bool = True) -> None:
    summary = report["summary"]
    table = Table(box=box.SIMPLE_HEAVY, title=f"RedGap coverage - {mode}", title_style="bold")
    table.add_column("ATT&CK", style="bold")
    table.add_column("Technique")
    table.add_column("Tactic", style="dim")
    table.add_column("Result", justify="left")
    table.add_column("Rule / gap")
    by_id = {t["id"]: t for t in report["techniques"]}
    for v in verdicts:
        t = by_id[v.technique_id]
        if v.detected:
            result = "[green]● detected[/green]"
            # escape(): a firing-rule id from a BYOR ruleset could contain Rich markup.
            rule = ", ".join(escape(r) for r in v.firing_rules)
        else:
            result = f"[red]● gap[/red] [dim]({v.gap_type.value})[/dim]"
            rule = "[dim]-[/dim]"
        if v.unexpected and show_regression:
            result += " [yellow](regression)[/yellow]"
        table.add_row(v.technique_id, t["name"], " / ".join(t["tactics"]), result, rule)
    console.print(table)
    gaps_str = ", ".join(f"{k}:{n}" for k, n in summary["gaps_by_type"].items()) or "none"
    gap_word = "gap" if summary["gaps"] == 1 else "gaps"
    console.print(
        f"[bold green]{summary['detected']}[/bold green]/{summary['techniques']} detected · "
        f"[bold red]{summary['gaps']}[/bold red] {gap_word}  [dim]({gaps_str})[/dim]"
    )


@app.command()
def run(
    live: Annotated[
        bool, typer.Option("--live", help="Capture fresh telemetry from the Docker lab.")
    ] = False,
    fix: Annotated[
        bool, typer.Option("--fix", help="Load the closing rule (flips the timestomp gap green).")
    ] = False,
    out: Annotated[
        Path, typer.Option(help="Write coverage.json/.md/navigator-layer.json here.")
    ] = Path("out"),
    json_out: Annotated[
        bool, typer.Option("--json", help="Print coverage JSON (for CI); no table.")
    ] = False,
    llm: Annotated[
        bool, typer.Option("--llm", help="Use the optional LLM planner (needs ANTHROPIC_API_KEY).")
    ] = False,
    adaptive: Annotated[
        bool,
        typer.Option(
            "--adaptive",
            help="Adaptive gap-driven chaining; also writes attack-path.json/.md (the ordered "
            "killchain). The coverage grid is byte-identical either way.",
        ),
    ] = False,
    max_steps: Annotated[
        int, typer.Option("--max-steps", min=1, help="Adaptive planner step cap (default 12).")
    ] = 12,
) -> None:
    """Run the coverage loop (REPLAY by default)."""
    if live:
        from redgap.target import LiveDockerTarget

        target = LiveDockerTarget()
    else:
        target = ReplayTarget()

    if not json_out:
        console.print(f"[dim]{_LIVE_BANNER if live else _REPLAY_BANNER}[/dim]")

    try:
        verdicts, report = run_coverage(
            target,
            generated_at=_now(),
            out_dir=out,
            fix=fix,
            use_llm=(True if llm else None),
            auto=adaptive,
            max_steps=max_steps,
        )
    except TargetError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc

    if json_out:
        typer.echo(_json.dumps(report, indent=2, ensure_ascii=False))
    else:
        _render(verdicts, report, target.mode)
        wrote = "coverage.json/.md + navigator-layer.json"
        if adaptive:
            wrote += " + attack-path.json/.md"
        console.print(f"[dim]wrote {wrote} → {out}/[/dim]")
        if adaptive:
            attack_md = out / "attack-path.md"
            if attack_md.is_file():
                console.print()
                console.print(attack_md.read_text(encoding="utf-8"))

    raise typer.Exit(exit_code_for(verdicts))


@app.command()
def audit(
    rules: Annotated[
        Path, typer.Option("--rules", help="Directory of YOUR own Sigma rules to score.")
    ],
    out: Annotated[
        Path, typer.Option(help="Write coverage.json/.md + rules-scorecard.json/.md here.")
    ] = Path("byor-out"),
    fail_under: Annotated[
        int | None,
        typer.Option("--fail-under", help="CI gate: exit 1 if fewer than N techniques detected."),
    ] = None,
    json_out: Annotated[
        bool, typer.Option("--json", help="Print summary + scorecard JSON; no table.")
    ] = False,
) -> None:
    """Bring Your Own Rules - score YOUR Sigma directory against RedGap's real telemetry.

    Every one of RedGap's benign techniques is evaluated against the rules under --rules,
    offline (REPLAY, no Docker, no key). You get your own ATT&CK coverage plus a rule-health
    scorecard: which of your rules fire on real exec telemetry, which are SILENT (tagged but
    never firing - false confidence), and which are outside RedGap's corpus.
    """
    from redgap.audit import run_audit

    if not rules.is_dir():
        raise typer.BadParameter(f"--rules must be a directory of Sigma rules: {rules}")

    target = ReplayTarget()
    try:
        result = run_audit(
            target, rules_dir=rules, generated_at=_now(), out_dir=out, fail_under=fail_under
        )
    except (TargetError, ValueError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc

    if json_out:
        typer.echo(
            _json.dumps(
                {"summary": result.coverage["summary"], "scorecard": result.scorecard["summary"]},
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        # A foreign ruleset legitimately doesn't cover every shipped-expected technique;
        # `unexpected` is catalog-relative, so its "(regression)" marker is meaningless here.
        _render(result.verdicts, result.coverage, target.mode, show_regression=False)
        s = result.scorecard["summary"]
        cov = result.coverage["summary"]
        console.print(f"[dim]loaded {s['loaded']} rules, {s['excluded']} unevaluable[/dim]")
        console.print(
            f"coverage: [bold]{cov['detected']}[/bold]/{cov['techniques']} techniques "
            f"detected by your rules"
        )
        console.print(
            f"rule health: [green]{s['firing']} firing[/green] · "
            f"[red]{s['silent']} SILENT[/red] · {s['out_of_corpus']} out-of-corpus · "
            f"{s['unevaluable']} unevaluable"
        )
        console.print(
            f"[dim]wrote coverage.json/.md + navigator-layer.json + "
            f"rules-scorecard.json/.md → {out}/[/dim]"
        )

    raise typer.Exit(result.exit_code)


@app.command()
def capture(
    at: Annotated[str, typer.Option(help="captured_at timestamp to stamp into provenance.")] = "",
    git_commit: Annotated[
        str, typer.Option(help="git commit to stamp into provenance.")
    ] = "unknown",
) -> None:
    """Regenerate the committed real-telemetry fixtures from a live lab run (needs Docker)."""
    from redgap import lab

    console.print("[dim]building the lab image, capturing real telemetry (needs Docker)[/dim]")
    try:
        counts = lab.capture_all(at or _now(), git_commit=git_commit)
    except lab.LabError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc
    for tid, n in counts.items():
        console.print(f"  {tid}: [bold]{n}[/bold] events")
    console.print("[green]fixtures regenerated.[/green]")


@app.command()
def suggest(
    limit: Annotated[
        int, typer.Option("--limit", min=1, help="Max rule-gaps to draft rules for.")
    ] = 3,
) -> None:
    """For each rule-gap, an optional LLM drafts a candidate Sigma rule - then the ENGINE, not
    the model, re-runs it and says whether it actually closes the gap.

    The most literal demonstration of the trust boundary: the model writes rule text; only the
    deterministic engine grants green. Needs the ``llm`` extra and ``ANTHROPIC_API_KEY``.
    """
    if not os.getenv("ANTHROPIC_API_KEY"):
        console.print(
            "[yellow]redgap suggest needs ANTHROPIC_API_KEY[/yellow] - the LLM drafts a rule, "
            "the engine judges it. Install [bold]redgap[llm][/bold] and set the key."
        )
        raise typer.Exit(2)

    from redgap.catalog import BY_ID
    from redgap.models import GapType
    from redgap.suggest import suggest_for_gaps

    target = ReplayTarget()
    try:
        verdicts, _ = run_coverage(target, generated_at=_now())
    except TargetError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc

    gaps = [
        (v.technique_id, BY_ID[v.technique_id].name)
        for v in verdicts
        if not v.detected and v.gap_type is GapType.RULE
    ][:limit]
    if not gaps:
        console.print(
            "[green]no rule-gaps to draft for[/green] - every gap is base-rate or closed."
        )
        raise typer.Exit(0)

    label = {
        "closes": "[green]CLOSES the gap[/green]",
        "over_broad": "[yellow]OVER-BROAD (also fires elsewhere)[/yellow]",
        "untagged": "[yellow]fires, but the draft omitted the ATT&CK tag[/yellow]",
        "no_fire": "[red]did NOT fire on the real telemetry[/red]",
        "unevaluable": "[red]unevaluable[/red]",
    }
    for r in suggest_for_gaps(target, gaps):
        v = r["verdict"]
        console.print(f"\n[bold]{r['technique_id']}[/bold] {escape(r['name'])}")
        console.print("[dim]--- LLM-drafted candidate (unverified) ---[/dim]")
        console.print(escape(r["candidate_yaml"]))
        verdict_line = label.get(v["status"], v["status"])
        if v["status"] == "over_broad" and v.get("also_fires"):
            verdict_line += f" [dim]{', '.join(v['also_fires'])}[/dim]"
        console.print(f"[bold]engine verdict:[/bold] {verdict_line}")
    console.print(
        "\n[dim]The model wrote the rule text; the engine decided whether it fires. "
        "A draft is never trusted until the engine re-runs it on real telemetry.[/dim]"
    )
    raise typer.Exit(0)


@app.command()
def verify() -> None:
    """Prove RedGap's honesty in one offline command (no key, no Docker, no network).

    Re-checks that every committed fixture matches its sha256 provenance, that coverage is
    deterministic across runs, and that the batch and adaptive planners produce byte-identical
    coverage - so the orchestration layer can never move a verdict. Exit 0 if all hold, else 1.
    """
    from redgap.verify import run_verification

    try:
        r = run_verification(generated_at=_now())
    except TargetError as exc:
        console.print(f"[red]✗ fixture authenticity FAILED:[/red] {exc}")
        raise typer.Exit(1) from exc

    def mark(ok: bool) -> str:
        return "[green]✓[/green]" if ok else "[red]✗[/red]"

    console.print(
        f"{mark(r.fixtures_checked > 0)} {r.fixtures_checked} fixtures authentic "
        f"(sha256 matches provenance)"
    )
    console.print(f"{mark(r.deterministic)} coverage deterministic (byte-identical across runs)")
    console.print(
        f"{mark(r.planner_independent)} verdict identical batch vs adaptive planner "
        f"(orchestration never sets a verdict)"
    )
    if r.ok:
        console.print(
            f"[bold green]OK[/bold green] - {r.detected}/{r.techniques} detected, "
            f"engine-computed and reproducible."
        )
    else:
        console.print("[bold red]FAILED[/bold red] - an invariant did not hold.")
    raise typer.Exit(0 if r.ok else 1)


@app.command()
def version() -> None:
    """Print the RedGap version."""
    typer.echo(f"redgap {__version__}")


if __name__ == "__main__":
    app()
