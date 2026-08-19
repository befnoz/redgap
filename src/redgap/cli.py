"""The ``redgap`` command - the only module that imports typer/rich.

Default run is REPLAY: re-evaluate the committed real-telemetry fixtures fully offline,
with no Docker and no API key. ``--live`` captures fresh telemetry from the Docker lab;
``--fix`` loads the closing rule that flips the timestomp gap red -> green.
"""

from __future__ import annotations

import json as _json
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
            target, generated_at=_now(), out_dir=out, fix=fix, use_llm=(True if llm else None)
        )
    except TargetError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc

    if json_out:
        typer.echo(_json.dumps(report, indent=2, ensure_ascii=False))
    else:
        _render(verdicts, report, target.mode)
        console.print(f"[dim]wrote coverage.json/.md + navigator-layer.json → {out}/[/dim]")

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
def version() -> None:
    """Print the RedGap version."""
    typer.echo(f"redgap {__version__}")


if __name__ == "__main__":
    app()
