"""The ``redgap`` command — the only module that imports typer/rich.

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
from rich.table import Table

from redgap import __version__
from redgap.pipeline import exit_code_for, run_coverage
from redgap.target import ReplayTarget

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="RedGap — automated MITRE ATT&CK offense<->detection coverage harness.",
)
console = Console()

_LIVE_BANNER = "LIVE — capturing real telemetry from the disposable lab"
_REPLAY_BANNER = "REPLAY — re-evaluating real captured telemetry; no live attack run"


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _render(verdicts, report: dict, mode: str) -> None:
    summary = report["summary"]
    table = Table(box=box.SIMPLE_HEAVY, title=f"RedGap coverage — {mode}", title_style="bold")
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
            rule = ", ".join(v.firing_rules)
        else:
            result = f"[red]● gap[/red] [dim]({v.gap_type.value})[/dim]"
            rule = "[dim]—[/dim]"
        if v.unexpected:
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

    verdicts, report = run_coverage(
        target, generated_at=_now(), out_dir=out, fix=fix, use_llm=(True if llm else None)
    )

    if json_out:
        typer.echo(_json.dumps(report, indent=2, ensure_ascii=False))
    else:
        _render(verdicts, report, target.mode)
        console.print(f"[dim]wrote coverage.json/.md + navigator-layer.json → {out}/[/dim]")

    raise typer.Exit(exit_code_for(verdicts))


@app.command()
def capture(
    at: Annotated[str, typer.Option(help="captured_at timestamp to stamp into provenance.")] = "",
    git_commit: Annotated[
        str, typer.Option(help="git commit to stamp into provenance.")
    ] = "unknown",
) -> None:
    """Regenerate the committed real-telemetry fixtures from a live lab run (needs Docker)."""
    from redgap import lab

    console.print("[dim]building the lab image and capturing real telemetry (needs Docker)…[/dim]")
    counts = lab.capture_all(at or _now(), git_commit=git_commit)
    for tid, n in counts.items():
        console.print(f"  {tid}: [bold]{n}[/bold] events")
    console.print("[green]fixtures regenerated.[/green]")


@app.command()
def version() -> None:
    """Print the RedGap version."""
    typer.echo(f"redgap {__version__}")


if __name__ == "__main__":
    app()
