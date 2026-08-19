"""The deterministic core must import with ZERO dependency on typer/rich/anthropic, so
the offline REPLAY path (and CI) never needs a UI framework or an API key. Run in a
subprocess so we inspect a clean sys.modules.
"""

from __future__ import annotations

import subprocess
import sys

_CORE = [
    "redgap.pipeline",
    "redgap.planner",
    "redgap.engine_facade",
    "redgap.target",
    "redgap.detection.coverage",
    "redgap.detection.engine",
    "redgap.detection.sigma_ast",
    "redgap.report",
    "redgap.report.navigator",
    "redgap.report.scorecard",
    "redgap.audit",
    "redgap.models",
    "redgap.catalog",
    "redgap.telemetry.snoopy",
]

_FORBIDDEN = ("typer", "rich", "anthropic", "docker")


def test_core_modules_pull_no_ui_or_llm_or_docker():
    code = (
        "import importlib, sys\n"
        + "".join(f"importlib.import_module({m!r})\n" for m in _CORE)
        + f"bad = [m for m in {_FORBIDDEN!r} if m in sys.modules]\n"
        "print(','.join(bad))\n"
        "sys.exit(1 if bad else 0)\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, f"core imported forbidden modules: {result.stdout.strip()}"
