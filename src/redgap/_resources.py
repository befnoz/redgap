"""Locate RedGap's committed data (Sigma rules, replay fixtures, lab build context)
in BOTH an editable checkout and an installed wheel.

In a source checkout the data lives at the repository root (``rules/``, ``fixtures/``,
``lab/``). The wheel force-includes those same trees *inside* the package
(``redgap/rules`` ...), so an installed ``redgap`` resolves them through
``importlib.resources`` instead of guessing a path relative to the repo root. This is
what lets ``pip install .`` / ``pipx install redgap`` run ``redgap run`` from any
directory - not only an editable install run from the source tree.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path


def _data_root(name: str) -> Path:
    # Installed wheel: the data tree is force-included inside the package. This assumes a
    # filesystem-based install (pip/pipx unpack to site-packages - the supported targets),
    # not zipimport/zipapp; str() on the Traversable is a real path there.
    try:
        packaged = files("redgap") / name
        if packaged.is_dir():
            return Path(str(packaged))
    except (ModuleNotFoundError, FileNotFoundError, NotADirectoryError):
        pass
    # Editable install / source checkout: the data lives at the repository root.
    return Path(__file__).resolve().parents[2] / name


def rules_dir() -> Path:
    """Directory holding the shipped Sigma rules."""
    return _data_root("rules")


def fixtures_dir() -> Path:
    """Directory holding the committed replay telemetry fixtures."""
    return _data_root("fixtures") / "replay"


def lab_dir() -> Path:
    """Docker build context for the disposable lab (LIVE mode only)."""
    return _data_root("lab")
