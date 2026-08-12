"""Coverage report renderers: machine-readable JSON, human-readable Markdown, and an
ATT&CK Navigator layer. All are pure functions of (catalog, verdicts) — the numbers
come straight from the deterministic engine, never from a language model.
"""

from redgap.report.build import coverage_dict
from redgap.report.markdown import markdown_report
from redgap.report.navigator import navigator_layer

__all__ = ["coverage_dict", "markdown_report", "navigator_layer"]
