"""Benign technique specifications.

Each technique is a small, auditable set of benign commands (derived from published
Atomic Red Team tests) run against RedGap's own disposable lab, plus an idempotent
cleanup. No exploits, no payloads, no off-box actions, no runtime downloads.
"""

from redgap.techniques.base import TechniqueSpec
from redgap.techniques.registry import SPECS, get_spec

__all__ = ["TechniqueSpec", "SPECS", "get_spec"]
