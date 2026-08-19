"""Regression tests for the final-audit fixes: the load-time ReDoS/None-operand guards,
the setuid gate reaching a preserve-mode cp and reference-form chown, the pinned
tactic-count and single-source version claims, and cross-process determinism.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

import redgap
from redgap.catalog import CATALOG
from redgap.detection.sigma_ast import RuleError, parse_rule
from redgap.techniques.registry import (
    _spec_grants_privilege,
    _validate_setuid_safety,
    is_safe_setuid_command,
)

_HEAD = (
    "title: t\n"
    "id: 11111111-2222-3333-4444-555555555555\n"
    "logsource:\n    product: linux\n    category: process_creation\n"
    "detection:\n"
)


def _rule(detection_body: str) -> str:
    return _HEAD + detection_body


# --- ReDoS: a value with too many wildcards is excluded at load -----------------------
def test_excessive_wildcards_are_excluded():
    value = "*" + "a*" * 17  # 18 multi-wildcards -> over the cap
    with pytest.raises(RuleError):
        parse_rule(
            _rule(f"    selection:\n        CommandLine: '{value}'\n    condition: selection\n")
        )


def test_reasonable_wildcards_still_load():
    parse_rule(
        _rule(
            "    selection:\n"
            "        CommandLine|contains: '*/bin/sh*-c*'\n"
            "    condition: selection\n"
        )
    )


# --- A buried None operand (an `of` pattern matching nothing) is a loud exclusion ------
def test_buried_none_operand_is_excluded():
    with pytest.raises(RuleError):
        parse_rule(
            _rule(
                "    selection:\n        Image|endswith: '/x'\n"
                "    condition: selection and 1 of filter_*\n"
            )
        )


# --- Setuid safety gate reaches preserve-mode cp and reference-form chown --------------
def test_setuid_gate_routes_and_rejects_preserve_cp():
    spec = SimpleNamespace(commands=["cp -p /bin/su /tmp/x"], cleanup=[])
    assert _spec_grants_privilege(spec) is True  # cp -p now triggers validation
    assert is_safe_setuid_command("cp -p /bin/su /tmp/x") is False  # and is rejected
    assert is_safe_setuid_command("cp --preserve=mode /bin/su /tmp/x") is False


def test_chown_reference_is_rejected():
    assert is_safe_setuid_command("chown --reference=/etc/passwd /bin/bash") is False
    assert is_safe_setuid_command("chown --reference /etc/passwd /bin/bash") is False


def test_real_specs_pass_the_setuid_gate():
    _validate_setuid_safety()  # the shipped catalog must import clean


# --- Headline claims are pinned by a test, not only asserted in prose ------------------
def test_catalog_spans_eleven_tactics():
    tactics = {tac for t in CATALOG for tac in t.tactics}
    assert len(tactics) == 11


def test_version_is_single_valued():
    pyproject = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text("utf-8"))
    assert pyproject["project"]["version"] == redgap.__version__


# --- Determinism holds across processes with different hash seeds ----------------------
def _coverage_json(seed: str) -> str:
    code = (
        "import json;"
        "from redgap.pipeline import run_coverage;"
        "from redgap.target import ReplayTarget;"
        "v,r=run_coverage(ReplayTarget(),generated_at='2026-08-11T00:00:00Z');"
        "print(json.dumps(r['techniques']))"  # NOT sort_keys: exposes insertion-order drift
    )
    env = dict(os.environ, PYTHONHASHSEED=seed)
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env, check=True
    )
    return out.stdout


def test_coverage_is_byte_identical_across_hash_seeds():
    a = _coverage_json("1")
    b = _coverage_json("2")
    assert a == b
    assert json.loads(a)  # sanity: non-empty
