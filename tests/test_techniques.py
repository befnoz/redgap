"""Technique specs: every catalog technique has a benign spec, state-changing ones
clean up, and the setuid flagship is a single shell line targeting the inert copy.
"""

from __future__ import annotations

from redgap.catalog import BY_ID
from redgap.techniques.registry import SPECS, get_spec


def test_every_catalog_technique_has_a_spec():
    assert set(SPECS.keys()) == set(BY_ID.keys())


def test_specs_have_commands():
    for tid, spec in SPECS.items():
        assert spec.commands, tid


def test_state_changing_techniques_clean_up():
    for tid in ("T1136.001", "T1548.001", "T1070.006"):
        assert SPECS[tid].cleanup, tid


def test_get_spec_returns_matching_id():
    assert get_spec("T1548.001").technique_id == "T1548.001"


def test_setuid_is_single_shell_line_with_both_substrings():
    spec = SPECS["T1548.001"]
    suid_cmds = [c for c in spec.commands if "chmod" in c and "+s" in c]
    assert suid_cmds, "expected a chmod +s command"
    for cmd in suid_cmds:
        # Both substrings must live in ONE command line so the shipped rule matches.
        # The shipped rule requires a LEADING SPACE before chmod (' chmod u+s'), which
        # the '&& chmod' form provides - assert the exact substring the rule keys on.
        assert "chown root" in cmd
        assert " chmod u+s" in cmd
