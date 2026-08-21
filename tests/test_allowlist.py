"""The allowlist is a load-bearing safety control, so it gets load-bearing tests.

These prove RedGap cannot be pointed at a third-party host and that the allowlist
cannot be widened at runtime via the environment or any public function.
"""

from __future__ import annotations

import os

import pytest

from redgap import allowlist
from redgap.allowlist import (
    TargetNotAllowed,
    assert_lab_only,
    is_allowed,
    resolve_and_check,
)


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "127.5.9.9",  # anywhere in 127.0.0.0/8
        "::1",
        "172.28.0.5",  # the pinned lab bridge
        "172.28.0.255",
        "localhost",
        "LocalHost",  # case-insensitive hostname
        "redgap-lab",
        "lab",
    ],
)
def test_lab_targets_are_allowed(target: str) -> None:
    assert is_allowed(target) is True
    assert resolve_and_check(target)  # does not raise


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",
        "1.1.1.1",
        "10.0.0.5",  # private, but not the lab bridge
        "192.168.1.10",
        "172.28.1.5",  # one subnet over from the lab -> rejected
        "172.29.0.5",
        "example.com",
        "github.com",
        "ajax.systems",
        "169.254.169.254",  # cloud metadata endpoint, notably
        "0.0.0.0",
        "",
        "   ",
    ],
)
def test_non_lab_targets_are_refused(target: str) -> None:
    assert is_allowed(target) is False
    with pytest.raises(TargetNotAllowed):
        resolve_and_check(target)


def test_allowlist_cannot_be_widened_by_environment() -> None:
    """No environment variable should ever make an external host acceptable."""
    for var in ("REDGAP_TARGET", "REDGAP_ALLOWLIST", "TARGET", "REDGAP_ALLOW_HOSTS"):
        os.environ[var] = "8.8.8.8"
    try:
        assert is_allowed("8.8.8.8") is False
        with pytest.raises(TargetNotAllowed):
            resolve_and_check("8.8.8.8")
    finally:
        for var in ("REDGAP_TARGET", "REDGAP_ALLOWLIST", "TARGET", "REDGAP_ALLOW_HOSTS"):
            os.environ.pop(var, None)


def test_module_exposes_no_widening_api() -> None:
    """There must be no public function to add/extend allowed targets."""
    public = {n for n in dir(allowlist) if not n.startswith("_")}
    forbidden_substrings = ("add", "extend", "append", "register", "allow_host", "set_")
    offenders = {
        n
        for n in public
        if callable(getattr(allowlist, n)) and any(s in n.lower() for s in forbidden_substrings)
    }
    assert not offenders, f"allowlist must not expose widening helpers: {offenders}"


def test_no_dns_resolution_for_lookalike_hostnames() -> None:
    """A hostname that is not a literal lab name is refused without DNS lookup."""
    # 'localhost.attacker.example' is not in the literal set, must be refused.
    assert is_allowed("localhost.attacker.example") is False


def test_container_launch_gate_allows_offline_lab() -> None:
    """The container-launch gate accepts a run that disables networking."""
    assert_lab_only(("run", "-d", "--name", "x", "--network", "none", "redgap-lab:v0.1"))
    assert_lab_only(("run", "--rm", "--network=none", "redgap-lab:v0.1", "uname", "-r"))


@pytest.mark.parametrize(
    "run_args",
    [
        ("run", "-d", "redgap-lab:v0.1"),  # no --network => default bridge => refused
        ("run", "--network", "host", "redgap-lab:v0.1"),
        ("run", "--network", "bridge", "redgap-lab:v0.1"),
        ("run", "--network=8.8.8.8", "redgap-lab:v0.1"),
        ("run", "--net", "host", "redgap-lab:v0.1"),  # --net alias
    ],
)
def test_container_launch_gate_refuses_networked_runs(run_args: tuple[str, ...]) -> None:
    """Any container launch that could reach off-box is refused at runtime."""
    with pytest.raises(TargetNotAllowed):
        assert_lab_only(run_args)


@pytest.mark.parametrize(
    "run_args",
    [
        # `docker container run` alias must be gated like `docker run`
        ("container", "run", "--network", "host", "redgap-lab:v0.1"),
        ("container", "run", "redgap-lab:v0.1"),
        # `docker create` (+ later `start`) must be gated too
        ("create", "--name", "x", "--network", "host", "redgap-lab:v0.1"),
        ("create", "--name", "x", "redgap-lab:v0.1"),
        # a second --network the first-match check would have missed
        ("run", "--network", "none", "--network", "evil", "redgap-lab:v0.1"),
        # daemon-redirect global flags target a remote/other engine
        ("-H", "tcp://attacker:2375", "run", "--network", "none", "redgap-lab:v0.1"),
        ("--context", "remote", "run", "--network", "none", "redgap-lab:v0.1"),
        ("--host", "ssh://box", "run", "--network", "none", "redgap-lab:v0.1"),
    ],
)
def test_container_launch_gate_refuses_bypass_forms(run_args: tuple[str, ...]) -> None:
    """Aliased/redirected/multi-network launch forms must not slip past the gate."""
    with pytest.raises(TargetNotAllowed):
        assert_lab_only(run_args)


def test_gate_allows_container_run_alias_offline() -> None:
    assert_lab_only(("container", "run", "--network", "none", "redgap-lab:v0.1"))


def test_gate_allows_non_creating_commands() -> None:
    # build/exec/cp/rm/inspect do not create a networked container and are allowed -
    # including an `exec` whose in-container command legitimately contains `-c`.
    assert_lab_only(("build", "-t", "redgap-lab:v0.1", "lab"))
    assert_lab_only(("exec", "redgap-cap", "sh", "-c", "chmod u+s /tmp/x"))
    assert_lab_only(("image", "inspect", "redgap-lab:v0.1"))
    assert_lab_only(("cp", "redgap-cap:/var/log/redgap/exec.log", "/tmp/out"))
    assert_lab_only(("rm", "-f", "redgap-cap"))


def test_adaptive_pick_list_is_a_catalog_subset_never_widened() -> None:
    """The adaptive planner hands the model a candidate list == catalog minus what already
    ran. Like the batch allowlist, it can only ever SHRINK - a planner can never surface a
    technique outside the shipped catalog."""
    from pathlib import Path

    from redgap.agent_state import state_view
    from redgap.catalog import BY_ID
    from redgap.detection.sigma_ast import load_rules_detailed
    from redgap.engine_facade import CoverageEngine
    from redgap.target import ReplayTarget

    rules_dir = Path(__file__).resolve().parents[1] / "rules"
    rules, excluded = load_rules_detailed(rules_dir)
    engine = CoverageEngine(ReplayTarget(), rules, excluded, generated_at="2026-08-11T00:00:00Z")

    full = set(state_view(engine, [])["remaining_techniques"])
    assert full == set(BY_ID)  # nothing run yet -> the whole catalog, nothing more

    engine.run_technique("T1548.001")
    after = set(state_view(engine, [])["remaining_techniques"])
    assert after == full - {"T1548.001"}  # only ever shrinks; still a strict catalog subset
    assert after <= set(BY_ID)
