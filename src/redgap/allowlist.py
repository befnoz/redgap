"""Target allowlist - the gate that keeps RedGap pointed at its own lab.

RedGap must never be usable against a system the operator does not own. That is
enforced structurally here, not by convention, on two surfaces:

* **Container launches (the LIVE path).** Every ``docker run`` goes through
  :func:`assert_lab_only`, which refuses to start a container unless networking is
  disabled (``--network none``). ``lab.py`` routes each launch through it, so an edit
  that quietly networks the lab fails at runtime. (The lab subnet below is an accepted
  *target* string, not a container-networking mode.)
* **Target strings.** :func:`resolve_and_check` accepts only loopback, the lab subnet,
  or the fixed lab hostnames. There is deliberately **no** function to add a host and
  nothing here reads the environment or CLI to widen the set; hostnames are matched
  literally (no DNS), so a name that resolves to loopback cannot slip through. This is
  the guard for any network-reachable target surface (LIVE-remote is on the roadmap).

``tests/test_allowlist.py`` asserts both gates and that neither can be widened.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

#: Loopback ranges (the only IP targets that make sense for a local lab).
_LOOPBACK_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)

#: The fixed private bridge the disposable Docker lab is pinned to. Not routable.
_LAB_SUBNET = ipaddress.ip_network("172.28.0.0/24")

#: The only literal hostnames accepted (the lab's compose service names + loopback).
_LAB_HOSTNAMES = frozenset({"localhost", "lab", "redgap-lab"})


class TargetNotAllowed(ValueError):
    """Raised when a target is not the local lab. Never caught to 'try anyway'."""


def is_allowed(target: str) -> bool:
    """Return True iff ``target`` is loopback, the lab subnet, or a lab hostname."""
    t = (target or "").strip()
    if not t:
        return False
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        # Not an IP literal: accept only the fixed lab hostnames, verbatim.
        return t.lower() in _LAB_HOSTNAMES
    if any(ip in net for net in _LOOPBACK_NETS):
        return True
    return ip in _LAB_SUBNET


def resolve_and_check(target: str) -> str:
    """Return the normalized target if allowed; otherwise raise TargetNotAllowed.

    This is the only sanctioned way to obtain a target for the runner/lab.
    """
    t = (target or "").strip()
    if not is_allowed(t):
        raise TargetNotAllowed(
            f"refusing target {target!r}: RedGap only acts against its own local lab "
            f"(loopback, {_LAB_SUBNET}, or one of {sorted(_LAB_HOSTNAMES)}). "
            f"There is no override - this is by design (see ETHICS.md)."
        )
    return t.lower() if not _is_ip(t) else t


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# Global flags that could point docker at a remote/other engine - never allowed.
_DAEMON_REDIRECT_FLAGS = frozenset({"-H", "--host", "--context", "-c"})
# Subcommands that create/launch a container (as `docker run` or `docker container run`).
_CONTAINER_CREATE_VERBS = frozenset({"run", "create"})
# Global flags that consume a following value, so that value is not the subcommand.
_VALUE_GLOBAL_FLAGS = frozenset(
    {
        "-H", "--host", "--context", "-c", "--config",
        "--log-level", "-l", "--tlscacert", "--tlscert", "--tlskey",
    }
)  # fmt: skip


def _network_values(docker_args: Sequence[str]) -> list[str]:
    """Every ``--network``/``--net`` value in a docker argv. docker *appends* repeated
    ``--network`` flags and attaches the container to all of them, so we collect all."""
    vals: list[str] = []
    args = list(docker_args)
    for i, arg in enumerate(args):
        if arg in ("--network", "--net"):
            if i + 1 < len(args):
                vals.append(args[i + 1])
        elif arg.startswith("--network=") or arg.startswith("--net="):
            vals.append(arg.split("=", 1)[1])
    return vals


def _effective_verb_and_index(args: list[str]) -> tuple[str | None, int]:
    """The docker subcommand verb and its index, skipping leading global flags (and any
    values they consume) and an optional ``container`` management-group word."""
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            i += 2 if (a in _VALUE_GLOBAL_FLAGS and "=" not in a) else 1
            continue
        if a == "container":  # `docker container run/create` == `docker run/create`
            i += 1
            continue
        return a, i
    return None, len(args)


def assert_lab_only(docker_args: Sequence[str]) -> None:
    """Gate a docker invocation so RedGap can only ever act on its own offline lab.

    Refuses (1) any daemon-redirecting global flag (``-H``/``--host``/``--context``),
    which could target a remote engine, and (2) any container-creating command
    (``run``/``create``, including the ``docker container ...`` form) whose networking is
    not disabled - every ``--network``/``--net`` value must be ``none``. Non-creating
    commands (build, exec, cp, rm, inspect) are allowed. :mod:`redgap.lab` routes every
    docker call through here, so an edit that networks the lab fails at runtime."""
    args = list(docker_args)
    verb, verb_idx = _effective_verb_and_index(args)
    # Global flags sit before the verb; none may redirect the daemon off the local box.
    for a in args[:verb_idx]:
        if a.split("=", 1)[0] in _DAEMON_REDIRECT_FLAGS:
            raise TargetNotAllowed(
                f"refusing docker invocation with {a!r}: RedGap uses the local docker "
                f"daemon only, never a remote/redirected engine (see ETHICS.md)."
            )
    if verb not in _CONTAINER_CREATE_VERBS:
        return
    nets = _network_values(args[verb_idx:])
    if not nets or any(n != "none" for n in nets):
        raise TargetNotAllowed(
            f"refusing to launch a container with networking {nets or ['(default bridge)']}: "
            f"RedGap's lab must run with '--network none'. There is no override - by design."
        )
