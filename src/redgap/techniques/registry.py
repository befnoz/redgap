"""The v0.1 technique specifications, plus a hard safety validator.

Safety: the setuid technique (T1548.001) sets the setuid bit ONLY on an inert copy
of ``/bin/true`` — never on a shell or interpreter, which would create a real local
privilege-escalation primitive. That rule is enforced at import time by
:func:`_validate_setuid_safety`; editing the spec to target a shell makes the module
fail to import (and the test suite red).
"""

from __future__ import annotations

import re
import shlex

from redgap.techniques.base import TechniqueSpec

# The setuid technique may only ever touch this inert target, copied from this
# inert source. Changing these is the only sanctioned way to alter the target, and
# the validator below still forbids a dangerous one.
INERT_SUID_SOURCE = "/bin/true"
INERT_SUID_TARGET = "/tmp/redgap_demo_suid"


SPECS: dict[str, TechniqueSpec] = {
    "T1087.001": TechniqueSpec(
        technique_id="T1087.001",
        commands=("cat /etc/passwd",),
        note="Read /etc/passwd to enumerate local accounts.",
    ),
    "T1057": TechniqueSpec(
        technique_id="T1057",
        commands=("ps aux",),
        note="List processes (base-rate gap: too noisy for a single-event rule).",
    ),
    "T1136.001": TechniqueSpec(
        technique_id="T1136.001",
        commands=("useradd -M -N -s /usr/sbin/nologin svc_demo",),
        cleanup=("userdel svc_demo",),
        note="Create a nologin, no-password, no-home throwaway account, then delete it.",
    ),
    "T1548.001": TechniqueSpec(
        technique_id="T1548.001",
        commands=(
            f"cp {INERT_SUID_SOURCE} {INERT_SUID_TARGET}",
            # ONE shell command line so CommandLine carries both 'chown root' and
            # ' chmod u+s' — which is what the shipped SigmaHQ rule requires.
            f"sh -c 'chown root {INERT_SUID_TARGET} && chmod u+s {INERT_SUID_TARGET}'",
        ),
        cleanup=(f"rm -f {INERT_SUID_TARGET}",),
        note="Setuid an INERT /bin/true copy (never a shell). Matches shipped SigmaHQ rule.",
    ),
    "T1070.006": TechniqueSpec(
        technique_id="T1070.006",
        commands=("touch -r /etc/hostname /tmp/redgap_agent_file",),
        cleanup=("rm -f /tmp/redgap_agent_file",),
        note="Copy a reference file's timestamps (timestomp). Rule-gap by default.",
    ),
}


def get_spec(technique_id: str) -> TechniqueSpec:
    return SPECS[technique_id]


# Symbolic setuid/setgid (u+s, g+s, +s, a=s, u+rs, ...): a +/=/- op whose perm set
# ends in an 's'. The perm chars after the operator come from [rwxXstugo].
_SYMBOLIC_SETUID = re.compile(r"[-+=][rwxXstugo]*s")
# Interpreters/wrappers whose '-c ARG' body must be recursed into, so a nested
# `sh -c '... chmod u+s ...'` is checked, not treated as an opaque argument.
_SHELL_WRAPPERS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash"})
_SHELL_OPERATORS = frozenset({"&&", "||", ";", "|", "&", "\n"})


class _Unparseable(Exception):
    """The command could not be tokenized; the guard then fails closed."""


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _mode_grants_setuid(mode: str) -> bool:
    """True if a chmod mode operand grants the setuid or setgid bit (symbolic or
    any-length octal). Octal is parsed, so 0o-prefixed/leading-zero forms are caught."""
    if _SYMBOLIC_SETUID.search(mode):
        return True
    if re.fullmatch(r"[0-7]+", mode):
        try:
            return bool(int(mode, 8) & 0o6000)  # 0o4000 setuid | 0o2000 setgid
        except ValueError:
            return False
    return False


# Programs the technique specs legitimately use that cannot, on their own, set a
# setuid/setgid bit or exec an unseen child. Anything NOT recognized as one of these
# (an interpreter like python/perl, an exec-wrapper like env/sudo/xargs/timeout, a
# capability tool like setcap, a shell with no -c body, a grouping token like "(chmod",
# or any unknown program) fails closed. This is a positive allowlist, not a denylist.
_BENIGN_LEAF_PROGRAMS = frozenset(
    {
        "cat", "ps", "ls", "stat", "id", "echo", "true", "false",
        "touch", "rm", "rmdir", "mkdir", "mktemp", "head", "tail",
        "useradd", "userdel", "usermod", "groupadd", "groupdel",
    }
)  # fmt: skip
# A shell option bundle containing 'c' (e.g. -c, -cx, -ec): the next token is the body.
_C_FLAG = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")


def _has_reference_flag(args: list[str]) -> bool:
    # `chmod/install --reference=FILE` copies FILE's mode bits (incl. setuid): undecidable.
    return any(a == "--reference" or a.startswith("--reference=") for a in args)


def _is_cp_preserve(arg: str) -> bool:
    # cp copies the setuid bit of a setuid source only with a mode-preserving flag.
    if arg.startswith("--"):
        return arg in ("--archive", "--preserve") or arg.startswith("--preserve=")
    if arg.startswith("-") and len(arg) > 1:
        return "p" in arg[1:] or "a" in arg[1:]
    return False


def _chmod_mode_and_paths(args: list[str]) -> tuple[str | None, list[str]]:
    """chmod: the first non-flag token is the mode; the rest are path operands."""
    mode: str | None = None
    paths: list[str] = []
    for a in args:
        if a.startswith("-"):
            continue
        if mode is None:
            mode = a
        else:
            paths.append(a)
    return mode, paths


def _install_mode_and_paths(args: list[str]) -> tuple[str | None, list[str]]:
    """install: the mode comes via -m/--mode; path operands are the non-flag tokens."""
    mode: str | None = None
    paths: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-m", "--mode"):
            mode = args[i + 1] if i + 1 < len(args) else None
            i += 2
            continue
        if a.startswith("--mode="):
            mode = a.split("=", 1)[1]
        elif a.startswith("-m") and len(a) > 2:
            mode = a[2:]
        elif not a.startswith("-"):
            paths.append(a)
        i += 1
    return mode, paths


def _setuid_targets_only_inert(mode: str | None, paths: list[str], args: list[str]) -> bool:
    """True iff a chmod/install grants no setuid/setgid bit to anything but the inert
    target. A --reference flag (mode copied from another file), a missing mode, or a
    path misparsed as the mode all fail closed."""
    if _has_reference_flag(args):
        return False
    if mode is None or "/" in mode:
        return False
    if not _mode_grants_setuid(mode):
        return True
    return bool(paths) and all(p == INERT_SUID_TARGET for p in paths)


def _chown_paths(args: list[str]) -> list[str]:
    """The path operands of a chown (everything after the owner spec, minus flags)."""
    paths: list[str] = []
    seen_owner = False
    for a in args:
        if a.startswith("-"):
            continue
        if not seen_owner:
            seen_owner = True  # first non-flag token is the owner[:group] spec
            continue
        paths.append(a)
    return paths


def _shell_c_body(argv: list[str]) -> str | None:
    """The command body of a ``<shell> -c BODY``; handles bundled flags like ``-cx``."""
    for i in range(1, len(argv)):
        if _C_FLAG.match(argv[i]):
            return argv[i + 1] if i + 1 < len(argv) else None
    return None


def _simple_commands(cmd: str) -> list[list[str]]:
    """Tokenize ``cmd`` into a flat list of simple-command argv lists, splitting on
    shell operators and recursing into ``<shell> -c BODY`` wrappers. Raises
    :class:`_Unparseable` on any input it cannot tokenize (so the caller fails closed)."""
    try:
        tokens = shlex.split(cmd, comments=False, posix=True)
    except ValueError as exc:
        raise _Unparseable(str(exc)) from exc
    groups: list[list[str]] = []
    current: list[str] = []
    for tok in tokens:
        if tok in _SHELL_OPERATORS:
            if current:
                groups.append(current)
                current = []
        else:
            current.append(tok)
    if current:
        groups.append(current)

    expanded: list[list[str]] = []
    for argv in groups:
        if not argv:
            continue
        if _basename(argv[0]) in _SHELL_WRAPPERS:
            body = _shell_c_body(argv)
            if body is None:
                expanded.append(argv)  # a shell not running -c: the caller fails it closed
            else:
                expanded.extend(_simple_commands(body))
        else:
            expanded.append(argv)
    return expanded


def is_safe_setuid_command(cmd: str) -> bool:
    """Strict positive allowlist. Return True only if every simple command in ``cmd`` is
    known-safe: a ``chmod``/``install`` that grants a setuid/setgid bit exclusively to
    :data:`INERT_SUID_TARGET`, a ``chown`` that touches only the inert target, a ``cp``
    with no mode-preserving flag, or a benign leaf utility. **Everything else fails
    closed** — interpreters, exec-wrappers (``env``, ``sudo``, ``xargs`` …), ``setcap``,
    ``--reference`` tricks, a shell with no ``-c`` body, or anything unparseable."""
    try:
        simples = _simple_commands(cmd)
    except _Unparseable:
        return False
    for argv in simples:
        if not argv:
            return False
        prog = _basename(argv[0])
        if prog == "chmod":
            mode, paths = _chmod_mode_and_paths(argv[1:])
            if not _setuid_targets_only_inert(mode, paths, argv[1:]):
                return False
        elif prog == "install":
            mode, paths = _install_mode_and_paths(argv[1:])
            if not _setuid_targets_only_inert(mode, paths, argv[1:]):
                return False
        elif prog == "chown":
            if any(p != INERT_SUID_TARGET for p in _chown_paths(argv[1:])):
                return False
        elif prog == "cp":
            if any(_is_cp_preserve(a) for a in argv[1:]):
                return False
        elif prog not in _BENIGN_LEAF_PROGRAMS:
            return False  # unknown / exec-capable / interpreter / grouping — fail closed
    return True


def _validate_setuid_safety() -> None:
    """Refuse to load if the setuid technique targets anything but the inert copy."""
    spec = SPECS.get("T1548.001")
    if spec is None:
        return
    for cmd in spec.commands:
        if not is_safe_setuid_command(cmd):
            raise RuntimeError(
                f"unsafe setuid command in T1548.001: {cmd!r} — the setuid bit may only "
                f"be set on the inert {INERT_SUID_TARGET}, never on a shell/interpreter"
            )


_validate_setuid_safety()
