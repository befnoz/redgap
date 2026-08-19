"""The v0.1 technique specifications, plus a hard safety validator.

Safety: the setuid technique (T1548.001) sets the setuid bit ONLY on an inert copy
of ``/bin/true`` - never on a shell or interpreter, which would create a real local
privilege-escalation primitive. That rule is enforced at import time by
:func:`_validate_setuid_safety`; editing the spec to target a shell makes the module
fail to import (and the test suite red).
"""

from __future__ import annotations

import re
import shlex

from redgap.techniques.base import TechniqueSpec
from redgap.techniques.catalog_data import TECHNIQUES

# The setuid technique may only ever touch this inert target, copied from this
# inert source. The validator below still forbids a dangerous edit to the T1548.001
# commands in catalog_data.py.
INERT_SUID_SOURCE = "/bin/true"
INERT_SUID_TARGET = "/tmp/redgap_demo_suid"
#: The setcap technique (T1548) grants a file capability to this inert copy only.
INERT_SETCAP_TARGET = "/tmp/rgcap"
#: Every path a privilege/capability grant is allowed to touch.
INERT_TARGETS = frozenset({INERT_SUID_TARGET, INERT_SETCAP_TARGET})


#: Executable specs, built from the single catalog_data source of truth.
SPECS: dict[str, TechniqueSpec] = {
    t.id: TechniqueSpec(
        technique_id=t.id,
        commands=t.commands,
        cleanup=t.cleanup,
        note=t.name,
    )
    for t in TECHNIQUES
}


def get_spec(technique_id: str) -> TechniqueSpec:
    return SPECS[technique_id]


# Symbolic setuid/setgid (u+s, g+s, +s, a=s, u+rs, ...): a +/=/- op whose perm set
# ends in an 's'. The perm chars after the operator come from [rwxXstugo].
_SYMBOLIC_SETUID = re.compile(r"[-+=][rwxXstugo]*s")
# Interpreters/wrappers whose '-c ARG' body must be recursed into, so a nested
# `sh -c '... chmod u+s ...'` is checked, not treated as an opaque argument.
_SHELL_WRAPPERS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash"})
_SHELL_OPERATORS = frozenset({"&&", "||", ";", "|", "&"})  # newlines are whitespace to shlex


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
        return bool(int(mode, 8) & 0o6000)  # 0o4000 setuid | 0o2000 setgid; regex ensures octal
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
    return bool(paths) and all(p in INERT_TARGETS for p in paths)


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
    known-safe: a ``chmod``/``chown`` that grants/touches only an inert target
    (:data:`INERT_TARGETS`), a ``cp`` of ``/bin/true`` onto an inert target with no
    mode-preserving flag, a ``setcap`` onto an inert target, or a benign leaf utility.
    **Everything else fails closed** - interpreters, exec-wrappers (``env``, ``sudo``,
    ``xargs`` ...), ``install`` (its ``-t DIR`` grammar can hide the real setuid target),
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
        elif prog == "chown":
            # --reference=FILE copies another file's owner; like the chmod path, reject it
            # so a reference-form chown cannot slip a non-inert target past _chown_paths.
            if _has_reference_flag(argv[1:]):
                return False
            if any(p not in INERT_TARGETS for p in _chown_paths(argv[1:])):
                return False
        elif prog == "cp":
            # A mode-preserving flag could copy a setuid SOURCE's bit; reject it. AND pin the
            # copy to `cp /bin/true <inert target>` - without pinning the SOURCE, copying a
            # shell onto the allowed target and then chmod u+s it yields a setuid-root shell.
            if any(_is_cp_preserve(a) for a in argv[1:]):
                return False
            operands = [a for a in argv[1:] if not a.startswith("-")]
            ok = (
                len(operands) == 2
                and operands[0] == INERT_SUID_SOURCE
                and operands[1] in INERT_TARGETS
            )
            if not ok:
                return False
        elif prog == "setcap":
            # setcap grants a file capability; allow it only onto an inert target. The file is
            # the last non-flag operand (`setcap cap_setuid+ep /tmp/rgcap`, `setcap -r /tmp/rgcap`).
            operands = [a for a in argv[1:] if not a.startswith("-")]
            if not operands or operands[-1] not in INERT_TARGETS:
                return False
        elif prog not in _BENIGN_LEAF_PROGRAMS:
            return False  # unknown / exec-capable / interpreter / install / grouping - fail closed
    return True


_GRANT_PROGS = frozenset({"chmod", "chown", "setcap", "install"})


def _cp_preserves_mode(argv: list[str]) -> bool:
    """A ``cp`` with a mode-preserving flag - it can copy a setuid SOURCE's bit, so it must
    be routed through the inert-target allowlist just like chmod/chown/setcap/install."""
    return bool(argv) and _basename(argv[0]) == "cp" and any(_is_cp_preserve(a) for a in argv[1:])


def _spec_grants_privilege(spec) -> bool:
    """True if any of the spec's commands invokes a setuid/setgid/capability-granting tool
    (or a mode-preserving ``cp``), so the whole spec must pass the inert-target allowlist."""
    for cmd in spec.commands:
        try:
            simples = _simple_commands(cmd)
        except _Unparseable:
            # Fail toward validation on unparseable input that names a granting tool or a
            # preserve-mode cp (e.g. `cp -p`, `cp --preserve`, `cp --archive`).
            if re.search(r"\b(?:setcap|chmod|chown|install)\b", cmd) or re.search(
                r"\bcp\b[^;&|]*(?:--preserve|--archive|\s-[a-zA-Z]*[pa])", cmd
            ):
                return True
            continue
        if any(
            _basename(argv[0]) in _GRANT_PROGS or _cp_preserves_mode(argv)
            for argv in simples
            if argv
        ):
            return True
    return False


def _validate_setuid_safety() -> None:
    """Refuse to load if ANY capability-granting technique (not a hardcoded id) touches
    anything but an inert target - fail-closed for every setuid/setgid/setcap spec."""
    for tid, spec in SPECS.items():
        if not _spec_grants_privilege(spec):
            continue
        for cmd in spec.commands:
            if not is_safe_setuid_command(cmd):
                raise RuntimeError(
                    f"unsafe capability-granting command in {tid}: {cmd!r} - a privilege bit "
                    f"may only be set on an inert target {sorted(INERT_TARGETS)}"
                )


# A duplicate technique id would desync the execution set from the report; survives python -O.
if len(SPECS) != len(TECHNIQUES):
    raise RuntimeError("duplicate technique id in catalog_data.TECHNIQUES")

_validate_setuid_safety()
