"""Weaponization guard: the setuid technique may only ever touch an inert /bin/true
copy, never a shell or interpreter. This is the single most important safety test in
a public offensive repo.
"""

from __future__ import annotations

import pytest

from redgap.techniques.registry import (
    INERT_SUID_SOURCE,
    INERT_SUID_TARGET,
    SPECS,
    is_safe_setuid_command,
)


def test_setuid_spec_only_touches_the_inert_copy():
    spec = SPECS["T1548.001"]
    # It must copy the inert source, then setuid only that inert target.
    assert any(INERT_SUID_SOURCE in c and INERT_SUID_TARGET in c for c in spec.commands)
    for cmd in spec.commands:
        assert is_safe_setuid_command(cmd), cmd
    # And it must clean up after itself.
    assert any("rm" in c and INERT_SUID_TARGET in c for c in spec.cleanup)


def test_source_is_inert_true():
    assert INERT_SUID_SOURCE == "/bin/true"


def test_guard_rejects_setuid_on_a_shell_or_interpreter():
    for evil in (
        "chmod u+s /bin/bash",
        "chmod u+s /usr/bin/python3",
        "sh -c 'chmod g+s /bin/dash'",
        "chmod 4755 /bin/bash",  # numeric setuid mode must also be rejected
        "chmod 6755 /usr/bin/env",  # setuid+setgid numeric mode
    ):
        assert is_safe_setuid_command(evil) is False, evil


def test_guard_ignores_non_setuid_chmod():
    # A plain executable-bit chmod (no setuid/setgid) is not a setuid command.
    assert is_safe_setuid_command("chmod +x /tmp/script.sh") is True
    assert is_safe_setuid_command("chmod 0755 /tmp/x") is True


def test_guard_allows_the_inert_target():
    good = f"sh -c 'chown root {INERT_SUID_TARGET} && chmod u+s {INERT_SUID_TARGET}'"
    assert is_safe_setuid_command(good) is True


def test_guard_rejects_extra_target_smuggled_alongside_inert():
    # A second path operand on the same chmod — the inert target is present, but a
    # real privesc binary rides along. The old substring denylist missed this.
    evil = f"chmod u+s {INERT_SUID_TARGET} /bin/su"
    assert is_safe_setuid_command(evil) is False, evil


def test_guard_rejects_shell_setuid_even_when_inert_is_chowned():
    # The inert target is chowned (so the substring is present), but the setuid bit
    # actually lands on /bin/bash — followed by a quote, not a space, defeating the
    # old end-of-token check. Must fail closed now.
    evil = f"sh -c 'chown root {INERT_SUID_TARGET} && chmod u+s /bin/bash'"
    assert is_safe_setuid_command(evil) is False, evil


def test_guard_rejects_octal_setuid_with_leading_zero():
    # 0o-style leading zero (04755) still grants setuid; must be parsed, not pattern-hit.
    assert is_safe_setuid_command("chmod 04755 /bin/bash") is False


def test_guard_fails_closed_on_unparseable_command():
    # An unbalanced quote cannot be tokenized — the guard must refuse, not allow.
    assert is_safe_setuid_command(f"chmod u+s {INERT_SUID_TARGET} '") is False


@pytest.mark.parametrize(
    "evil",
    [
        "env chmod u+s /bin/sh",  # exec-wrapper hides the chmod from an argv[0] check
        "sudo chmod u+s /bin/sh",
        "xargs chmod u+s /bin/sh",
        "timeout 5 chmod u+s /bin/sh",
        "busybox chmod u+s /bin/sh",
        "nice chmod u+s /bin/sh",
        "install -m 4755 /bin/sh /tmp/rootsh",  # install can create a setuid file
        "install -m4755 /bin/sh /tmp/rootsh",
        # install's -t/--target-directory grammar hides the real setuid target (DIR/basename)
        f"install -m4755 --target-directory=/etc/cron.d {INERT_SUID_TARGET}",
        f"install -m 4755 --target-directory=/etc/cron.d {INERT_SUID_TARGET}",
        f"install -m4755 -t/etc/cron.d {INERT_SUID_TARGET}",
        "chmod --reference=/usr/bin/passwd /bin/sh",  # copy setuid bits from a setuid file
        "sh -cx 'chmod u+s /bin/sh'",  # bundled -c flag still runs the body
        "bash -xc 'chmod u+s /bin/sh'",
        "sh -c '(chmod u+s /bin/sh)'",  # subshell grouping
        "cp -p /usr/bin/passwd /tmp/rootsh",  # cp -p preserves the source's setuid bit
        "cp --preserve=mode /usr/bin/passwd /tmp/rootsh",
        "python3 -c 'import os;os.chmod(\"/bin/sh\",0o4755)'",  # interpreter
    ],
)
def test_guard_rejects_indirect_and_wrapped_setuid(evil: str) -> None:
    assert is_safe_setuid_command(evil) is False, evil
