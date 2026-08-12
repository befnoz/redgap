"""snoopy log parsing, plus an end-to-end check that a real snoopy line for the
flagship setuid command flows through the parser into the shipped SigmaHQ rule.
"""

from __future__ import annotations

from pathlib import Path

from redgap.detection.engine import rule_matches
from redgap.detection.sigma_ast import parse_rule
from redgap.telemetry import schema
from redgap.telemetry.snoopy import parse_snoopy_line, parse_snoopy_log

RULES = Path(__file__).resolve().parents[1] / "rules"


def _line(pid, user, cwd, filename, cmdline):
    return (
        f"Aug 11 09:00:00 host snoopy[{pid}]: REDGAP\t{pid}\t{user}\t{cwd}\t{filename}\t{cmdline}"
    )


def test_parse_single_line():
    ev = parse_snoopy_line(
        _line(1234, "root", "/root", "/usr/bin/cat", "cat /etc/passwd"),
        run_id="r",
        technique_id="T1087.001",
    )
    assert ev is not None
    assert ev[schema.IMAGE] == "/usr/bin/cat"
    assert ev[schema.COMMAND_LINE] == "cat /etc/passwd"
    assert ev[schema.USER] == "root"
    assert ev[schema.PID] == 1234
    assert ev[schema.TECHNIQUE_ID] == "T1087.001"
    assert ev[schema.RUN_ID] == "r"


def test_non_marker_line_is_ignored():
    assert (
        parse_snoopy_line("Aug 11 sshd[1]: accepted password", run_id="r", technique_id="T") is None
    )


def test_parse_log_skips_noise_and_preserves_order():
    text = "\n".join(
        [
            "random syslog noise",
            _line(1, "root", "/", "/usr/bin/ps", "ps aux"),
            "more noise here",
            _line(2, "root", "/", "/usr/sbin/useradd", "useradd -M svc_demo"),
        ]
    )
    events = parse_snoopy_log(text, run_id="r", technique_id="Tx")
    assert len(events) == 2
    assert events[0][schema.IMAGE] == "/usr/bin/ps"
    assert events[1][schema.IMAGE] == "/usr/sbin/useradd"


def test_end_to_end_setuid_parse_then_detect():
    # argv ['sh','-c','chown root X && chmod u+s X'] renders (snoopy %{cmdline}) as a
    # single space-joined line carrying both 'chown root' and ' chmod u+s'.
    cmdline = "sh -c chown root /tmp/redgap_demo_suid && chmod u+s /tmp/redgap_demo_suid"
    ev = parse_snoopy_line(
        _line(9, "root", "/root", "/usr/bin/sh", cmdline),
        run_id="r",
        technique_id="T1548.001",
    )
    rule = parse_rule((RULES / "proc_creation_lnx_setgid_setuid.yml").read_text(encoding="utf-8"))
    assert rule_matches(rule, ev) is not None
