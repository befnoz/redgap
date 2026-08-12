"""Parse snoopy execve telemetry into normalized events.

snoopy is an ``LD_PRELOAD`` execve logger: an *independent* collector (loaded into
the shell, not into RedGap's attacker code) that writes one line per executed
command to syslog. The lab image configures snoopy with the exact ``message_format``
below so parsing is trivial and unambiguous.

Independence matters: the attacker only runs commands; these events come from a
separate collector and are read back here by ``run_id``/``technique_id``. RedGap's
offense code never fabricates an event.
"""

from __future__ import annotations

from typing import Any

from redgap.telemetry.schema import make_event

#: The snoopy datasource format the lab must configure (snoopy.ini message_format).
#: Fields: marker, pid, username, cwd, filename (executable), cmdline.
MARKER = "REDGAP"
FIELD_SEP = "\t"
SNOOPY_MESSAGE_FORMAT = "REDGAP\t%{pid}\t%{username}\t%{cwd}\t%{filename}\t%{cmdline}"


def parse_snoopy_line(
    line: str, *, run_id: str, technique_id: str, index: int = 0
) -> dict[str, Any] | None:
    """Parse one syslog line into an event, or ``None`` if it is not a snoopy record.

    A real line carries a syslog prefix, e.g.::

        Aug 11 09:00:00 host snoopy[1234]: REDGAP\t1234\troot\t/root\t/usr/bin/cat\tcat /etc/passwd

    We locate the ``REDGAP<TAB>`` marker and parse the tab-delimited payload after it.
    """
    needle = MARKER + FIELD_SEP
    pos = line.find(needle)
    if pos < 0:
        return None
    payload = line[pos + len(needle) :].rstrip("\r\n")
    # cmdline is last and may itself contain spaces; keep it intact with maxsplit.
    parts = payload.split(FIELD_SEP, 4)
    if len(parts) != 5:
        return None
    pid_raw, username, cwd, filename, cmdline = parts
    try:
        pid: int | None = int(pid_raw)
    except ValueError:
        pid = None
    return make_event(
        run_id=run_id,
        technique_id=technique_id,
        image=filename or None,
        command_line=cmdline or None,
        user=username or None,
        current_directory=cwd or None,
        pid=pid,
        raw=line.rstrip("\r\n"),
        index=index,
    )


def parse_snoopy_log(text: str, *, run_id: str, technique_id: str) -> list[dict[str, Any]]:
    """Parse a snoopy log (one execve per line) into normalized events, in order."""
    events: list[dict[str, Any]] = []
    index = 0
    for line in text.splitlines():
        event = parse_snoopy_line(line, run_id=run_id, technique_id=technique_id, index=index)
        if event is not None:
            events.append(event)
            index += 1
    return events
