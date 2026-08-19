"""Parse snoopy-style execve telemetry into normalized events.

The collector is ``lab/collector/redgap_exec.c`` - a small in-repo ``LD_PRELOAD``
constructor (snoopy-style, hence the module name) loaded into the shell, NOT into
RedGap's attacker code. On each ``execve`` it writes one tab-delimited record per
executed command to a plain file (``/var/log/redgap/exec.log``); no syslog and no
external ``snoopy`` package or ``.ini`` is involved. Each record is::

    REDGAP<TAB>pid<TAB>username<TAB>cwd<TAB>filename(executable)<TAB>cmdline

so parsing is trivial and unambiguous. ``MARKER`` + ``FIELD_SEP`` below are the wire
tokens the C collector emits (kept in sync with its ``snprintf`` layout).

Independence matters: the attacker only runs commands; these events come from a
separate collector and are read back here by ``run_id``/``technique_id``. RedGap's
offense code never fabricates an event.
"""

from __future__ import annotations

from typing import Any

from redgap.telemetry.schema import PID, make_event

#: Wire tokens emitted by the redgap_exec.c collector, one record per execve.
#: Fields: marker, pid, username, cwd, filename (executable), cmdline.
MARKER = "REDGAP"
FIELD_SEP = "\t"


def parse_snoopy_line(
    line: str, *, run_id: str, technique_id: str, index: int = 0
) -> dict[str, Any] | None:
    """Parse one collector ``exec.log`` record line into an event, or ``None`` if the line
    carries no record. The collector writes plain tab-delimited lines (no syslog); we still
    locate the ``REDGAP<TAB>`` marker ANYWHERE in the line, so any leading prefix a future
    collector might add is tolerated. A line looks like::

        REDGAP\t1234\troot\t/root\t/usr/bin/cat\tcat /etc/passwd

    and we parse the tab-delimited payload after the marker.
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
    # Split ONLY on '\n' - the sole record delimiter the collector emits. str.splitlines()
    # would also break on \v \f \x1c-\x1e \x85 U+2028 U+2029, which the universal-newline
    # read leaves intact, so a cmdline containing one could silently truncate a real record.
    for line in text.split("\n"):
        event = parse_snoopy_line(line, run_id=run_id, technique_id=technique_id, index=index)
        if event is None:
            continue
        index += 1
        # Drop the container's own init process (PID 1, `sleep infinity`): it is lab
        # scaffolding, not part of the technique, so a Bring-Your-Own-Rules rule cannot
        # falsely 'fire' on it and score an unrelated technique detected.
        if event.get(PID) == 1:
            continue
        events.append(event)
    return events
