"""The normalized event schema RedGap detects on.

RedGap events use the **SigmaHQ Linux ``process_creation`` field vocabulary**
(``Image``, ``CommandLine``, ``ParentImage``, ``User`` ...). This is deliberate:
it means a real, shipped SigmaHQ rule matches our events *unmodified* (maximum
credibility for the "we didn't rig the verdict" claim), and our authored rules
speak the same portable language.

RedGap-internal bookkeeping (run id, technique id, event id, provenance) is stored
under **underscore-prefixed keys**. No Sigma rule can reference those, and the
keyword/value-only search skips them, so bookkeeping can never accidentally
satisfy a detection.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# --- Sigma-visible fields (SigmaHQ linux/process_creation vocabulary) ---------
IMAGE = "Image"
COMMAND_LINE = "CommandLine"
PARENT_IMAGE = "ParentImage"
PARENT_COMMAND_LINE = "ParentCommandLine"
USER = "User"
CURRENT_DIRECTORY = "CurrentDirectory"
PID = "ProcessId"  # SigmaHQ/Sysmon-for-Linux standard token (not "Pid"), so a real rule matches

SIGMA_FIELDS: tuple[str, ...] = (
    IMAGE,
    COMMAND_LINE,
    PARENT_IMAGE,
    PARENT_COMMAND_LINE,
    USER,
    CURRENT_DIRECTORY,
    PID,
)

# --- RedGap-internal keys (never referenced by rules) -------------------------
RUN_ID = "_run_id"
TECHNIQUE_ID = "_technique_id"
EVENT_ID = "_event_id"
TIMESTAMP = "_timestamp"
RAW = "_raw"


def is_internal_key(key: str) -> bool:
    """RedGap bookkeeping keys are underscore-prefixed and invisible to rules."""
    return key.startswith("_")


def compute_event_id(fields: dict[str, Any], index: int = 0) -> str:
    """A content-addressed id for an event.

    Derived from the Sigma-visible content plus a positional index (to keep
    identical command lines distinct within a run). No wall clock, no randomness,
    so replay is byte-reproducible.
    """
    visible = {k: v for k, v in fields.items() if not is_internal_key(k)}
    blob = json.dumps([visible, index], sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
    return f"ev_{digest}"


def make_event(
    *,
    run_id: str,
    technique_id: str,
    image: str | None = None,
    command_line: str | None = None,
    parent_image: str | None = None,
    parent_command_line: str | None = None,
    user: str | None = None,
    current_directory: str | None = None,
    pid: int | None = None,
    timestamp: str = "",
    raw: str = "",
    index: int = 0,
) -> dict[str, Any]:
    """Build one normalized process-creation event."""
    fields: dict[str, Any] = {}
    if image is not None:
        fields[IMAGE] = image
    if command_line is not None:
        fields[COMMAND_LINE] = command_line
    if parent_image is not None:
        fields[PARENT_IMAGE] = parent_image
    if parent_command_line is not None:
        fields[PARENT_COMMAND_LINE] = parent_command_line
    if user is not None:
        fields[USER] = user
    if current_directory is not None:
        fields[CURRENT_DIRECTORY] = current_directory
    if pid is not None:
        fields[PID] = pid

    fields[EVENT_ID] = compute_event_id(fields, index)
    fields[RUN_ID] = run_id
    fields[TECHNIQUE_ID] = technique_id
    fields[TIMESTAMP] = timestamp
    if raw:
        fields[RAW] = raw
    return fields
