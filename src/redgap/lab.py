"""Live lab: build the disposable container and capture REAL execve telemetry.

This is the LIVE half of RedGap (opt-in; the default path is REPLAY over committed
fixtures). It drives Docker via the CLI (no docker-SDK dependency) and is kept out of
the deterministic core so the offline path never imports it.

Independence: the offense only runs commands via ``docker exec``; the telemetry comes
from the container's own preloaded collector (``redgap_exec.so``), read back read-only.
RedGap's Python never writes the collector log.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from redgap._resources import fixtures_dir, lab_dir
from redgap.allowlist import assert_lab_only
from redgap.techniques.registry import SPECS
from redgap.telemetry.snoopy import parse_snoopy_log

IMAGE = "redgap-lab:v0.1"
CONTAINER_LOG = "/var/log/redgap/exec.log"
LAB_DIR = lab_dir()
FIXTURES_DIR = fixtures_dir()


class LabError(RuntimeError):
    """A docker/lab operation failed."""


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    # Every docker call is gated: assert_lab_only refuses a remote daemon or any
    # container-creating command that is not `--network none` (see redgap.allowlist).
    assert_lab_only(args)
    proc = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise LabError(f"docker {' '.join(args)} failed:\n{proc.stderr.strip()}")
    return proc


def build_image() -> str:
    """Build the lab image and return its content id."""
    _docker("build", "-t", IMAGE, str(LAB_DIR))
    return _docker("image", "inspect", IMAGE, "--format", "{{.Id}}").stdout.strip()


# Hardening applied to every container we launch, matching lab/compose.yaml so the
# LIVE path is no weaker than the documented compose lab: no network, and
# no-new-privileges (the setuid bit T1548.001 sets can never be honored to escalate).
_RUN_HARDENING = ("--network", "none", "--security-opt", "no-new-privileges:true")


def _kernel() -> str:
    return _docker("run", "--rm", *_RUN_HARDENING, IMAGE, "uname", "-r").stdout.strip()


def capture_technique(technique_id: str) -> tuple[str, list[dict]]:
    """Run one technique in a FRESH throwaway container (so the whole collector log is
    that technique's scope) and return (verbatim_raw_log, parsed_events)."""
    spec = SPECS[technique_id]
    name = "redgap-cap-" + technique_id.replace(".", "_").lower()
    _docker("rm", "-f", name, check=False)
    _docker("run", "-d", "--name", name, *_RUN_HARDENING, IMAGE)
    try:
        for cmd in (*spec.commands, *spec.cleanup):
            _docker("exec", name, "sh", "-c", cmd, check=False)
        # docker cp is non-perturbing (it runs no process in the container), so reading
        # the collector log does not itself appear in the log.
        with tempfile.TemporaryDirectory() as td:
            dst = Path(td) / "exec.log"
            _docker("cp", f"{name}:{CONTAINER_LOG}", str(dst))
            raw = dst.read_text(encoding="utf-8")
    finally:
        _docker("rm", "-f", name, check=False)
    events = parse_snoopy_log(raw, run_id=f"capture-{technique_id}", technique_id=technique_id)
    return raw, events


def capture_all(captured_at: str, git_commit: str = "unknown") -> dict[str, int]:
    """Capture every technique and write fixtures/replay/<TID>/{raw,events.jsonl,provenance}."""
    image_id = build_image()
    kernel = _kernel()
    counts: dict[str, int] = {}
    for technique_id in SPECS:
        raw, events = capture_technique(technique_id)
        out = FIXTURES_DIR / technique_id
        (out / "raw").mkdir(parents=True, exist_ok=True)
        (out / "raw" / "exec.log").write_text(raw, encoding="utf-8")
        (out / "events.jsonl").write_text(
            "".join(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n" for e in events),
            encoding="utf-8",
        )
        provenance = {
            "technique_id": technique_id,
            "collector": "redgap_exec.so (LD_PRELOAD execve constructor)",
            "image": IMAGE,
            "image_id": image_id,
            "host_kernel": kernel,
            "git_commit": git_commit,
            "captured_at": captured_at,
            "commands": list(SPECS[technique_id].commands),
            "cleanup": list(SPECS[technique_id].cleanup),
            "raw_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            "event_count": len(events),
            "note": (
                "VERBATIM real capture from a live lab run. Not synthesized. "
                "Regenerate with `redgap capture` and diff the volatile-stripped events."
            ),
        }
        (out / "provenance.json").write_text(
            json.dumps(provenance, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        counts[technique_id] = len(events)
    return counts
