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
import os
import re
import subprocess
import tempfile
from pathlib import Path

from redgap._resources import fixtures_dir, lab_dir
from redgap.allowlist import assert_lab_only
from redgap.techniques.registry import SPECS
from redgap.telemetry.snoopy import parse_snoopy_log

IMAGE = "redgap-lab:v0.1"
CONTAINER_LOG = "/var/log/redgap/exec.log"
#: A well-formed ATT&CK technique id, so a malformed id can never escape FIXTURES_DIR on write.
_VALID_TID = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
LAB_DIR = lab_dir()
FIXTURES_DIR = fixtures_dir()


class LabError(RuntimeError):
    """A docker/lab operation failed."""


# Docker CLI env vars that select the daemon. Neutralized so the argv gate in
# assert_lab_only cannot be sidestepped via the environment: DOCKER_HOST/--context could
# otherwise redirect every call to a remote/off-box engine with no argv change.
_DAEMON_ENV_VARS = ("DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")


def _local_docker_env() -> dict[str, str]:
    """A copy of the environment forced to the LOCAL default docker daemon."""
    env = {k: v for k, v in os.environ.items() if k not in _DAEMON_ENV_VARS}
    env["DOCKER_CONTEXT"] = "default"  # override any active remote context (env + config)
    return env


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    # Every docker call is gated to the LOCAL daemon two ways: assert_lab_only refuses a
    # remote-daemon argv flag or any container-creating command that is not
    # `--network none`, AND the environment is sanitized so DOCKER_HOST/DOCKER_CONTEXT
    # cannot redirect us off-box (see redgap.allowlist).
    assert_lab_only(args)
    # A bounded timeout so a wedged docker build/run/exec fails loudly instead of hanging
    # the whole capture. capture_technique's finally-block still removes the container.
    try:
        proc = subprocess.run(
            ["docker", *args],
            capture_output=True,
            encoding="utf-8",
            errors="replace",  # never crash capture on a non-UTF-8 byte in docker/technique output
            env=_local_docker_env(),
            timeout=600,
        )
    except FileNotFoundError as exc:
        raise LabError(
            "docker CLI not found on PATH; install Docker to use --live/capture"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise LabError(f"docker {' '.join(args)} timed out after {exc.timeout}s") from exc
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
    try:
        # Inside the try so the finally's `rm -f` always cleans up, even if `run -d` half-starts.
        _docker("run", "-d", "--name", name, *_RUN_HARDENING, IMAGE)
        for cmd in (*spec.commands, *spec.cleanup):
            _docker("exec", name, "sh", "-c", cmd, check=False)
        # docker cp is non-perturbing (it runs no process in the container), so reading
        # the collector log does not itself appear in the log.
        with tempfile.TemporaryDirectory() as td:
            dst = Path(td) / "exec.log"
            _docker("cp", f"{name}:{CONTAINER_LOG}", str(dst))
            # errors="replace" to match _docker's policy: a non-UTF-8 byte in a captured
            # cmdline must never crash the capture with a raw UnicodeDecodeError.
            raw = dst.read_text(encoding="utf-8", errors="replace")
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
        if not _VALID_TID.match(technique_id):
            raise LabError(
                f"refusing to write fixtures for a malformed technique id: {technique_id!r}"
            )
        raw, events = capture_technique(technique_id)
        out = FIXTURES_DIR / technique_id
        (out / "raw").mkdir(parents=True, exist_ok=True)
        (out / "raw" / "exec.log").write_text(raw, encoding="utf-8", newline="\n")
        (out / "events.jsonl").write_text(
            "".join(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n" for e in events),
            encoding="utf-8",
            newline="\n",
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
            json.dumps(provenance, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n"
        )
        counts[technique_id] = len(events)
    return counts
