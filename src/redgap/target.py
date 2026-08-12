"""Where events come from: a REPLAY target (committed real fixtures, the default) or a
LIVE target (a fresh capture from the Docker lab).

Both expose the same interface, so the coverage pipeline swaps between them with no
change. REPLAY is stdlib-only and offline; LIVE lazily imports the Docker driver.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Protocol, runtime_checkable

from redgap._resources import fixtures_dir
from redgap.catalog import CATALOG
from redgap.detection.engine import Event
from redgap.telemetry.snoopy import parse_snoopy_log

DEFAULT_FIXTURES = fixtures_dir()


class TargetError(RuntimeError):
    """A target could not produce telemetry."""


class FixtureError(TargetError):
    """A replay fixture is missing or fails its integrity check."""


@runtime_checkable
class Target(Protocol):
    mode: str
    run_id: str

    def events_by_technique(self) -> dict[str, list[Event]]: ...

    def provenance(self) -> dict: ...


class ReplayTarget:
    """Re-evaluate committed real-telemetry fixtures. Offline, no Docker, no key.

    The raw capture is re-parsed through the SAME parser used live (byte-parity), after
    its sha256 is checked against the recorded provenance — a tampered fixture fails
    loudly rather than silently producing a wrong verdict.
    """

    mode = "replay"

    def __init__(self, fixtures_dir: str | Path = DEFAULT_FIXTURES, run_id: str = "replay"):
        self.fixtures_dir = Path(fixtures_dir)
        self.run_id = run_id

    def events_by_technique(self) -> dict[str, list[Event]]:
        out: dict[str, list[Event]] = {}
        for tech in CATALOG:
            base = self.fixtures_dir / tech.id
            raw_path = base / "raw" / "exec.log"
            if not raw_path.exists():
                raise FixtureError(f"missing fixture for {tech.id}: {raw_path}")
            raw = raw_path.read_text(encoding="utf-8")
            # Integrity is mandatory, not best-effort. A fixture with no provenance,
            # or with an empty/absent raw_sha256, is refused rather than trusted — the
            # check fails closed so a deleted/blanked hash cannot smuggle doctored logs.
            prov_path = base / "provenance.json"
            if not prov_path.exists():
                raise FixtureError(
                    f"{tech.id}: missing provenance.json — refusing to trust an "
                    f"unverifiable fixture ({prov_path})"
                )
            want = json.loads(prov_path.read_text(encoding="utf-8")).get("raw_sha256")
            if not want:
                raise FixtureError(
                    f"{tech.id}: provenance.json has no raw_sha256 — cannot verify "
                    f"fixture integrity"
                )
            got = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            if want != got:
                raise FixtureError(
                    f"{tech.id}: raw sha256 mismatch — fixture was edited? "
                    f"expected {want}, got {got}"
                )
            out[tech.id] = parse_snoopy_log(raw, run_id=self.run_id, technique_id=tech.id)
        return out

    def provenance(self) -> dict:
        provs: dict[str, dict] = {}
        for tech in CATALOG:
            p = self.fixtures_dir / tech.id / "provenance.json"
            if p.exists():
                provs[tech.id] = json.loads(p.read_text(encoding="utf-8"))
        return {"mode": "replay", "fixtures": provs}


class LiveDockerTarget:
    """Bring up the disposable lab, run the techniques, capture fresh real telemetry.

    Requires Docker. Uses the exact same collector + parser as the committed fixtures,
    so a LIVE run and a REPLAY of a capture from it agree.
    """

    mode = "live"

    def __init__(self, run_id: str = "live"):
        self.run_id = run_id

    def events_by_technique(self) -> dict[str, list[Event]]:
        from redgap import lab  # lazy: Docker only needed for LIVE

        lab.build_image()
        out: dict[str, list[Event]] = {}
        for tech in CATALOG:
            _, events = lab.capture_technique(tech.id)
            out[tech.id] = events
        return out

    def provenance(self) -> dict:
        return {"mode": "live", "note": "fresh live capture; commit via `redgap capture`"}
