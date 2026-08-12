"""Fixture integrity: the committed replay fixtures are verbatim real captures, their
hashes match provenance, and each technique's real telemetry carries the artifact its
rule keys on. (Offline consistency; a LIVE re-capture in CI proves authenticity.)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from redgap.catalog import CATALOG
from redgap.telemetry.snoopy import parse_snoopy_log

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "replay"

# The real captured telemetry for each technique must contain this substring — the
# artifact the technique's rule keys on. For setuid this pins the leading-space
# invariant (' chmod u+s') the shipped SigmaHQ rule requires, on REAL telemetry.
ARTIFACT = {
    "T1087.001": "/etc/passwd",
    "T1057": "ps aux",
    "T1136.001": "/usr/sbin/useradd",
    "T1548.001": " chmod u+s",
    "T1070.006": "touch -r",
}


def _raw(tid: str) -> str:
    return (FIX / tid / "raw" / "exec.log").read_text(encoding="utf-8")


def test_raw_sha256_matches_provenance():
    for tech in CATALOG:
        prov = json.loads((FIX / tech.id / "provenance.json").read_text(encoding="utf-8"))
        got = hashlib.sha256(_raw(tech.id).encode("utf-8")).hexdigest()
        assert got == prov["raw_sha256"], tech.id


def test_every_raw_line_is_a_six_field_redgap_record():
    for tech in CATALOG:
        for line in _raw(tech.id).splitlines():
            if not line.strip():
                continue
            assert line.startswith("REDGAP\t"), (tech.id, line)
            fields = line.split("\t")
            assert len(fields) == 6, (tech.id, len(fields), line)
            assert fields[1].isdigit(), (tech.id, "pid not numeric", line)


def test_committed_events_match_a_reparse_of_the_raw():
    for tech in CATALOG:
        reparsed = parse_snoopy_log(
            _raw(tech.id), run_id=f"capture-{tech.id}", technique_id=tech.id
        )
        committed = [
            json.loads(line)
            for line in (FIX / tech.id / "events.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert reparsed == committed, tech.id


def test_real_telemetry_carries_the_detectable_artifact():
    for tech in CATALOG:
        assert ARTIFACT[tech.id] in _raw(tech.id), tech.id
    # The setuid combined line must carry BOTH substrings the shipped rule needs.
    setuid = _raw("T1548.001")
    assert "chown root" in setuid and " chmod u+s" in setuid
