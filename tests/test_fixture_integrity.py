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
    "T1136.001": "useradd",
    "T1548.001": " chmod u+s",
    "T1070.006": "touch -r",
    "T1082": "uname",
    "T1016": "/etc/resolv.conf",
    "T1069.001": "groups",
    "T1518.001": "falcond",
    "T1083": "-name hosts",
    "T1033": "whoami",
    "T1518": "dpkg",
    "T1140": "base64",
    "T1222.002": "chattr",
    "T1070.004": "shred",
    "T1497.001": "product_name",
    "T1059": "system(",
    "T1059.004": "env /bin/sh",
    "T1059.006": "print('redgap')",
    "T1053.003": "crontab",
    "T1053.002": "at now",
    "T1548": "cap_setuid",
    "T1546.004": ".bashrc",
    "T1098.004": "authorized_keys",
    "T1552.001": "/tmp/shadow",
    "T1003.008": "getent",
    "T1552.004": "id_rsa",
    "T1560.001": "rg_loot.tgz",
    "T1005": "cat /etc/hostname",
    "T1071.001": "RedGap/1.0",
    "T1090": "http_proxy=",
    "T1567": "--upload-file",
    "T1048.003": "http.server",
    "T1485": "if=/dev/zero",
    "T1489": "redgap-nonexistent",
    "T1653": "hibernate.target",
    "T1565.001": "/etc/hosts",
    "T1592.004": "/etc/sudoers",
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
    assert set(ARTIFACT) == {t.id for t in CATALOG}, "ARTIFACT must cover every technique"
    for tid, art in ARTIFACT.items():
        assert art in _raw(tid), (tid, art)
    # The setuid combined line must carry BOTH substrings the shipped rule needs.
    setuid = _raw("T1548.001")
    assert "chown root" in setuid and " chmod u+s" in setuid
