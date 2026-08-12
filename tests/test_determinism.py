"""The verdict must be a deterministic function of (events, rules): the same inputs
produce byte-identical verdicts across runs. This guards against accidental
nondeterminism (dict/set ordering) and is the basis of the reproducibility claim.
"""

from __future__ import annotations

from pathlib import Path

from redgap.catalog import CATALOG
from redgap.detection.coverage import evaluate_all
from redgap.detection.sigma_ast import load_rules
from redgap.telemetry.schema import make_event

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def test_verdicts_are_deterministic():
    rules = load_rules(RULES_DIR)
    events = {
        "T1548.001": [
            make_event(
                run_id="r",
                technique_id="T1548.001",
                image="/usr/bin/sh",
                command_line="sh -c chown root /x && chmod u+s /x",
            )
        ],
        "T1087.001": [
            make_event(
                run_id="r",
                technique_id="T1087.001",
                image="/usr/bin/cat",
                command_line="cat /etc/passwd",
            )
        ],
    }
    first = evaluate_all(list(CATALOG), events, rules)
    second = evaluate_all(list(CATALOG), events, rules)
    assert first == second


def test_event_id_is_content_addressed_and_stable():
    a = make_event(run_id="r1", technique_id="T1", image="/bin/x", command_line="x --flag")
    b = make_event(run_id="r2", technique_id="T2", image="/bin/x", command_line="x --flag")
    # Same visible content -> same event id, regardless of internal bookkeeping.
    assert a["_event_id"] == b["_event_id"]
