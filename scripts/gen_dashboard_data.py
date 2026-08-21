#!/usr/bin/env python3
"""Regenerate the embedded dashboard dataset (``docs/index.html`` #data block) in place
from the committed sample coverage - so the web heatmap/table/detail always reflect the
real run.

    python scripts/gen_dashboard_data.py     # patches docs/index.html

Each technique carries a ``detail`` block (attacker command + the REAL captured telemetry +
the firing rule and the exact fields it matched, or the gap reason) so the site's Detection
Playground shows genuine evidence, not a placeholder. Every value comes from the committed
coverage.json, the catalog, and the real fixtures - nothing is authored here.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INDEX = REPO / "docs" / "index.html"
FIX = REPO / "fixtures" / "replay"
sys.path.insert(0, str(REPO / "src"))

from redgap.techniques.catalog_data import TECHNIQUES  # noqa: E402

CMD = {t.id: (t.commands[0] if t.commands else "") for t in TECHNIQUES}
RULEFILE = {t.id: t.rule_file for t in TECHNIQUES}


def _telemetry(tid: str) -> list[dict]:
    """The real captured process-creation events for a technique (image + command line)."""
    path = FIX / tid / "events.jsonl"
    if not path.exists():
        return []
    out = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue  # one bad line degrades that technique's telemetry, never aborts the build
        out.append({"image": e.get("Image", ""), "cmd": e.get("CommandLine", "")})
    return out[:8]


def _why(t: dict) -> str:
    if t["detected"]:
        ev = t.get("evidence") or []
        fields = ", ".join((ev[0].get("matched_fields") or {}).keys()) if ev else ""
        title = ev[0].get("rule_title", "a rule") if ev else "a rule"
        on = fields or "the event"
        return f"'{title}' fired on the real captured telemetry - matched on {on}."
    if t["gap_type"] == "rule":
        return (
            "Telemetry was captured, but no shipped rule is tagged to this technique - "
            "a rule gap you can close by writing one Sigma rule."
        )
    if t["gap_type"] == "base_rate":
        return (
            "The signal is real but too common to alert on with a single-event rule - "
            "it needs correlation, not a standalone detection."
        )
    return "The collector saw no telemetry for this technique (a visibility gap)."


def _detail(t: dict) -> dict:
    ev = (t.get("evidence") or [{}])[0] if t["detected"] else {}
    return {
        "command": CMD.get(t["id"], ""),
        "telemetry": _telemetry(t["id"]),
        "rule_title": ev.get("rule_title", ""),
        "rule_id": ev.get("rule_id", ""),
        "rule_path": RULEFILE.get(t["id"], "") if t["detected"] else "",
        "matched": ev.get("matched_fields", {}),
        "why": _why(t),
    }


def _attack_path() -> dict:
    """The committed adaptive attack-path, flattened for the dashboard's kill-chain view.

    Every ``detected``/``gap_type`` is copied straight from the committed artifact (which the
    engine authored); only ``why``/``source`` are the planner's ordering rationale. Nothing is
    authored here - it mirrors docs/samples/adaptive/attack-path.json.
    """
    ap = json.loads(
        (REPO / "docs" / "samples" / "adaptive" / "attack-path.json").read_text(encoding="utf-8")
    )
    steps = [
        {
            "step": s["step"],
            "id": s["technique_id"],
            "name": s["name"],
            "tactics": s["tactics"],
            "detected": s["detected"],
            "gap_type": s["gap_type"],
            "why": s["reason"]["explanation"],
            "source": s["reason"]["source"],
        }
        for s in ap["steps"]
    ]
    return {"planner": ap["planner"], "stop": ap["stop"], "summary": ap["summary"], "steps": steps}


def _scorecard() -> dict:
    """The committed BYOR rule-health scorecard (examples/my-sigma: 1 firing / 1 SILENT /
    1 out-of-corpus), flattened for the dashboard's rule-health card. Mirrors
    docs/samples/byor/rules-scorecard.json - nothing authored here."""
    sc = json.loads(
        (REPO / "docs" / "samples" / "byor" / "rules-scorecard.json").read_text(encoding="utf-8")
    )
    rules = [
        {
            "id": r["id"],
            "title": r["title"],
            "status": r["status"],
            "technique_ids": r["technique_ids"],
            "in_corpus": r["in_corpus_techniques"],
            "fired_on": sorted({h["technique_id"] for h in r.get("fired_on", [])}),
            "silent_detail": r.get("silent_detail", []),
        }
        for r in sc["rules"]
    ]
    return {"summary": sc["summary"], "rules_dir": sc["rules_dir"], "rules": rules}


def _load(name: str) -> dict:
    d = json.loads((REPO / "docs" / "samples" / name / "coverage.json").read_text(encoding="utf-8"))
    techs = [
        {
            "id": t["id"],
            "name": t["name"],
            "tactics": t["tactics"],
            "detected": t["detected"],
            "gap_type": t["gap_type"],
            "rule": (t["firing_rules"][0] if t["firing_rules"] else ""),
            "rules": list(t.get("firing_rules", [])),
            "depth": t.get("depth", len(t.get("firing_rules", []))),
            "detail": _detail(t),
        }
        for t in d["techniques"]
    ]
    return {"detected": d["summary"]["detected"], "gaps": d["summary"]["gaps"], "techniques": techs}


def _patch_island(html: str, island_id: str, obj: dict) -> str:
    # Neutralize '<' so a value containing '</script>' can't break out of the JSON island
    # (JSON.parse decodes the < escape transparently).
    block = json.dumps(obj, indent=2, ensure_ascii=False).replace("<", "\\u003c")
    new, n = re.subn(
        r'(<script type="application/json" id="' + re.escape(island_id) + r'">)(.*?)(</script>)',
        lambda m: m.group(1) + "\n" + block + "\n" + m.group(3),
        html,
        count=1,
        flags=re.DOTALL,
    )
    if n != 1:
        raise SystemExit(f"could not find the #{island_id} script block in docs/index.html")
    return new


def main() -> None:
    data = {"baseline": _load("baseline"), "fixed": _load("fixed")}
    html = INDEX.read_text(encoding="utf-8")
    html = _patch_island(html, "data", data)
    html = _patch_island(html, "attackpath-data", _attack_path())
    html = _patch_island(html, "scorecard-data", _scorecard())
    INDEX.write_text(html, encoding="utf-8")
    print(
        f"patched {INDEX} with {len(data['baseline']['techniques'])} techniques + detail "
        f"+ {len(_attack_path()['steps'])}-step attack path"
    )


if __name__ == "__main__":
    main()
