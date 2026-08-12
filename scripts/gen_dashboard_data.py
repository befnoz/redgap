#!/usr/bin/env python3
"""Regenerate the embedded dashboard dataset (``docs/index.html`` #data block) in place
from the committed sample coverage — so the web heatmap/table always reflect the real run.

    python scripts/gen_dashboard_data.py     # patches docs/index.html
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INDEX = REPO / "docs" / "index.html"


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
        }
        for t in d["techniques"]
    ]
    return {"detected": d["summary"]["detected"], "gaps": d["summary"]["gaps"], "techniques": techs}


def main() -> None:
    data = {"baseline": _load("baseline"), "fixed": _load("fixed")}
    block = json.dumps(data, indent=2, ensure_ascii=False)
    html = INDEX.read_text(encoding="utf-8")
    new, n = re.subn(
        r'(<script type="application/json" id="data">)(.*?)(</script>)',
        lambda m: m.group(1) + "\n" + block + "\n" + m.group(3),
        html,
        count=1,
        flags=re.DOTALL,
    )
    if n != 1:
        raise SystemExit("could not find the #data script block in docs/index.html")
    INDEX.write_text(new, encoding="utf-8")
    print(f"patched {INDEX} with {len(data['baseline']['techniques'])} techniques")


if __name__ == "__main__":
    main()
