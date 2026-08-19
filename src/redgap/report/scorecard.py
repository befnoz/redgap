"""The Bring-Your-Own-Rules rule-health scorecard.

``redgap audit --rules <DIR>`` scores a user's OWN Sigma rules against RedGap's real
captured telemetry. Coverage (``coverage.json``) answers "which techniques do your rules
catch?"; this scorecard answers the dual question "how healthy is each of your rules?" by
bucketing every loaded rule:

* **firing** - the rule matched at least one real captured event (evidence attached).
* **silent** - the rule is tagged to an in-corpus technique yet never fired on that
  technique's real telemetry. This is *false confidence*: a rule can pass static
  validation (``sigma check``) yet do nothing on real exec data - a finding that linting
  the rule text cannot produce, because it never runs the rule against real events.
* **out_of_corpus** - the rule is not tagged to any of RedGap's techniques, so there is no
  telemetry to exercise it. Reported honestly, never scored pass/fail.

Rules the engine could not evaluate (unsupported modifier / malformed / ReDoS shape) are
carried through verbatim as **unevaluable**.

Pure function of ``(loaded, excluded, verdicts, catalog)``. Every classification is a
boolean the deterministic engine already computed - no re-measurement, no language model.
"""

from __future__ import annotations

from collections.abc import Sequence

from redgap.detection.coverage import rule_covers
from redgap.detection.sigma_ast import LoadedRule
from redgap.models import Technique, Verdict
from redgap.report.markdown import _cell, _code, display_path

ExcludedRule = tuple[str, str, tuple[str, ...]]

#: firing < silent < out_of_corpus, for a stable, meaning-ordered rule listing.
_STATUS_RANK = {"firing": 0, "silent": 1, "out_of_corpus": 2}


def rule_scorecard(
    loaded: Sequence[LoadedRule],
    excluded: Sequence[ExcludedRule],
    verdicts: Sequence[Verdict],
    catalog: Sequence[Technique],
    *,
    mode: str,
    run_id: str,
    generated_at: str,
    rules_dir: str,
) -> dict:
    """Classify every loaded rule and every excluded rule. Pure reduction of the inputs."""
    vmap = {v.technique_id: v for v in verdicts}
    # Key firing on the rule's FILE PATH, not its Sigma id: two Bring-Your-Own-Rules files
    # can share an id (the duplicate_ids health warning below exists for exactly that), and
    # an id-keyed join would then mis-bucket a genuinely SILENT rule as FIRING and even
    # credit it a sibling's evidence - hiding the false confidence the scorecard exists for.
    fired_paths = {e.rule_path for v in verdicts for e in v.evidence}

    rows: list[dict] = []
    for r in loaded:
        covered = [t for t in catalog if rule_covers(r, t)]
        in_corpus = sorted(t.id for t in covered)

        fired_on: list[dict] = []
        covered_but_not_fired: list[str] = []
        silent_detail: list[dict] = []

        if not covered:
            status = "out_of_corpus"
        elif r.path in fired_paths:
            status = "firing"
            for t in covered:
                v = vmap.get(t.id)
                if v is None:
                    continue
                hits = [e for e in v.evidence if e.rule_path == r.path]
                if hits:
                    for e in hits:
                        fired_on.append(
                            {
                                "technique_id": t.id,
                                "event_id": e.event_id,
                                "matched_fields": dict(e.matched_fields),
                            }
                        )
                else:
                    covered_but_not_fired.append(t.id)
            fired_on.sort(key=lambda d: (d["technique_id"], d["event_id"]))
            covered_but_not_fired.sort()
        else:
            status = "silent"
            for t in covered:
                v = vmap.get(t.id)
                silent_detail.append(
                    {
                        "technique_id": t.id,
                        "telemetry_present": bool(v.telemetry_present) if v else False,
                    }
                )
            silent_detail.sort(key=lambda d: d["technique_id"])

        rows.append(
            {
                "id": r.id,
                "title": r.title,
                # Relativized like coverage.json's rule_path: the join above uses the
                # absolute in-memory r.path; the written artifact must not leak it.
                "path": display_path(r.path),
                "technique_ids": list(r.technique_ids),
                "status": status,
                "in_corpus_techniques": in_corpus,
                "fired_on": fired_on,
                "covered_but_not_fired": covered_but_not_fired,
                "silent_detail": silent_detail,
            }
        )

    rows.sort(key=lambda d: (_STATUS_RANK[d["status"]], d["id"], d["path"]))

    corpus_ids = {t.id for t in catalog}
    unevaluable = [
        {
            "path": display_path(path),
            "reason": reason,
            "technique_ids": list(tech_ids),
            # sub->parent aware, mirroring rule_covers: a rule tagged to a sub-technique
            # covers (and can be excluded from) its in-corpus parent.
            "targets_in_corpus": any(
                tid in corpus_ids or tid.split(".", 1)[0] in corpus_ids for tid in tech_ids
            ),
        }
        for path, reason, tech_ids in excluded
    ]
    unevaluable.sort(key=lambda d: d["path"])

    # Sigma ids are required-unique; surface any collision as a health warning.
    by_id: dict[str, list[str]] = {}
    for r in loaded:
        by_id.setdefault(r.id, []).append(r.path)
    duplicate_ids = [
        {"id": rid, "paths": sorted(paths)} for rid, paths in by_id.items() if len(paths) > 1
    ]
    duplicate_ids.sort(key=lambda d: d["id"])

    firing = sum(1 for r in rows if r["status"] == "firing")
    silent = sum(1 for r in rows if r["status"] == "silent")
    out_of_corpus = sum(1 for r in rows if r["status"] == "out_of_corpus")
    detected = sum(1 for v in verdicts if v.detected)

    return {
        "tool": "redgap",
        "artifact": "rules-scorecard",
        "mode": mode,
        "run_id": run_id,
        "generated_at": generated_at,
        "rules_dir": display_path(rules_dir),
        "corpus_size": len(catalog),
        "summary": {
            "loaded": len(loaded),
            "excluded": len(excluded),
            "firing": firing,
            "silent": silent,
            "out_of_corpus": out_of_corpus,
            "unevaluable": len(unevaluable),
            "detected": detected,
        },
        "rules": rows,
        "unevaluable": unevaluable,
        "duplicate_ids": duplicate_ids,
    }


def rule_scorecard_markdown(scorecard: dict) -> str:
    """Render the scorecard as sectioned Markdown. Our scaffolding is ASCII-only; user rule
    titles/paths are passed through ``_cell`` (pipe/newline-safe) but not ASCII-forced."""
    s = scorecard["summary"]
    out: list[str] = []
    out.append("# RedGap rule scorecard")
    out.append("")
    out.append(f"- Mode: **{scorecard['mode']}**")
    out.append(f"- Run: `{scorecard['run_id']}`")
    out.append(f"- Generated: {scorecard['generated_at']}")
    out.append(f"- Rules dir: `{_code(scorecard['rules_dir'])}`")
    out.append("")
    out.append(
        f"**{s['loaded']} rules loaded** "
        f"({s['firing']} firing, {s['silent']} SILENT, {s['out_of_corpus']} out-of-corpus) "
        f"- {s['excluded']} unevaluable - "
        f"**{s['detected']}/{scorecard['corpus_size']}** techniques detected."
    )
    out.append("")

    rows = scorecard["rules"]

    def _section(title: str, status: str, describe) -> None:
        picked = [r for r in rows if r["status"] == status]
        out.append(f"## {title} ({len(picked)})")
        out.append("")
        if not picked:
            out.append("- (none)")
            out.append("")
            return
        for r in picked:
            out.append(f"- `{_code(r['id'])}` {_cell(r['title'])} - {describe(r)}")
        out.append("")

    _section(
        "FIRING",
        "firing",
        lambda r: "fired on " + ", ".join(sorted({h["technique_id"] for h in r["fired_on"]})),
    )
    _section(
        "SILENT",
        "silent",
        lambda r: (
            "tagged to "
            + ", ".join(r["in_corpus_techniques"])
            + " but never fired on real telemetry"
        ),
    )
    _section(
        "OUT-OF-CORPUS",
        "out_of_corpus",
        lambda r: (
            "tagged to "
            + (", ".join(r["technique_ids"]) or "no ATT&CK technique")
            + " (no RedGap telemetry to exercise it)"
        ),
    )

    out.append(f"## UNEVALUABLE ({len(scorecard['unevaluable'])})")
    out.append("")
    if not scorecard["unevaluable"]:
        out.append("- (none)")
    else:
        for u in scorecard["unevaluable"]:
            flag = " [targets an in-corpus technique]" if u["targets_in_corpus"] else ""
            out.append(f"- `{_code(u['path'])}` - {_cell(u['reason'])}{flag}")
    out.append("")

    if scorecard["duplicate_ids"]:
        out.append("## Duplicate rule ids (health warning)")
        out.append("")
        for d in scorecard["duplicate_ids"]:
            out.append(f"- `{_code(d['id'])}` used by {len(d['paths'])} files")
        out.append("")

    return "\n".join(out)
