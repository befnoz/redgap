"""The single place RedGap touches pySigma internals (drift-isolation).

RedGap uses the official SigmaHQ ``pysigma`` library as a *parser only*: it lowers
the Sigma grammar into a plain boolean condition tree of ``ConditionItem`` nodes with
typed value leaves. RedGap's own evaluator (``engine.py``) walks that tree.

Honesty guarantees enforced here:

* **Loud exclusion, never silent mismatch.** A rule using a modifier outside RedGap's
  documented subset (``base64``, ``windash`` ...) is rejected at parse time with a
  :class:`RuleError`. The modifier scan recurses through nested selection lists so a
  modifier buried in a list-of-list cannot tunnel past it.
* **No crash takes down a run.** Condition-grammar errors, empty ``of`` patterns,
  unreadable files, and directories that match the glob are each turned into a listed
  exclusion - one bad rule never aborts the whole load.
* **Bounded matching.** A ``|re`` pattern with the classic nested-unbounded-quantifier
  ReDoS shape (e.g. ``(a+)+``) is rejected at load, so no single rule can hang the run.
  (This is a targeted static guard, not a general ReDoS proof - see SCOPE.md.)

The AST accessors are not a stability-guaranteed pySigma API, so they live behind this
one adapter and ``tests/test_sigma_ast_smoke.py`` pins the expected types. Pin:
``pysigma==1.5.0``.
"""

from __future__ import annotations

import os
import re
import warnings
from dataclasses import dataclass
from pathlib import Path

import yaml
from sigma.rule import SigmaRule
from sigma.types import SigmaRegularExpression, SigmaString, SpecialChars

_TECH_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

#: Field-modifier tokens RedGap's evaluator implements. Anything else is excluded.
SUPPORTED_MODIFIER_TOKENS = frozenset(
    {
        "contains",
        "startswith",
        "endswith",
        "all",
        "re",
        "i",
        "m",
        "s",
        "cased",
        "lt",
        "lte",
        "gt",
        "gte",
    }
)

#: Catastrophic-backtracking (ReDoS) signatures. A best-effort static blocklist - it
#: cannot be complete (a matching-time bound via re2/`regex` timeout is the roadmap, see
#: SCOPE.md), but it rejects the common shapes a Bring-Your-Own-Rules `|re` could hang on:
#: a group with an inner quantifier or alternation that is itself quantified (`(a+)+`,
#: `(a|a)+`, `(a+){2,}`), and two stacked quantified groups (`...)+...)+`). Note the
#: alternation shape is deliberately CONSERVATIVE: a quantified alternation is rejected
#: regardless of whether its branches actually overlap, because overlap is not statically
#: decidable here - so a benign `(sh|bash|zsh)+` is excluded too (a safe over-rejection).
_CATASTROPHIC_SHAPES = (
    re.compile(r"\([^()]*[*+][^()]*\)[*+{]"),
    re.compile(r"\([^()]*\|[^()]*\)[*+{]"),
    re.compile(r"\)[*+{][^)]*\)[*+{]"),
)

#: A single wildcard string value with more ``*`` than this lowers to that many greedy
#: ``.*`` segments, whose backtracking is O(n^k) on a long non-match. Real rules never
#: stack this many wildcards in one value, so a value over the cap is treated as a
#: ReDoS-prone shape and excluded at load (input length is separately capped in engine.py).
_MAX_WILDCARDS = 16


def _is_catastrophic(pattern: str) -> bool:
    return any(p.search(pattern) for p in _CATASTROPHIC_SHAPES)


class RuleError(Exception):
    """A rule file could not be loaded, is malformed, or uses an unsupported feature."""


@dataclass(frozen=True)
class LoadedRule:
    """A parsed Sigma rule plus the metadata RedGap joins and cites on."""

    id: str
    title: str
    level: str
    path: str
    technique_ids: tuple[str, ...]
    ast: object
    source: str


def _technique_ids_from_tags(rule: SigmaRule) -> tuple[str, ...]:
    ids: list[str] = []
    for tag in rule.tags:
        m = _TECH_TAG.match(str(tag))
        if m:
            ids.append(m.group(1).upper())
    return tuple(dict.fromkeys(ids))


def _tags_from_yaml(yaml_str: str) -> tuple[str, ...]:
    """Best-effort technique-id extraction from raw YAML (used for excluded rules,
    whose parse failed, so we can still tell which technique they were meant to cover)."""
    try:
        doc = yaml.safe_load(yaml_str)
    except (yaml.YAMLError, RecursionError):
        return ()
    tags = (doc or {}).get("tags", []) if isinstance(doc, dict) else []
    ids: list[str] = []
    for tag in tags or []:
        m = _TECH_TAG.match(str(tag))
        if m:
            ids.append(m.group(1).upper())
    return tuple(dict.fromkeys(ids))


def _iter_field_keys(block: object):
    """Yield every ``field|modifier`` key inside a detection selection block.

    Recurses through dicts AND nested lists so a modifier buried in a list-of-list
    cannot escape the modifier scan.
    """
    if isinstance(block, dict):
        yield from block.keys()
    elif isinstance(block, list):
        for item in block:
            yield from _iter_field_keys(item)


def _unsupported_modifiers(yaml_str: str) -> set[str]:
    try:
        doc = yaml.safe_load(yaml_str)
    except (yaml.YAMLError, RecursionError):
        return set()  # a real YAML/nesting error surfaces later via SigmaRule.from_yaml
    detection = (doc or {}).get("detection", {}) if isinstance(doc, dict) else {}
    bad: set[str] = set()
    if isinstance(detection, dict):
        for name, block in detection.items():
            if name == "condition":
                continue
            for key in _iter_field_keys(block):
                if isinstance(key, str) and "|" in key:
                    for token in key.split("|")[1:]:
                        if token.lower() not in SUPPORTED_MODIFIER_TOKENS:
                            bad.add(token.lower())
    return bad


def _unsafe_value(node: object) -> str | None:
    """First value leaf that could hang matching - a ``|re`` with a catastrophic shape or
    a wildcard string with too many ``*`` - as a human reason string, else None."""
    args = getattr(node, "args", None)
    if args:
        for arg in args:
            found = _unsafe_value(arg)
            if found is not None:
                return found
        return None
    value = getattr(node, "value", None)
    if isinstance(value, SigmaRegularExpression):
        pattern = str(value.regexp)
        if _is_catastrophic(pattern):
            return f"|re pattern {pattern!r} has a catastrophic-backtracking shape"
    elif isinstance(value, SigmaString):
        stars = sum(1 for part in value.s if part == SpecialChars.WILDCARD_MULTI)
        if stars > _MAX_WILDCARDS:
            return f"a value with {stars} '*' wildcards is a ReDoS-prone shape"
    return None


def _has_none_operand(node: object) -> bool:
    """True if any AND/OR/NOT node carries a None operand. pySigma keeps a ``1 of foo_*``
    that matched zero selections as a literal None inside the tree (it does not raise),
    so a malformed condition can load clean and only blow up at eval - this catches it."""
    args = getattr(node, "args", None)
    if args is None:
        return False
    return any(arg is None or _has_none_operand(arg) for arg in args)


def parse_rule(yaml_str: str, path: str = "<memory>") -> LoadedRule:
    """Parse one Sigma rule document into a LoadedRule, or raise :class:`RuleError`."""
    bad = _unsupported_modifiers(yaml_str)
    if bad:
        raise RuleError(
            f"{path}: unsupported Sigma modifier(s) {sorted(bad)} - outside RedGap's v0.1 "
            f"subset (see SCOPE.md); excluded rather than silently mismatched"
        )

    try:
        rule = SigmaRule.from_yaml(yaml_str)
        parsed = rule.detection.parsed_condition
        if not parsed:
            raise RuleError(f"{path}: rule has no condition")
        if len(parsed) != 1:
            raise RuleError(f"{path}: multiple conditions are not supported in v0.1")
        ast = parsed[0].parse()  # condition grammar is parsed lazily here, so wrap it
    except RuleError:
        raise
    except Exception as exc:  # noqa: BLE001 - any pySigma failure becomes a RuleError
        raise RuleError(f"{path}: failed to parse Sigma rule: {exc}") from exc

    if ast is None:
        raise RuleError(
            f"{path}: condition reduced to nothing (an 'of' pattern matched no selection?)"
        )

    # A None buried inside AND/OR/NOT (an `of` pattern that matched zero selections) loads
    # clean but raises at eval - reject it loudly here, like the whole-condition case above.
    if _has_none_operand(ast):
        raise RuleError(
            f"{path}: an 'of' pattern operand matched no selection; "
            f"excluded rather than silently mismatched"
        )

    unsafe = _unsafe_value(ast)
    if unsafe is not None:
        raise RuleError(f"{path}: {unsafe}; excluded so it cannot hang the run (see SCOPE.md)")

    return LoadedRule(
        id=str(rule.id) if rule.id else path,
        title=rule.title or "",
        level=str(rule.level.name).lower() if rule.level is not None else "",
        path=path,
        technique_ids=_technique_ids_from_tags(rule),
        ast=ast,
        source=yaml_str,
    )


def load_rules_detailed(
    root: str | Path, exclude: tuple[str, ...] = ("roundtrip",)
) -> tuple[list[LoadedRule], list[tuple[str, str, tuple[str, ...]]]]:
    """Load rules under ``root``; return (loaded, excluded).

    ``excluded`` is a list of ``(path, reason, technique_ids)`` - the technique ids are
    recovered from the raw YAML so an excluded rule is still attributable to its technique
    in the report. Both ``*.yml`` and ``*.yaml`` are loaded; order is OS-independent; any
    unreadable file or directory that matches the glob becomes an exclusion, not a crash.
    """
    root = Path(root)
    root_r = root.resolve()
    # Discover *.yml/*.yaml case-INSENSITIVELY (so .YML loads identically on Linux and
    # Windows) and WITHOUT following directory symlinks (so a Bring-Your-Own-Rules pack
    # cannot pull files from outside its tree or spin an infinite symlink-cycle glob).
    found: list[Path] = []
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            if not name.lower().endswith((".yml", ".yaml")):
                continue
            p = Path(dirpath) / name
            try:
                if not p.resolve().is_relative_to(root_r):  # a file symlink escaping root
                    continue
            except OSError:
                continue
            found.append(p)
    paths = sorted(found, key=lambda p: p.as_posix())
    rules: list[LoadedRule] = []
    excluded: list[tuple[str, str, tuple[str, ...]]] = []
    for path in paths:
        # Match the exclude tokens ONLY against components below the rules root. Testing
        # path.parts (an absolute path) would also match the drive and every ancestor
        # directory, so a checkout under e.g. .../roundtrip/redgap/ would silently drop
        # the entire ruleset and produce an all-gaps report. paths come from root.rglob,
        # so relative_to(root) is always well-defined.
        if any(part in exclude for part in path.relative_to(root).parts):
            continue
        if not path.is_file():  # rglob also matches directories named *.yml
            continue
        # A size cap before read: a real Sigma rule is a few KiB. A huge Bring-Your-Own-
        # Rules file would otherwise be slurped and parsed up to three times.
        try:
            if path.stat().st_size > 512 * 1024:
                excluded.append((str(path), "rule file too large (>512 KiB) - skipped", ()))
                continue
        except OSError:
            pass
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            warnings.warn(f"RedGap: skipping unreadable file {path}: {exc}", stacklevel=2)
            excluded.append((str(path), f"unreadable: {exc}", ()))
            continue
        try:
            rules.append(parse_rule(text, str(path)))
        except (RuleError, RecursionError) as exc:
            # A deeply-nested YAML rule can hit RecursionError deep in the parser; treat it
            # as one loud per-file exclusion, never an abort of the whole load.
            reason = str(exc) or f"{type(exc).__name__} while parsing"
            warnings.warn(f"RedGap: excluding rule {path}: {reason}", stacklevel=2)
            excluded.append((str(path), reason, _tags_from_yaml(text)))
    return rules, excluded


def load_rules(root: str | Path, exclude: tuple[str, ...] = ("roundtrip",)) -> list[LoadedRule]:
    """Load every supported rule under ``root`` (unsupported/broken rules are excluded
    with a warning; use :func:`load_rules_detailed` to see what was excluded)."""
    rules, _ = load_rules_detailed(root, exclude)
    return rules
