"""The deterministic Sigma evaluator — RedGap's own detection engine.

pySigma parses a rule into a boolean tree of ``ConditionItem`` nodes with typed
value leaves; this module *evaluates* that tree against a normalized event dict.
The whole detection verdict is a pure function of ``(events, rules)`` — no SIEM, no
cloud, no language model. A judge can re-run it over the saved events and reproduce
every ``detected`` bit-for-bit.

Supported Sigma subset (see SCOPE.md): ``and``/``or``/``not``, parentheses,
``1 of``/``all of``/``them``/``selection_*``; the field modifiers
``contains``/``startswith``/``endswith``/``re`` (with ``i``/``m``/``s`` flags)/``all``/
``cased``/``lt``/``lte``/``gt``/``gte``; ``*``/``?`` wildcards; keyword (value-only)
substring search; numeric and boolean values matched as case-insensitive strings
(Sigma semantics); and null. Unsupported modifiers are rejected at load time (see
:mod:`redgap.detection.sigma_ast`); any unsupported value leaf that still reaches here
raises :class:`UnsupportedFeature` rather than silently mismatching.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionIdentifier,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCompareExpression,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from redgap.detection.sigma_ast import LoadedRule
from redgap.telemetry import schema

Event = dict[str, Any]

#: An INPUT-LENGTH bound: field values longer than this many characters are treated as
#: a non-match instead of being handed to the regex engine. This bounds input size, not
#: matching time — catastrophic ``|re`` patterns are rejected separately at load
#: (see sigma_ast). Not a general ReDoS proof; see SCOPE.md.
MAX_MATCH_LEN = 64 * 1024

_SUPPORTED_VALUE_TYPES = (
    SigmaCasedString,
    SigmaString,
    SigmaBool,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaCompareExpression,
)


class UnsupportedFeature(Exception):
    """A rule uses a Sigma feature outside RedGap's documented v0.1 subset."""


@dataclass(frozen=True)
class RuleMatch:
    """Why a rule fired on an event — the hand-verifiable evidence (satisfied path only)."""

    rule_id: str
    rule_title: str
    event_id: str
    matched_fields: dict[str, str]


# --------------------------------------------------------------------------- #
# Value-leaf matching
# --------------------------------------------------------------------------- #
def _sigmastring_to_regex(value: SigmaString) -> str:
    out: list[str] = []
    for part in value.s:
        if isinstance(part, SpecialChars):
            if part == SpecialChars.WILDCARD_MULTI:
                if out and out[-1] == ".*":
                    continue  # collapse consecutive .*
                out.append(".*")
            elif part == SpecialChars.WILDCARD_SINGLE:
                out.append(".")
            else:  # pragma: no cover - defensive
                raise UnsupportedFeature(f"unknown special char {part!r}")
        else:
            out.append(re.escape(part))
    return "".join(out)


def _match_string(
    value: SigmaString, actual: str, *, whole: bool = True, ignorecase: bool = True
) -> bool:
    """Match ``actual`` against a SigmaString. ``whole`` uses fullmatch (field equality
    with wildcards); ``whole=False`` uses search (keyword substring). ``ignorecase`` is
    disabled for ``|cased`` values."""
    if len(actual) > MAX_MATCH_LEN:
        return False
    regex = _sigmastring_to_regex(value)
    flags = re.DOTALL | (re.IGNORECASE if ignorecase else 0)
    matcher = re.fullmatch if whole else re.search
    return matcher(regex, actual, flags) is not None


def _match_regex(value: SigmaRegularExpression, actual: str) -> bool:
    if len(actual) > MAX_MATCH_LEN:
        return False
    pattern = str(value.regexp)
    # sigma_to_python_flags is a class-level MAPPING (flag -> re flag), not a method.
    flag_map = getattr(value, "sigma_to_python_flags", {}) or {}
    flags = 0
    for flag in getattr(value, "flags", ()) or ():
        mapped = flag_map.get(flag)
        if mapped:
            flags |= mapped
    return re.search(pattern, actual, flags) is not None


def _match_compare(actual: Any, value: SigmaCompareExpression) -> bool:
    # A boolean is an int subclass; exclude it so it cannot coerce to 1.0/0.0 (mirrors
    # the equality path, which also refuses to let a bool over-match a number).
    if isinstance(actual, bool):
        return False
    try:
        left = float(actual)
        right = float(value.number.number)
    except (TypeError, ValueError, OverflowError):
        return False
    op = value.op.name
    if op == "LT":
        return left < right
    if op == "LTE":
        return left <= right
    if op == "GT":
        return left > right
    if op == "GTE":
        return left >= right
    raise UnsupportedFeature(f"unsupported compare op: {op}")


def _match_field(actual: Any, value: Any) -> bool:
    """Match one collected field value against one Sigma value leaf."""
    if isinstance(value, SigmaNull):
        return actual is None
    # Validate the value type BEFORE the missing-field short-circuit, so an unsupported
    # leaf on an absent field raises instead of silently mismatching.
    if not isinstance(value, _SUPPORTED_VALUE_TYPES):
        raise UnsupportedFeature(f"unsupported value type: {type(value).__name__}")
    if actual is None:
        return False
    if isinstance(actual, (list, tuple)):
        return any(_match_field(item, value) for item in actual)
    # SigmaCasedString subclasses SigmaString, so it must be checked first.
    if isinstance(value, SigmaCasedString):
        return _match_string(value, str(actual), ignorecase=False)
    if isinstance(value, SigmaString):
        return _match_string(value, str(actual))
    if isinstance(value, SigmaBool):
        # Sigma matches values as case-insensitive strings; booleans serialize as
        #'true'/'false'. No .strip(), to stay consistent with the number path.
        return str(actual).lower() == ("true" if value.boolean else "false")
    if isinstance(value, SigmaNumber):
        # Match numbers as strings too, so '  1000  ' / '1e3' / True do not over-match.
        return _match_string(SigmaString(str(value.number)), str(actual))
    if isinstance(value, SigmaRegularExpression):
        return _match_regex(value, str(actual))
    if isinstance(value, SigmaCompareExpression):
        return _match_compare(actual, value)
    raise UnsupportedFeature(f"unsupported value type: {type(value).__name__}")  # pragma: no cover


def _string_values(event: Event) -> list[str]:
    """All Sigma-visible values rendered to strings, for keyword / value-only matching
    (Sigma keyword search is full-text across the whole event, including numeric fields)."""
    vals: list[str] = []
    for key, val in event.items():
        if schema.is_internal_key(key):
            continue
        if isinstance(val, str):
            vals.append(val)
        elif isinstance(val, (list, tuple)):
            for item in val:
                if isinstance(item, str):
                    vals.append(item)
                elif isinstance(item, (int, float, bool)):
                    vals.append(str(item))
        elif isinstance(val, (int, float, bool)):
            vals.append(str(val))
    return vals


def _match_keyword(value: Any, event: Event) -> bool:
    """Keyword / value-only search: a substring match across the event's values
    (Sigma keyword semantics, values-as-strings), NOT whole-value equality."""
    strings = _string_values(event)
    if isinstance(value, SigmaCasedString):
        return any(_match_string(value, s, whole=False, ignorecase=False) for s in strings)
    if isinstance(value, SigmaString):
        return any(_match_string(value, s, whole=False) for s in strings)
    if isinstance(value, SigmaNumber):
        needle = SigmaString(str(value.number))
        return any(_match_string(needle, s, whole=False) for s in strings)
    if isinstance(value, SigmaBool):
        needle = SigmaString("true" if value.boolean else "false")
        return any(_match_string(needle, s, whole=False) for s in strings)
    return any(_match_field(s, value) for s in strings)


# --------------------------------------------------------------------------- #
# Condition-tree evaluation
# --------------------------------------------------------------------------- #
def _eval(node: Any, event: Event) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        actual = None if schema.is_internal_key(node.field) else event.get(node.field)
        return _match_field(actual, node.value)
    if isinstance(node, ConditionValueExpression):
        return _match_keyword(node.value, event)
    if isinstance(node, ConditionIdentifier):  # pragma: no cover - resolved by parse()
        raise UnsupportedFeature("unresolved selection identifier in parsed AST")
    raise UnsupportedFeature(f"unsupported condition node: {type(node).__name__}")


def _satisfied_fields(node: Any, event: Event) -> set[str]:
    """Fields on the SATISFIED path of a matching rule — the honest evidence set.

    A field under a NOT (which fires by NOT matching) or in an unsatisfied OR branch did
    not positively contribute, so it is excluded. Call only when the rule matched.
    """
    if isinstance(node, ConditionAND):
        acc: set[str] = set()
        for arg in node.args:
            acc |= _satisfied_fields(arg, event)
        return acc
    if isinstance(node, ConditionOR):
        acc = set()
        for arg in node.args:
            if _eval(arg, event):
                acc |= _satisfied_fields(arg, event)
        return acc
    if isinstance(node, ConditionNOT):
        return set()
    if isinstance(node, ConditionFieldEqualsValueExpression):
        if schema.is_internal_key(node.field):
            return set()
        return {node.field} if _match_field(event.get(node.field), node.value) else set()
    return set()  # keyword / value-only contributes no single field


def rule_matches(rule: LoadedRule, event: Event) -> RuleMatch | None:
    """Return a :class:`RuleMatch` if ``rule`` fires on ``event``, else ``None``."""
    if rule.ast is None:  # defensive; parse_rule rejects None ASTs
        raise UnsupportedFeature(f"{rule.path}: rule condition reduced to nothing")
    if not _eval(rule.ast, event):
        return None
    fields = _satisfied_fields(rule.ast, event)
    matched = {f: str(event[f]) for f in sorted(fields) if event.get(f) is not None}
    return RuleMatch(
        rule_id=rule.id,
        rule_title=rule.title,
        event_id=str(event.get(schema.EVENT_ID, "")),
        matched_fields=matched,
    )
