"""Evaluate Sigma rules against JSON events for the regression tests.

pySigma parses the rule and, when a test lists pipelines, applies them, so field names and
modifiers arrive exactly as pySigma hands them to every backend. This module only decides
whether each resulting value matches an event:

- Strings match the whole field value, case-insensitively unless the rule uses `cased`.
  `*` and `?` are wildcards.
- `re` is an unanchored search, as in SigmaHQ's json matcher. It is case-sensitive unless the
  rule adds the `i` flag (`|re|i`).
- A field holding a list matches if any element matches.
- A keyword (a value without a field) matches if any value anywhere in the event contains it.
- Elasticsearch multi-fields such as `process.executable.caseless` exist in the index mapping
  but not in a document's _source, so a missing `<field>.caseless` falls back to `<field>`.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Iterable, Iterator

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from repo import ROOT, resolve_pipeline

TEST_TYPES = ("json", "ndjson", "jsonl")
MULTI_FIELD_SUFFIXES = (".caseless", ".keyword", ".text")
MISSING = object()

_REGEX_FLAGS = {
    SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
    SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
    SigmaRegularExpressionFlag.DOTALL: re.DOTALL,
}
_COMPARE = {
    SigmaCompareExpression.CompareOperators.LT: lambda a, b: a < b,
    SigmaCompareExpression.CompareOperators.LTE: lambda a, b: a <= b,
    SigmaCompareExpression.CompareOperators.GT: lambda a, b: a > b,
    SigmaCompareExpression.CompareOperators.GTE: lambda a, b: a >= b,
    SigmaCompareExpression.CompareOperators.NEQ: lambda a, b: a != b,
}


class EvaluationError(Exception):
    """The rule or the test data uses something this evaluator can't decide."""


def load_events(path: Path, test_type: str) -> list[dict]:
    """Load events from a sample file: `json` is one event, `ndjson`/`jsonl` one per line."""
    if test_type not in TEST_TYPES:
        raise EvaluationError(f"unsupported test type {test_type!r} (supported: {', '.join(TEST_TYPES)})")
    text = path.read_text(encoding="utf-8")
    if test_type == "json":
        events = [json.loads(text)]
    else:
        events = [json.loads(line) for line in text.splitlines() if line.strip()]
    for number, event in enumerate(events, 1):
        if not isinstance(event, dict):
            raise EvaluationError(f"{path.name}: event {number} is not a JSON object")
    return events


def load_rule(rule_path: Path, pipelines: Iterable[str] = (), root: Path = ROOT) -> SigmaRule:
    """Parse a rule file and apply the given pipelines (names or repo-relative paths)."""
    collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
    rules = [rule for rule in collection.rules if isinstance(rule, SigmaRule)]
    if len(rules) != 1:
        raise EvaluationError(f"expected exactly one detection rule, found {len(rules)}")
    rule = rules[0]
    pipelines = list(pipelines)
    if pipelines:
        rule = resolve_pipeline(pipelines, root=root).apply(rule)
    return rule


def match_events(rule: SigmaRule, events: list[dict]) -> list[bool]:
    """Return, for each event, whether any of the rule's conditions matches it."""
    conditions = [condition.parsed for condition in rule.detection.parsed_condition]
    return [any(_evaluate(condition, event) for condition in conditions) for event in events]


def _evaluate(node: Any, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(_evaluate(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_evaluate(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _evaluate(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _match_field(event, node.field, node.value)
    if isinstance(node, ConditionValueExpression):
        return _match_keyword(event, node.value)
    raise EvaluationError(f"unsupported condition element {type(node).__name__}")


def lookup(event: Any, field: str) -> Any:
    """Find a field by dotted path, in nested objects or literal dotted keys."""
    value = _lookup(event, field.split("."))
    if value is MISSING:
        for suffix in MULTI_FIELD_SUFFIXES:
            if field.endswith(suffix):
                return lookup(event, field[: -len(suffix)])
    return value


def _lookup(node: Any, parts: list[str]) -> Any:
    if not parts:
        return node
    if isinstance(node, list):
        found = [value for value in (_lookup(item, parts) for item in node) if value is not MISSING]
        if not found:
            return MISSING
        return [element for value in found for element in (value if isinstance(value, list) else [value])]
    if not isinstance(node, dict):
        return MISSING
    for split in range(len(parts), 0, -1):  # longest key first, so "process.executable" keys win
        key = ".".join(parts[:split])
        if key in node:
            value = _lookup(node[key], parts[split:])
            if value is not MISSING:
                return value
    return MISSING


def _match_field(event: dict, field: str, value: Any) -> bool:
    if isinstance(value, SigmaExpansion):
        return any(_match_field(event, field, item) for item in value.values)
    found = lookup(event, field)
    if isinstance(value, SigmaNull):
        return found is MISSING or found is None
    if isinstance(value, SigmaExists):
        return (found is not MISSING and found is not None) == value.exists
    if found is MISSING or found is None:
        return False
    candidates = [item for item in (found if isinstance(found, list) else [found]) if item is not None]

    if isinstance(value, SigmaString):
        pattern = _string_pattern(value, cased=isinstance(value, SigmaCasedString))
        return any(pattern.fullmatch(text) for text in _texts(candidates))
    if isinstance(value, SigmaNumber):
        return any(_number(item) == value.number or _text(item) == str(value.number) for item in candidates)
    if isinstance(value, SigmaBool):
        return any(_text(item).lower() == str(value.boolean).lower() for item in candidates if _text(item) is not None)
    if isinstance(value, SigmaRegularExpression):
        flags = 0
        for flag in value.flags:
            flags |= _REGEX_FLAGS[flag]
        pattern = re.compile(str(value.regexp), flags)
        return any(pattern.search(text) for text in _texts(candidates))
    if isinstance(value, SigmaCIDRExpression):
        return any(_in_network(item, value.network) for item in candidates)
    if isinstance(value, SigmaCompareExpression):
        compare = _COMPARE[value.op]
        return any((number := _number(item)) is not None and compare(number, value.number.number) for item in candidates)
    if isinstance(value, SigmaFieldReference):
        return _match_field_reference(event, candidates, value)
    raise EvaluationError(f"field {field!r}: value type {type(value).__name__} is not supported")


def _match_field_reference(event: dict, candidates: list, value: SigmaFieldReference) -> bool:
    other = lookup(event, value.field)
    if other is MISSING or other is None:
        return False
    others = [text.lower() for text in _texts(other if isinstance(other, list) else [other])]
    for text in (text.lower() for text in _texts(candidates)):
        for reference in others:
            if value.starts_with and text.startswith(reference):
                return True
            if value.ends_with and text.endswith(reference):
                return True
            if not value.starts_with and not value.ends_with and text == reference:
                return True
    return False


def _match_keyword(event: dict, value: Any) -> bool:
    if isinstance(value, SigmaExpansion):
        return any(_match_keyword(event, item) for item in value.values)
    if not isinstance(value, SigmaString):
        raise EvaluationError(f"keyword of type {type(value).__name__} is not supported")
    pattern = _string_pattern(value, cased=isinstance(value, SigmaCasedString))
    return any(pattern.search(text) for text in _texts(_all_values(event)))


def _string_pattern(value: SigmaString, cased: bool) -> re.Pattern:
    parts = []
    for part in value.s:
        if isinstance(part, str):
            parts.append(re.escape(part))
        elif part == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            raise EvaluationError(f"unresolved placeholder in {value!r}; add a pipeline that fills it in")
    return re.compile("".join(parts), re.DOTALL if cased else re.DOTALL | re.IGNORECASE)


def _all_values(node: Any) -> Iterator[Any]:
    if isinstance(node, dict):
        for item in node.values():
            yield from _all_values(item)
    elif isinstance(node, list):
        for item in node:
            yield from _all_values(item)
    elif node is not None:
        yield node


def _text(item: Any) -> str | None:
    if isinstance(item, bool):
        return "true" if item else "false"
    if isinstance(item, (str, int, float)):
        return str(item)
    return None


def _texts(items: Iterable[Any]) -> Iterator[str]:
    for item in items:
        text = _text(item)
        if text is not None:
            yield text


def _number(item: Any) -> int | float | None:
    if isinstance(item, bool):
        return None
    if isinstance(item, (int, float)):
        return item
    if isinstance(item, str):
        try:
            return int(item)
        except ValueError:
            try:
                return float(item)
            except ValueError:
                return None
    return None


def _in_network(item: Any, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        return ipaddress.ip_address(str(item)) in network
    except ValueError:
        return False
