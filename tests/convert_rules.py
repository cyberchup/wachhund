"""Convert every rule for each target in pipelines/targets.yml and flag unmapped fields.

Writes one file per rule and target under the output folder; CI uploads it as the
`platform-queries` artifact. Exits non-zero if a rule fails to convert for a required
target, uses a field that no pipeline maps for it, or uses a value form that the target
converts into a query with a different meaning. Problems with best-effort targets
(`required: false`) are reported but don't fail the run. Where tests/backends.py fixes a
backend, its class converts instead of the installed one.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.transformations.base import FieldMappingTransformationBase
from sigma.rule import SigmaRule
from sigma.types import SigmaExpansion, SigmaRegularExpression, SigmaString, SpecialChars

from backends import BACKENDS
from repo import ROOT, iter_detection_items, iter_rule_files, load_yaml, rel, resolve_pipeline, sigma_plugins, write_step_summary

# Raised by the Kusto pipelines when a field isn't a column of the target table.
INVALID_FIELD = re.compile(r"Invalid SigmaDetectionItem field name encountered: (.+?)\. Please use valid fields for the (\S+) table")

# Attribution for targets whose output is a bare query (CONVENTIONS.md, section 8).
REPO_URL = "https://github.com/cyberchup/wachhund"
REPO_LICENSE = "DRL-1.1"
DRL_URL = "https://github.com/SigmaHQ/Detection-Rule-License"


def regex(value: object) -> str | None:
    return str(value.regexp) if isinstance(value, SigmaRegularExpression) else None


def inner_wildcard(value: object) -> str | None:
    """A `?` anywhere, or a `*` that isn't part of the value's leading or trailing `*`s."""
    if not isinstance(value, SigmaString):
        return None
    parts = list(value.s)
    while parts and parts[0] is SpecialChars.WILDCARD_MULTI:
        parts.pop(0)
    while parts and parts[-1] is SpecialChars.WILDCARD_MULTI:
        parts.pop()
    return str(value) if any(isinstance(part, SpecialChars) for part in parts) else None


# Value forms that a backend converts without an error into a query with a different
# meaning (CONVENTIONS.md, section 9). Targets list the forms they get wrong in
# `unfaithful_values` in pipelines/targets.yml.
UNFAITHFUL_VALUES = {
    "regex": regex,
    "inner_wildcard": inner_wildcard,
}


@dataclass
class Result:
    rule: str
    target: str
    problem: str | None = None
    output: str | None = None
    required: bool = True


def pick_route(rule: SigmaRule, routes: list[dict]) -> dict | None:
    for route in routes:
        when = route.get("when") or {}
        if all(getattr(rule.logsource, key, None) == value for key, value in when.items()):
            return route
    return None


def unmapped_fields(rules: list[SigmaRule], pipeline: ProcessingPipeline, fallback: set[str], original: dict[int, str]) -> list[str]:
    """Fields that no field-mapping step renamed, or that only a catch-all step renamed.

    Only the rule's own detection items are checked. Conditions a pipeline adds for the
    logsource, such as ecs_windows' `winlog.channel: Security`, already use the target's
    field names.
    """
    mapping_ids = {
        item.identifier
        for item in pipeline.items
        if item.identifier and isinstance(item.transformation, FieldMappingTransformationBase)
    }
    found: list[str] = []
    for rule in rules:
        for item in iter_detection_items(rule):
            if item.field is None or id(item) not in original:
                continue
            applied = set(item.applied_processing_items) & mapping_ids
            if applied and not applied <= fallback:
                continue
            source = original.get(id(item), item.field)
            label = source if source == item.field else f"{source} (became {item.field})"
            if label not in found:
                found.append(label)
    return found


def unfaithful_values(rules: list[SigmaRule], forms: list[str], original: dict[int, str]) -> list[str]:
    """The rule's own values in a form that this target's query would match differently."""
    found: list[str] = []
    for rule in rules:
        for item in iter_detection_items(rule):
            if id(item) not in original:
                continue
            values = [v for value in item.value for v in (value.values if isinstance(value, SigmaExpansion) else [value])]
            for form in forms:
                for value in values:
                    text = UNFAITHFUL_VALUES[form](value)
                    label = f"{original[id(item)] or 'keyword'} '{text}' ({form.replace('_', ' ')})"
                    if text is not None and label not in found:
                        found.append(label)
    return found


def attribution(rule: SigmaRule, rule_path: str) -> list[str]:
    """What DRL 1.1 asks a shared rule to keep: its authors, a link to it, and its license."""
    rule_license = rule.license or REPO_LICENSE
    return [
        f"title: {rule.title}",
        f"id: {rule.id}",
        f"author: {rule.author}",
        f"license: {rule_license} ({DRL_URL})" if rule_license == "DRL-1.1" else f"license: {rule_license}",
        f"rule: {REPO_URL}/blob/main/{rule_path}",
    ]


def convert(rule_path: Path, target: str, config: dict, out_dir: Path, root: Path = ROOT) -> Result:
    result = Result(rel(rule_path, root), target, required=bool(config.get("required", True)))
    try:
        collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
    except SigmaError as error:
        result.problem = "rule doesn't parse: " + str(error).splitlines()[0]
        return result
    rules = [rule for rule in collection.rules if isinstance(rule, SigmaRule)]
    route = pick_route(rules[0], config["routes"]) if rules else None
    if route is None:
        result.problem = "no route in pipelines/targets.yml matches this rule's logsource"
        return result

    original = {id(item): item.field for rule in rules for item in iter_detection_items(rule)}
    try:
        pipeline = resolve_pipeline(route["pipelines"], config["backend"], root)
        backend_class = BACKENDS.get(config["backend"]) or sigma_plugins().backends[config["backend"]]
        backend = backend_class(processing_pipeline=pipeline, **(config.get("options") or {}))
        output = backend.convert(collection, config.get("format", "default"))
    except SigmaError as error:
        invalid = INVALID_FIELD.search(str(error))
        if invalid:
            result.problem = f"unmapped field: {invalid.group(1)} is not a column of {invalid.group(2)}"
        else:
            result.problem = "conversion failed: " + str(error).splitlines()[0]
        return result

    if config.get("require_mapped_fields"):
        unmapped = unmapped_fields(rules, backend.last_processing_pipeline, set(config.get("fallback_items") or []), original)
        if unmapped:
            result.problem = "unmapped field(s): " + ", ".join(unmapped)
            return result

    unfaithful = unfaithful_values(rules, config.get("unfaithful_values") or [], original)
    if unfaithful:
        result.problem = "query would match differently from the rule: " + ", ".join(unfaithful)
        return result

    target_dir = out_dir / target
    target_dir.mkdir(parents=True, exist_ok=True)
    out_file = target_dir / f"{rule_path.stem}.{config.get('extension', 'txt')}"
    lines = [json.dumps(query) if isinstance(query, (dict, list)) else str(query) for query in output]
    if config.get("attribution_comment"):
        notes = [config["attribution_comment"].format(line) for line in attribution(rules[0], result.rule)]
        lines = lines + notes if config.get("attribution_at") == "end" else notes + lines
    out_file.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    result.output = rel(out_file, root)
    return result


def run(root: Path = ROOT, out_dir: Path | None = None, rule_files: list[Path] | None = None) -> list[Result]:
    targets = load_yaml(root / "pipelines" / "targets.yml")
    out_dir = out_dir or root / "build"
    return [
        convert(rule_path, target, config, out_dir, root)
        for rule_path in rule_files or list(iter_rule_files(root))
        for target, config in targets.items()
    ]


def exit_code(results: list[Result]) -> int:
    """Fail only on problems with required targets."""
    return 1 if any(result.problem and result.required for result in results) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert rules for every target and flag unmapped fields.")
    parser.add_argument("--out", type=Path, default=ROOT / "build", help="output folder (default: build/)")
    parser.add_argument("rules", nargs="*", type=Path, help="rule files to convert (default: every rule)")
    args = parser.parse_args(argv)

    results = run(out_dir=args.out.resolve(), rule_files=[path.resolve() for path in args.rules] or None)
    for result in results:
        status = "OK  " if not result.problem else "FAIL" if result.required else "WARN"
        print(f"{status}  {result.target:8} {result.rule}  {result.problem or result.output}")
    failed = [result for result in results if result.problem and result.required]
    warned = [result for result in results if result.problem and not result.required]
    succeeded = len(results) - len(failed) - len(warned)
    print(f"\n{len(results)} conversions: {succeeded} succeeded, {len(failed)} failed, {len(warned)} best-effort warnings")

    summary = [f"### Conversion: {succeeded} of {len(results)} succeeded"]
    for title, problems in (("Failed (required targets)", failed), ("Best-effort warnings (don't fail CI)", warned)):
        if problems:
            summary += ["", f"**{title}**", "", "| Rule | Target | Problem |", "| --- | --- | --- |"]
            summary += [f"| `{r.rule}` | {r.target} | {r.problem} |" for r in problems]
    write_step_summary("\n".join(summary))
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
