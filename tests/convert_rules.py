"""Convert every rule for each target in pipelines/targets.yml and flag unmapped fields.

Writes one file per rule and target under the output folder; CI uploads it as the
`platform-queries` artifact. Exits non-zero if a rule fails to convert for any target, or
uses a field that no pipeline maps for that target.
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

from repo import ROOT, iter_detection_items, iter_rule_files, load_yaml, rel, resolve_pipeline, sigma_plugins, write_step_summary

# Raised by the Kusto pipelines when a field isn't a column of the target table.
INVALID_FIELD = re.compile(r"Invalid SigmaDetectionItem field name encountered: (.+?)\. Please use valid fields for the (\S+) table")


@dataclass
class Result:
    rule: str
    target: str
    problem: str | None = None
    output: str | None = None


def pick_route(rule: SigmaRule, routes: list[dict]) -> dict | None:
    for route in routes:
        when = route.get("when") or {}
        if all(getattr(rule.logsource, key, None) == value for key, value in when.items()):
            return route
    return None


def unmapped_fields(rules: list[SigmaRule], pipeline: ProcessingPipeline, fallback: set[str], original: dict[int, str]) -> list[str]:
    """Fields that no field-mapping step renamed, or that only a catch-all step renamed."""
    mapping_ids = {
        item.identifier
        for item in pipeline.items
        if item.identifier and isinstance(item.transformation, FieldMappingTransformationBase)
    }
    found: list[str] = []
    for rule in rules:
        for item in iter_detection_items(rule):
            if item.field is None:
                continue
            applied = set(item.applied_processing_items) & mapping_ids
            if applied and not applied <= fallback:
                continue
            source = original.get(id(item), item.field)
            label = source if source == item.field else f"{source} (became {item.field})"
            if label not in found:
                found.append(label)
    return found


def convert(rule_path: Path, target: str, config: dict, out_dir: Path, root: Path = ROOT) -> Result:
    result = Result(rel(rule_path, root), target)
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
        backend = sigma_plugins().backends[config["backend"]](processing_pipeline=pipeline, **(config.get("options") or {}))
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

    target_dir = out_dir / target
    target_dir.mkdir(parents=True, exist_ok=True)
    out_file = target_dir / f"{rule_path.stem}.{config.get('extension', 'txt')}"
    lines = [json.dumps(query) if isinstance(query, (dict, list)) else str(query) for query in output]
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert rules for every target and flag unmapped fields.")
    parser.add_argument("--out", type=Path, default=ROOT / "build", help="output folder (default: build/)")
    parser.add_argument("rules", nargs="*", type=Path, help="rule files to convert (default: every rule)")
    args = parser.parse_args(argv)

    results = run(out_dir=args.out.resolve(), rule_files=[path.resolve() for path in args.rules] or None)
    for result in results:
        status = "FAIL" if result.problem else "OK  "
        print(f"{status}  {result.target:8} {result.rule}  {result.problem or result.output}")
    failed = [result for result in results if result.problem]
    print(f"\n{len(results)} conversions, {len(results) - len(failed)} succeeded, {len(failed)} failed")

    summary = [f"### Conversion: {len(results) - len(failed)} of {len(results)} succeeded"]
    if failed:
        summary += ["", "| Rule | Target | Problem |", "| --- | --- | --- |"]
        summary += [f"| `{r.rule}` | {r.target} | {r.problem} |" for r in failed]
    write_step_summary("\n".join(summary))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
