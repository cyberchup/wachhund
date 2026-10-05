"""Run the regression tests that rules point to with `regression_tests_path`.

info.yml follows SigmaHQ's format (regression_data/README.md in SigmaHQ/sigma). This runner
differs from SigmaHQ's in two ways:

- Events are evaluated in Python (tests/evaluator.py) rather than with evtx-sigma-checker or
  json_matcher, so the tests also run on Windows. EVTX samples aren't supported.
- `match_count` must match exactly, and `match_count: 0` marks a benign test that fails on
  any match. SigmaHQ's runner only warns when it sees more matches than expected.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from sigma.exceptions import SigmaError

from evaluator import EvaluationError, load_events, load_rule, match_events
from repo import ROOT, iter_rule_files, load_yaml, rel, write_step_summary


@dataclass
class Outcome:
    rule: str
    test: str
    passed: bool
    detail: str


def run(root: Path = ROOT, rule_files: list[Path] | None = None) -> list[Outcome]:
    outcomes = []
    for rule_path in rule_files or list(iter_rule_files(root)):
        data = load_yaml(rule_path) or {}
        info_path = data.get("regression_tests_path")
        if not info_path:
            continue  # check_rules.py reports rules without tests
        if not (root / info_path).is_file():
            outcomes.append(Outcome(rel(rule_path, root), "-", False, f"regression_tests_path not found: {info_path}"))
            continue
        tests = (load_yaml(root / info_path) or {}).get("regression_tests_info") or []
        if not tests:
            outcomes.append(Outcome(rel(rule_path, root), "-", False, f"{info_path} has no regression_tests_info"))
        for test in tests:
            outcomes.append(run_test(rule_path, test, root))
    return outcomes


def run_test(rule_path: Path, test: dict, root: Path = ROOT) -> Outcome:
    name = test.get("name", "Unnamed test")
    try:
        if test.get("filters"):
            raise EvaluationError("filters aren't supported: environment tuning stays out of this repo")
        sample = root / str(test.get("path", ""))
        if not sample.is_file():
            raise EvaluationError(f"sample not found: {test.get('path')}")
        events = load_events(sample, str(test.get("type", "")))
        rule = load_rule(rule_path, test.get("pipelines") or [], root)
        matches = match_events(rule, events)
    except (EvaluationError, SigmaError, ValueError, OSError) as error:
        return Outcome(rel(rule_path, root), name, False, f"error: {error}")

    count = sum(matches)
    expected = test.get("match_count")
    passed = count > 0 if expected is None else count == expected
    matched_lines = ", ".join(str(number) for number, hit in enumerate(matches, 1) if hit) or "none"
    expectation = "at least 1" if expected is None else str(expected)
    detail = f"{count} of {len(events)} events matched, expected {expectation} (matching lines: {matched_lines})"
    return Outcome(rel(rule_path, root), name, passed, detail)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run true-positive and benign regression tests.")
    parser.add_argument("rules", nargs="*", type=Path, help="rule files to test (default: every rule)")
    args = parser.parse_args(argv)

    outcomes = run(rule_files=[path.resolve() for path in args.rules] or None)
    for outcome in outcomes:
        print(f"{'PASS' if outcome.passed else 'FAIL'}  {outcome.rule}  [{outcome.test}]  {outcome.detail}")
    failed = [outcome for outcome in outcomes if not outcome.passed]
    print(f"\n{len(outcomes)} tests, {len(outcomes) - len(failed)} passed, {len(failed)} failed")

    summary = [f"### Regression tests: {len(outcomes) - len(failed)} of {len(outcomes)} passed"]
    if failed:
        summary += ["", "| Rule | Test | Result |", "| --- | --- | --- |"]
        summary += [f"| `{o.rule}` | {o.test} | {o.detail} |" for o in failed]
    write_step_summary("\n".join(summary))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
