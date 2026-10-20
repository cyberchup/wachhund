"""Check the repository rules that `sigma check` doesn't cover (see CONVENTIONS.md).

Per rule: ATT&CK tactic and technique tags, the `simulation` entry (an Atomic Red Team
test, or a manual procedure when no atomic fits), true-positive and benign tests in
SigmaHQ's info.yml format, the status gate (`test` or `stable` needs a recorded hauslab
validation), folder placement, one-line title, author and license, and public-repo hygiene
in the rule, its info.yml and its samples. Across the repo: duplicate rule ids, test data
that no rule points to, and public-repo hygiene in pipelines/.

With --online, each Atomic Red Team entry is also checked against the Atomic Red Team repo.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

import yaml

from repo import ROOT, RULE_DIRS, iter_rule_files, load_yaml, rel, write_step_summary

TACTIC_TAG = re.compile(r"^attack\.[a-z]+(-[a-z]+)*$")
TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SAMPLE_TYPES = {".json": {"json"}, ".jsonl": {"jsonl", "ndjson"}}
PLATFORMS = {"elastic", "defender-xdr", "sentinel", "cortex-xdr", "sentinelone"}
PRODUCT_FOLDERS = {"windows", "linux", "macos"}
ART_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/{0}/{0}.yaml"
# What a `type: manual` simulation entry needs besides name and technique (CONVENTIONS.md, section 4).
MANUAL_KEYS = {"reason": "why no Atomic Red Team test fits", "steps": "how to produce the events in hauslab"}

# Rule fields the build copies into comments in the converted queries (CONVENTIONS.md, section 8).
COMMENT_FIELDS = ("title", "author", "license")

# Public-repo hygiene (CONVENTIONS.md, section 7).
ALLOWED_DOMAINS = ("hauslab.local", "example.com", "example.net", "example.org")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
INTERNAL_HOST = re.compile(r"\b((?:[A-Za-z0-9-]+\.)+(?:local|lan|corp|internal|intranet|localdomain))\b", re.IGNORECASE)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# File and product versions such as 1.0.0.0 look like IP addresses.
VERSION_KEY = re.compile(r"version", re.IGNORECASE)
# The domain or computer in front of an account: `DOMAIN\user` as a whole value, or after a
# command-line switch such as `net use ... /user:DOMAIN\user`.
QUALIFIED_USER = re.compile(r"^([^\\\s:][^\\:]*)\\[^\\]*$")
USER_SWITCH = re.compile(r"(?:^|[\s\"'])[/-]u(?:ser)?[:\s]\s*\"?([^\s\"\\/:]+)\\", re.IGNORECASE)
USER_KEY = re.compile(r"user|account", re.IGNORECASE)
DOMAIN_KEY = re.compile(r"domain", re.IGNORECASE)
# Allowed in front of an account: hauslab's domain, Windows' built-in names, and generic host
# names such as ws02 for local accounts. Environment variables such as %userdomain% also pass.
ACCOUNT_DOMAINS = {"hauslab", "nt authority", "builtin", "nt service", "window manager", "font driver host", "iis apppool", "nt virtual machine", "workgroup", "-", "."}
GENERIC_HOST = re.compile(r"[a-z]{1,4}-?\d{1,3}", re.IGNORECASE)
TENANT_KEY = re.compile(r"tenant|subscription", re.IGNORECASE)
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)


def check_rule(path: Path, root: Path, online: bool, atomics: dict) -> list[str]:
    data = load_yaml(path)
    if not isinstance(data, dict):
        return ["not a YAML mapping"]
    tags = [str(tag) for tag in data.get("tags") or []]
    problems = []
    if not any(TACTIC_TAG.match(tag) for tag in tags):
        problems.append("needs an ATT&CK tactic tag (attack.<tactic>)")
    if not any(TECHNIQUE_TAG.match(tag) for tag in tags):
        problems.append("needs an ATT&CK technique tag (attack.tNNNN or attack.tNNNN.NNN)")
    problems += check_simulation(data.get("simulation"), online, atomics)
    problems += check_folder(path, data, root)
    problems += check_tests(path, data, root)
    problems += check_comment_fields(data)
    rule_text = {key: value for key, value in data.items() if key != "references"}
    problems += [f"rule: {problem}" for problem in hygiene(rule_text, strict=False)]
    return problems


def check_comment_fields(data: dict) -> list[str]:
    """A line break or backtick would end the comment the build writes the field into."""
    return [
        f"`{field}` must be one line without backticks: the build copies it into comments in the converted queries"
        for field in COMMENT_FIELDS
        if isinstance(data.get(field), str) and ("".join(data[field].splitlines()) != data[field] or "`" in data[field])
    ]


def check_simulation(simulation: Any, online: bool, atomics: dict) -> list[str]:
    if not simulation:
        return ["needs a `simulation` entry: an Atomic Red Team test, or a manual procedure if the maintainer agrees none fits"]
    if not isinstance(simulation, list):
        return ["`simulation` must be a list"]
    problems = []
    for entry in simulation:
        entry = entry if isinstance(entry, dict) else {}
        technique, guid, name = str(entry.get("technique", "")), str(entry.get("atomic_guid", "")), entry.get("name")
        if not TECHNIQUE_ID.match(technique):
            problems.append(f"simulation: technique {technique!r} must look like T1234 or T1234.001")
        if not name:
            problems.append("simulation: `name` is required")
        if entry.get("type") == "manual":
            problems += [f"simulation: a manual entry needs `{key}` ({why})" for key, why in MANUAL_KEYS.items() if not entry.get(key)]
            continue
        if entry.get("type") != "atomic-red-team":
            problems.append("simulation: `type` must be atomic-red-team, or manual when no atomic fits")
        if not UUID.match(guid):
            problems.append(f"simulation: atomic_guid {guid!r} is not a lowercase UUID")
        if online and TECHNIQUE_ID.match(technique) and UUID.match(guid):
            problems += verify_atomic(technique, guid, name, atomics)
    return problems


def verify_atomic(technique: str, guid: str, name: Any, atomics: dict) -> list[str]:
    if technique not in atomics:
        try:
            with urllib.request.urlopen(ART_URL.format(technique), timeout=30) as response:
                tests = (yaml.safe_load(response.read()) or {}).get("atomic_tests") or []
            atomics[technique] = {str(test.get("auto_generated_guid")): test.get("name") for test in tests}
        except urllib.error.HTTPError as error:
            if error.code != 404:
                return [f"simulation: couldn't fetch Atomic Red Team {technique}: {error}"]
            atomics[technique] = None
        except urllib.error.URLError as error:
            return [f"simulation: couldn't reach Atomic Red Team to verify {technique}: {error.reason}"]
    tests = atomics[technique]
    if tests is None:
        return [f"simulation: Atomic Red Team has no atomics/{technique}/ (renumbered in ATT&CK v19?)"]
    if guid not in tests:
        return [f"simulation: atomic_guid {guid} is not in atomics/{technique}/{technique}.yaml"]
    if tests[guid] != name:
        return [f"simulation: name should be {tests[guid]!r} (the atomic's name)"]
    return []


def check_folder(path: Path, data: dict, root: Path) -> list[str]:
    product = (data.get("logsource") or {}).get("product")
    parts = path.relative_to(root).parts
    if product in PRODUCT_FOLDERS and parts[0] in RULE_DIRS and parts[1] != product:
        return [f"product {product} rules belong under {parts[0]}/{product}/"]
    return []


def check_tests(path: Path, data: dict, root: Path) -> list[str]:
    rule_id = str(data.get("id", ""))
    expected_info = Path("regression_data") / path.relative_to(root).with_suffix("") / "info.yml"
    info_path = data.get("regression_tests_path")
    if not info_path:
        return [f"needs regression_tests_path: {expected_info.as_posix()} (true-positive and benign tests)"]
    problems = []
    if Path(info_path) != expected_info:
        problems.append(f"regression_tests_path should be {expected_info.as_posix()}")
    if not (root / info_path).is_file():
        return problems + [f"regression_tests_path {info_path} doesn't exist"]

    info = load_yaml(root / info_path) or {}
    # The raw text, so comments are checked too.
    problems += [f"info.yml: {problem}" for problem in hygiene((root / info_path).read_text(encoding="utf-8"), strict=True)]
    metadata = info.get("rule_metadata") or [{}]
    if not isinstance(metadata[0], dict) or str(metadata[0].get("id")) != rule_id:
        problems.append("info.yml: rule_metadata[0].id must equal the rule id")
    tests = [test for test in info.get("regression_tests_info") or [] if isinstance(test, dict)]
    if not any(test.get("match_count") != 0 for test in tests):
        problems.append("info.yml: needs a true-positive test (match_count of 1 or more)")
    if not any(test.get("match_count") == 0 for test in tests):
        problems.append("info.yml: needs a benign test (match_count: 0)")
    for test in tests:
        problems += check_sample(test, rule_id, root / info_path, root)

    validated = info.get("validated") or []
    for entry in validated:
        entry = entry if isinstance(entry, dict) else {}
        if entry.get("platform") not in PLATFORMS:
            problems.append(f"info.yml: validated platform must be one of {', '.join(sorted(PLATFORMS))}")
        if not isinstance(entry.get("date"), datetime.date):
            problems.append("info.yml: validated date must be YYYY-MM-DD")
    status = data.get("status")
    if status in ("deprecated", "unsupported"):
        problems.append(f"status {status} rules belong under {status}/, not with active rules")
    if status in ("test", "stable") and not validated:
        problems.append(f"status {status} needs a `validated` entry in info.yml: only after the maintainer confirms it fired in hauslab")
    if status == "experimental" and validated:
        problems.append("status is experimental but info.yml records a validation; set status: test or remove the entry")
    return problems


def check_sample(test: dict, rule_id: str, info_file: Path, root: Path) -> list[str]:
    sample = Path(str(test.get("path", "")))
    label = f"info.yml: {sample.name or '<no path>'}"
    if (root / sample).parent != info_file.parent:
        return [f"{label}: samples belong next to info.yml"]
    if not (root / sample).is_file():
        return [f"{label}: file doesn't exist"]
    if sample.suffix not in SAMPLE_TYPES:
        return [f"{label}: only JSON samples are supported; export EVTX events as JSON Lines"]
    problems = []
    if not re.fullmatch(re.escape(rule_id) + r"(_[a-z0-9_]+)?\.jsonl|" + re.escape(rule_id) + r"\.json", sample.name):
        problems.append(f"{label}: name must be {rule_id}.jsonl or {rule_id}_<label>.jsonl")
    if test.get("type") not in SAMPLE_TYPES[sample.suffix]:
        problems.append(f"{label}: type {test.get('type')!r} doesn't fit a {sample.suffix} file")
    text = (root / sample).read_text(encoding="utf-8")
    try:
        if sample.suffix == ".json":
            events = [json.loads(text)]
        else:
            events = [json.loads(line) for line in text.splitlines() if line.strip()]
    except ValueError as error:
        return problems + [f"{label}: not valid JSON: {error}"]
    problems += [f"{label}: {problem}" for problem in hygiene(events, strict=True)]
    return problems


def hygiene(node: Any, strict: bool) -> list[str]:
    """Flag values that look like they came from somewhere other than hauslab.

    It catches the common shapes of client data, not every one. `strict` (for sample events,
    info.yml and pipelines) also flags public IPs and the values of domain fields, which rules
    may hold as IOCs or partial values.
    """
    problems = []
    for key, value in _strings(node):
        for domain in EMAIL.findall(value):
            if not _allowed(domain):
                problems.append(f"address at {domain!r}: use @hauslab.local or an example.com address")
        for host in INTERNAL_HOST.findall(value):
            if not _allowed(host):
                problems.append(f"internal hostname {host!r}: use a hauslab.local name")
        domains = [match.group(1) for match in USER_SWITCH.finditer(value)]
        if USER_KEY.search(key) and (match := QUALIFIED_USER.match(value)):
            domains.append(match.group(1))
        if strict and DOMAIN_KEY.search(key):
            domains.append(value)
        problems += [problem for domain in domains if (problem := _account_domain_problem(domain.strip()))]
        if TENANT_KEY.search(key):
            for guid in GUID.findall(value):
                if len(set(guid.replace("-", ""))) > 1:
                    problems.append(f"tenant or subscription ID {guid!r}: use 00000000-0000-0000-0000-000000000000")
        if strict and not VERSION_KEY.search(key):
            for text in dict.fromkeys([value.strip(), *IPV4.findall(value)]):
                try:
                    address = ipaddress.ip_address(text)
                except ValueError:
                    continue
                if address.is_global:
                    problems.append(f"public IP {text!r}: use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24")
    return list(dict.fromkeys(problems))


def _allowed(domain: str) -> bool:
    domain = domain.lower()
    return any(domain == allowed or domain.endswith("." + allowed) for allowed in ALLOWED_DOMAINS)


def _account_domain_problem(domain: str) -> str | None:
    if "." in domain.strip("."):
        return None if _allowed(domain) else f"domain {domain!r}: use hauslab.local or an example.com name"
    name = domain.lower()
    if not name or name in ACCOUNT_DOMAINS or (name.startswith("%") and name.endswith("%")) or GENERIC_HOST.fullmatch(name):
        return None
    return f"domain {domain!r}: use HAUSLAB, a built-in Windows name such as NT AUTHORITY, or a generic host name such as ws01"


def _strings(node: Any, key: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(node, dict):
        for child_key, value in node.items():
            yield from _strings(value, str(child_key))
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value, key)
    elif isinstance(node, str):
        yield key, node


def run(root: Path = ROOT, online: bool = False) -> dict[str, list[str]]:
    findings: dict[str, list[str]] = defaultdict(list)
    atomics: dict = {}
    for path in iter_rule_files(root):
        findings[rel(path, root)] += check_rule(path, root, online, atomics)

    ids = defaultdict(list)
    referenced = set()
    for folder in (*RULE_DIRS, "deprecated", "unsupported"):
        for path in sorted((root / folder).rglob("*.yml")) if (root / folder).is_dir() else []:
            data = load_yaml(path) or {}
            ids[str(data.get("id"))].append(rel(path, root))
            if data.get("regression_tests_path"):
                referenced.add(Path(data["regression_tests_path"]).as_posix())
    for rule_id, paths in ids.items():
        if len(paths) > 1:
            for path in paths:
                findings[path].append(f"duplicate id {rule_id} (also in {', '.join(p for p in paths if p != path)})")
    if (root / "regression_data").is_dir():
        for info in sorted((root / "regression_data").rglob("info.yml")):
            if rel(info, root) not in referenced:
                findings[rel(info, root)].append("no rule points to this test data (regression_tests_path)")
    for path in sorted((root / "pipelines").glob("*.yml")) if (root / "pipelines").is_dir() else []:
        findings[rel(path, root)] += hygiene(path.read_text(encoding="utf-8"), strict=True)
    return {path: problems for path, problems in findings.items() if problems}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check repository rules that sigma check doesn't cover.")
    parser.add_argument("--online", action="store_true", help="verify simulation entries against Atomic Red Team")
    args = parser.parse_args(argv)

    findings = run(online=args.online)
    for path, problems in findings.items():
        print(path)
        for problem in problems:
            print(f"    - {problem}")
    count = sum(len(problems) for problems in findings.values())
    print(f"\n{count} problem(s) in {len(findings)} file(s)" if count else "No problems found.")

    summary = [f"### Repository checks: {count} problem(s)"]
    for path, problems in findings.items():
        summary += [f"- `{path}`"] + [f"    - {problem}" for problem in problems]
    write_step_summary("\n".join(summary))
    return 1 if count else 0


if __name__ == "__main__":
    sys.exit(main())
