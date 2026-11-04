"""Tests of the rule templates in templates/ and the scaffold that copies them, tests/new_rule.py."""

import datetime
import json
import re
import shutil
from pathlib import Path

import pytest
import yaml

import check_rules
import new_rule
import regression_tests_runner
from repo import ROOT

RULE = Path("rules/windows/process_creation/proc_creation_win_hauslab_fixture_child.yml")
TEST_DIR = Path("regression_data/rules/windows/process_creation/proc_creation_win_hauslab_fixture_child")
TITLE = "Suspicious Child Process Of Hauslab Fixture Binary"
TODAY = datetime.date(2026, 10, 20)
# SigmaHQ's required fields plus the repo's (CONVENTIONS.md, section 3).
REQUIRED = {
    "title", "id", "status", "description", "references", "author", "date", "tags", "logsource",
    "detection", "falsepositives", "level", "regression_tests_path", "simulation",
}
# What a rule's author writes in place of the placeholders the scaffold leaves.
FILLED_RULE = {
    "description": "Detects a test fixture binary spawning cmd.exe. It exists only to exercise the repository tooling.\n",
    "references": ["https://example.com/fixture"],
    "tags": ["attack.execution", "attack.t1059.003"],
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {
        "selection": {"ParentImage|endswith": "\\hauslab_fixture.exe", "Image|endswith": "\\cmd.exe"},
        "condition": "selection",
    },
    "falsepositives": ["Unlikely"],
    "simulation": [{"type": "atomic-red-team", "name": "Fixture atomic", "technique": "T1059.003", "atomic_guid": "00000000-0000-4000-8000-000000000000"}],
}
TRUE_POSITIVE = {"EventID": 1, "Computer": "ws01.hauslab.local", "Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Tools\\hauslab_fixture.exe"}
BENIGN = {**TRUE_POSITIVE, "ParentImage": "C:\\Windows\\explorer.exe"}


def make_root(tmp_path: Path) -> Path:
    shutil.copytree(ROOT / "templates", tmp_path / "templates")
    return tmp_path


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_scaffold_creates_the_rule_and_its_tests(tmp_path):
    root = make_root(tmp_path)
    created = new_rule.scaffold(RULE, TITLE, "hauslab", root, TODAY)
    rule = load(root / RULE)
    rule_id = rule["id"]
    assert created == [RULE, TEST_DIR / "info.yml", TEST_DIR / f"{rule_id}.jsonl", TEST_DIR / f"{rule_id}_benign.jsonl"]
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", rule_id)
    assert (rule["title"], rule["author"], rule["date"], rule["status"]) == (TITLE, "hauslab", TODAY, "experimental")
    assert rule["logsource"]["product"] == "windows" and rule["logsource"]["category"] == "process_creation"
    assert rule["regression_tests_path"] == (TEST_DIR / "info.yml").as_posix()
    info = load(root / TEST_DIR / "info.yml")
    assert info["id"] != rule_id
    assert info["rule_metadata"] == [{"id": rule_id, "title": TITLE}]
    assert [test["path"] for test in info["regression_tests_info"]] == [(TEST_DIR / f"{rule_id}.jsonl").as_posix(), (TEST_DIR / f"{rule_id}_benign.jsonl").as_posix()]
    # The guidance stays in the templates; the new files start without it.
    assert all("#" not in (root / path).read_text(encoding="utf-8") for path in created)
    assert (root / TEST_DIR / f"{rule_id}.jsonl").read_text(encoding="utf-8") == ""


def test_scaffolded_rule_fails_until_its_placeholders_are_filled(tmp_path):
    root = make_root(tmp_path)
    new_rule.scaffold(RULE, TITLE, "hauslab", root, TODAY)
    found = [problem for problems in check_rules.run(root).values() for problem in problems]
    assert any(problem.startswith("still has template placeholders to fill in: <UUID of the related rule>, <the behavior>") for problem in found), found
    assert any(problem.startswith("info.yml: still has template placeholders to fill in: <what each true-positive event covers>") for problem in found), found

    rule = load(root / RULE)
    del rule["related"], rule["license"]
    rule.update(FILLED_RULE)
    (root / RULE).write_text(yaml.safe_dump(rule, sort_keys=False), encoding="utf-8")
    info_path = root / TEST_DIR / "info.yml"
    info = load(info_path)
    info["description"] = "Fixture tests"
    info_path.write_text(yaml.safe_dump(info, sort_keys=False), encoding="utf-8")
    (root / TEST_DIR / f"{rule['id']}.jsonl").write_text(json.dumps(TRUE_POSITIVE) + "\n", encoding="utf-8")
    (root / TEST_DIR / f"{rule['id']}_benign.jsonl").write_text(json.dumps(BENIGN) + "\n", encoding="utf-8")
    assert check_rules.run(root) == {}
    assert [o.passed for o in regression_tests_runner.run(root)] == [True, True]


def test_rules_may_hold_angle_brackets_that_arent_template_placeholders(tmp_path):
    root = make_root(tmp_path)
    placeholders = check_rules.template_placeholders(root)
    assert "<the behavior>" in placeholders and "<what it excludes>" in placeholders
    # Text such as SigmaHQ's "C:\Users\<USER>\AppData" or event 104's "The <name> log file was cleared".
    assert check_rules.check_placeholders({"description": "C:\\Users\\<USER>\\AppData: the <name> log"}, placeholders) == []


def test_logsource_is_filled_only_where_the_folder_says_it(tmp_path):
    root = make_root(tmp_path)
    new_rule.scaffold(Path("rules/windows/builtin/security/win_security_hauslab_fixture.yml"), None, None, root, TODAY)
    rule = load(root / "rules/windows/builtin/security/win_security_hauslab_fixture.yml")
    assert rule["logsource"]["category"] == "<category, such as process_creation>"
    assert (rule["title"], rule["author"]) == ("Potential <Short Behavior> Via <Tool Name>", "<public name or handle>")


@pytest.mark.parametrize(
    ("title", "expected"),
    [("Potential Example Via Example.EXE", "title: Potential Example Via Example.EXE"), ("HackTool - Example: Run", "title: 'HackTool - Example: Run'")],
)
def test_titles_stay_yaml(tmp_path, title, expected):
    root = make_root(tmp_path)
    new_rule.scaffold(RULE, title, "hauslab", root, TODAY)
    assert (root / RULE).read_text(encoding="utf-8").splitlines()[0] == expected
    assert load(root / TEST_DIR / "info.yml")["rule_metadata"][0]["title"] == title


@pytest.mark.parametrize(
    ("rule", "expected"),
    [
        ("rules/windows/process_creation/Proc-Creation.yml", "the file name must be lowercase"),
        ("templates/proc_creation_win_example.yml", "the rule must go under rules/"),
        (RULE.as_posix(), "already exists"),
    ],
)
def test_scaffold_refuses_bad_or_existing_paths(tmp_path, rule, expected):
    root = make_root(tmp_path)
    (root / RULE).parent.mkdir(parents=True)
    (root / RULE).write_text("title: Existing\n", encoding="utf-8")
    assert any(expected in problem for problem in new_rule.problems(Path(rule), root))


def test_template_follows_the_conventions_field_order():
    conventions = (ROOT / "CONVENTIONS.md").read_text(encoding="utf-8")
    section = conventions.split("## 3. Rule structure and field order")[1].split("## 4.")[0]
    block = section.split("```yaml\n")[1].split("```")[0]
    order = [line.split(":")[0] for line in block.splitlines() if re.match(r"[a-z_]+:", line)]
    template = list(load(ROOT / "templates" / "rule.yml"))
    assert template == [field for field in order if field in template]
    assert REQUIRED <= set(template)
