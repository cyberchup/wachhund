"""Start a new rule from the templates: the rule file, its info.yml and empty sample files.

    python tests/new_rule.py rules/windows/process_creation/proc_creation_win_example.yml --title "Potential Example Via Example.EXE"

Copies templates/rule.yml and templates/info.yml without their comments and fills in what
needs no judgment: fresh ids, today's date, the author (`git config user.name` unless
--author is given), the title (with --title), the test paths, and the logsource for rules
under rules/<windows|linux|macos>/<category>/. Every other <placeholder> is left for the
rule's author, and tests/check_rules.py fails a rule or info.yml that still has one.
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess
import sys
import uuid
from pathlib import Path

import yaml

from repo import ROOT, RULE_DIRS, rel

TEMPLATES = Path("templates")
FILE_NAME = re.compile(r"[a-z0-9_]+\.yml")
PRODUCT_FOLDERS = {"windows", "linux", "macos"}
PLACEHOLDER = re.compile(r"<[^<>\n]+>")


def strip_comments(text: str) -> str:
    """The template without its guidance. Its comments are whole lines, so dropping them is safe."""
    return "".join(line for line in text.splitlines(keepends=True) if line.strip() and not line.lstrip().startswith("#"))


def scalar(value: str) -> str:
    """A value as YAML text: plain when it reads back unchanged, otherwise single-quoted."""
    try:
        if yaml.safe_load(f"key: {value}") == {"key": value}:
            return value
    except yaml.YAMLError:
        pass
    return "'" + value.replace("'", "''") + "'"


def fill(text: str, values: dict[str, str]) -> str:
    for placeholder, value in values.items():
        text = text.replace(placeholder, value)
    return text


def logsource(rule: Path) -> dict[str, str]:
    """Product and category for rules*/<os>/<category>/<file>.yml. Other layouts are left to the author."""
    parts = rule.parts
    if len(parts) == 4 and parts[1] in PRODUCT_FOLDERS and parts[2] != "builtin":
        return {"<product, such as windows>": parts[1], "<category, such as process_creation>": parts[2]}
    return {}


def problems(rule: Path, root: Path) -> list[str]:
    found = []
    if rule.is_absolute() or rule.parts[0] not in RULE_DIRS:
        found.append(f"the rule must go under {', '.join(f'{name}/' for name in RULE_DIRS)} in the repo")
    if not FILE_NAME.fullmatch(rule.name):
        found.append("the file name must be lowercase a-z, 0-9 and _ with a .yml extension (CONVENTIONS.md, section 2)")
    if (root / rule).exists():
        found.append(f"{rule.as_posix()} already exists")
    if (root / "regression_data" / rule.with_suffix("")).exists():
        found.append(f"regression_data/{rule.with_suffix('').as_posix()}/ already exists")
    return found


def scaffold(rule: Path, title: str | None, author: str | None, root: Path = ROOT, today: datetime.date | None = None) -> list[Path]:
    """Write the rule, its info.yml and empty sample files; return their repo-relative paths."""
    rule_id, info_id = str(uuid.uuid4()), str(uuid.uuid4())
    test_dir = Path("regression_data") / rule.with_suffix("")
    common = {
        "<YYYY-MM-DD>": (today or datetime.date.today()).isoformat(),
        "<rule path without .yml>": rule.with_suffix("").as_posix(),
    }
    if author:
        common["<public name or handle>"] = scalar(author)
    if title:
        common["<the rule's title>"] = scalar(title)

    rule_text = fill(strip_comments((root / TEMPLATES / "rule.yml").read_text(encoding="utf-8")), {**common, "<random UUIDv4>": rule_id, **logsource(rule)})
    if title:
        rule_text = re.sub(r"^title: .*$", lambda _: f"title: {scalar(title)}", rule_text, count=1, flags=re.MULTILINE)
    info_text = fill(strip_comments((root / TEMPLATES / "info.yml").read_text(encoding="utf-8")), {**common, "<random UUIDv4>": info_id, "<the rule's id>": rule_id})

    files = {rule: rule_text, test_dir / "info.yml": info_text, test_dir / f"{rule_id}.jsonl": "", test_dir / f"{rule_id}_benign.jsonl": ""}
    for path, text in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text, encoding="utf-8", newline="\n")
    return list(files)


def git_author() -> str | None:
    try:
        name = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True, check=False).stdout.strip()
    except OSError:
        return None
    return name or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Start a new rule, with its tests, from the templates in templates/.")
    parser.add_argument("rule", type=Path, help="the new rule file, e.g. rules/windows/process_creation/proc_creation_win_example.yml")
    parser.add_argument("--title", help="the rule's title (Title Case, wording matching its level)")
    parser.add_argument("--author", help="public name or handle (default: git config user.name)")
    args = parser.parse_args(argv)

    rule = Path(rel(args.rule.resolve()))
    found = problems(rule, ROOT)
    if args.title and "".join(args.title.splitlines()) != args.title:
        found.append("the title must be one line")
    if found:
        for problem in found:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    created = scaffold(rule, args.title, args.author or git_author())
    print("Created:")
    for path in created:
        print(f"    {path.as_posix()}")
    left = list(dict.fromkeys(PLACEHOLDER.findall("".join((ROOT / path).read_text(encoding="utf-8") for path in created))))
    print("\nStill to fill in (templates/rule.yml and templates/info.yml explain each one):")
    for placeholder in left:
        print(f"    {placeholder}")
    print(
        "\nThen add true-positive and benign events to the two .jsonl files and run the checks in"
        "\nCONVENTIONS.md, section 9."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
