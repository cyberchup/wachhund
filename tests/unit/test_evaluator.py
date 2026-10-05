import json
import textwrap

import pytest

from evaluator import EvaluationError, load_events, load_rule, match_events

HEADER = """\
title: Evaluator Fixture
id: 2f9a4c1e-8b7d-4e6f-9a3b-1c5d7e9f0a2b
status: experimental
logsource:
    category: process_creation
    product: windows
"""


def matches(tmp_path, detection: str, events: list[dict], pipelines=()) -> list[bool]:
    rule_file = tmp_path / "rule.yml"
    rule_file.write_text(HEADER + "detection:\n" + textwrap.indent(textwrap.dedent(detection), "    "), encoding="utf-8")
    return match_events(load_rule(rule_file, pipelines), events)


def test_endswith_is_case_insensitive_and_matches_whole_value(tmp_path):
    detection = r"""
        selection:
            Image|endswith: '\reg.exe'
        condition: selection
    """
    events = [{"Image": r"C:\Windows\System32\REG.EXE"}, {"Image": r"C:\Windows\System32\reg.exe.bak"}, {}]
    assert matches(tmp_path, detection, events) == [True, False, False]


def test_cased_modifier_is_case_sensitive(tmp_path):
    detection = """
        selection:
            OriginalFileName|cased: 'reg.exe'
        condition: selection
    """
    assert matches(tmp_path, detection, [{"OriginalFileName": "reg.exe"}, {"OriginalFileName": "REG.EXE"}]) == [True, False]


def test_contains_all_and_windash(tmp_path):
    detection = """
        selection:
            CommandLine|contains|all:
                - 'add'
                - 'AmsiEnable'
            CommandLine|windash|contains: '-f'
        condition: selection
    """
    events = [
        {"CommandLine": "reg add HKCU\\x /v AmsiEnable /f"},
        {"CommandLine": "reg add HKCU\\x /v AmsiEnable"},
        {"CommandLine": "reg query HKCU\\x /v AmsiEnable /f"},
    ]
    assert matches(tmp_path, detection, events) == [True, False, False]


def test_selection_wildcards_filters_and_lists(tmp_path):
    detection = r"""
        selection_img:
            Image|endswith: '\cmd.exe'
        selection_parent:
            ParentImage|endswith:
                - '\winword.exe'
                - '\excel.exe'
        filter_main_signed:
            Signed: 'true'
        condition: all of selection_* and not 1 of filter_main_*
    """
    events = [
        {"Image": r"C:\Windows\System32\cmd.exe", "ParentImage": r"C:\Office\EXCEL.EXE"},
        {"Image": r"C:\Windows\System32\cmd.exe", "ParentImage": r"C:\Office\EXCEL.EXE", "Signed": "true"},
        {"Image": r"C:\Windows\System32\cmd.exe", "ParentImage": r"C:\Windows\explorer.exe"},
    ]
    assert matches(tmp_path, detection, events) == [True, False, False]


def test_regex_is_unanchored_and_case_sensitive_unless_flagged(tmp_path):
    detection = """
        selection_plain:
            Hashes|re: 'MD5=[0-9A-F]{32}'
        condition: selection_plain
    """
    md5 = "SHA1=AA,MD5=" + "A" * 32 + ",IMPHASH=BB"
    assert matches(tmp_path, detection, [{"Hashes": md5}, {"Hashes": md5.lower()}]) == [True, False]
    detection_i = """
        selection:
            Hashes|re|i: 'MD5=[0-9A-F]{32}'
        condition: selection
    """
    assert matches(tmp_path, detection_i, [{"Hashes": md5.lower()}]) == [True]


def test_numbers_cidr_and_comparisons(tmp_path):
    detection = """
        selection:
            EventID: 3
            DestinationIp|cidr: '10.0.0.0/8'
            DestinationPort|gte: 1024
        condition: selection
    """
    events = [
        {"EventID": 3, "DestinationIp": "10.1.2.3", "DestinationPort": "4444"},
        {"EventID": "3", "DestinationIp": "192.0.2.10", "DestinationPort": 4444},
        {"EventID": 3, "DestinationIp": "10.1.2.3", "DestinationPort": 443},
    ]
    assert matches(tmp_path, detection, events) == [True, False, False]


def test_exists_null_and_field_reference(tmp_path):
    detection = """
        selection_exists:
            ParentImage|exists: true
        selection_null:
            User: null
        selection_ref:
            IntegrityLevel|fieldref: ParentIntegrityLevel
        condition: all of selection_*
    """
    events = [
        {"ParentImage": "x", "IntegrityLevel": "High", "ParentIntegrityLevel": "high"},
        {"ParentImage": "x", "IntegrityLevel": "High", "ParentIntegrityLevel": "Medium"},
        {"ParentImage": "x", "User": "HAUSLAB\\labuser", "IntegrityLevel": "High", "ParentIntegrityLevel": "High"},
        {"IntegrityLevel": "High", "ParentIntegrityLevel": "High"},
    ]
    assert matches(tmp_path, detection, events) == [True, False, False, False]


def test_keywords_search_every_value(tmp_path):
    detection = """
        keywords:
            - 'mimikatz'
        condition: keywords
    """
    events = [{"a": {"b": ["x", "Invoke-Mimikatz -DumpCreds"]}}, {"a": "benign"}]
    assert matches(tmp_path, detection, events) == [True, False]


def test_list_values_match_any_element(tmp_path):
    detection = """
        selection:
            Tags: 'suspicious'
        condition: selection
    """
    assert matches(tmp_path, detection, [{"Tags": ["a", "Suspicious"]}, {"Tags": ["a", "b"]}]) == [True, False]


def test_ecs_pipeline_nested_and_flattened_documents(tmp_path):
    detection = r"""
        selection:
            Image|endswith: '\reg.exe'
            CommandLine|contains: 'AmsiEnable'
        condition: selection
    """
    nested = {"process": {"executable": r"C:\Windows\System32\reg.exe", "command_line": "reg add x /v AmsiEnable"}}
    flattened = {"process.executable": r"C:\Windows\System32\reg.exe", "process.command_line": "reg add x /v AmsiEnable"}
    sigma_native = {"Image": r"C:\Windows\System32\reg.exe", "CommandLine": "reg add x /v AmsiEnable"}
    # ecs_windows maps Image to process.executable.caseless, which only exists in the index mapping.
    assert matches(tmp_path, detection, [nested, flattened, sigma_native], ["ecs_windows"]) == [True, True, False]


def test_unresolved_placeholder_is_an_error(tmp_path):
    detection = """
        selection:
            User|expand: '%admin_users%'
        condition: selection
    """
    with pytest.raises(EvaluationError):
        matches(tmp_path, detection, [{"User": "x"}])


def test_load_events(tmp_path):
    single = tmp_path / "one.json"
    single.write_text(json.dumps({"a": 1}, indent=4), encoding="utf-8")
    lines = tmp_path / "many.jsonl"
    lines.write_text('{"a": 1}\n\n{"a": 2}\n', encoding="utf-8")
    assert load_events(single, "json") == [{"a": 1}]
    assert load_events(lines, "jsonl") == [{"a": 1}, {"a": 2}]
    with pytest.raises(EvaluationError):
        load_events(lines, "evtx")
    lines.write_text('[1, 2]\n', encoding="utf-8")
    with pytest.raises(EvaluationError):
        load_events(lines, "jsonl")
