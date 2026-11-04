# Rule template

Every wachhund rule starts from the same template, so every rule carries the same
metadata, in the same order, with tests and a way to make it fire in a lab.

| File | What it is |
| --- | --- |
| [rule.yml](rule.yml) | The Sigma rule template. Each field has a comment saying what goes in it and why |
| [info.yml](info.yml) | The rule's test definition: which sample events must match and which must not |

The template is plain Sigma (specification v2.1.0) plus two fields SigmaHQ also uses, so
it works outside this repo and for any platform Sigma converts to. See
[Using it elsewhere](#using-it-elsewhere).

## Start a rule

From the repo root:

```text
python tests/new_rule.py rules/windows/process_creation/proc_creation_win_<subject>_<behavior>.yml --title "Potential <Short Behavior> Via <Tool Name>"
```

The scaffold:

- copies both templates without their comments, so the new files hold only the rule;
- gives the rule and its `info.yml` fresh random UUIDs and today's date;
- fills in the author (`git config user.name`, or `--author`) and the title;
- fills in `logsource` when the folder names it (`rules/<windows|linux|macos>/<category>/`);
- points `regression_tests_path` at a new folder under `regression_data/` that mirrors the
  rule's path, and creates the true-positive and benign sample files there, empty;
- lists the placeholders that are left.

Then:

1. Replace every `<placeholder>`. Keep [rule.yml](rule.yml) open beside the new file; its
   comments explain each field. CI fails a rule or `info.yml` that still has one.
2. Add sample events: true positives to `<rule id>.jsonl` and near misses, such as the
   same tool doing something legitimate, to `<rule id>_benign.jsonl`. CI fails until the
   true positives match.
3. Run the checks in [CONVENTIONS.md, section 9](../CONVENTIONS.md#9-tests-and-ci), then
   open a pull request ([WORKFLOW.md](../WORKFLOW.md)).

To see a finished rule, compare the template with
[proc_creation_win_certutil_download.yml](../rules/windows/process_creation/proc_creation_win_certutil_download.yml)
and [its tests](../regression_data/rules/windows/process_creation/proc_creation_win_certutil_download/).

## What the template asks for, and why

| Field | Why it's there |
| --- | --- |
| `title` | The first thing an analyst reads. Its wording carries the level: "Potential" for medium, "Suspicious" for high |
| `id`, `related` | A stable identity that survives renames, and a record of the rules this one came from or replaces |
| `status` | `experimental` until the rule has fired in hauslab. Promotion takes evidence, never age |
| `description` | What the rule detects and why it matters, for whoever triages the alert |
| `license`, `references`, `author` | Attribution. Rules adapted from SigmaHQ keep their authors and license (Detection Rule License 1.1) |
| `tags` | ATT&CK tactics and techniques, for coverage mapping |
| `logsource` | Which telemetry the rule reads. `definition` says what has to be switched on for it to exist |
| `detection` | The logic. Named `selection_*` and `filter_*` blocks keep the condition readable; plain values keep it portable |
| `falsepositives`, `level` | What triage should expect, and how urgent an alert is |
| `regression_tests_path` | True-positive and benign events that CI runs against the rule on every pull request |
| `simulation` | The Atomic Red Team test, or written lab procedure, that makes the rule fire, for validating it |

The rules behind each field, and the reasons for them, are in
[CONVENTIONS.md](../CONVENTIONS.md).

## Using it elsewhere

The rule is the source; a platform's query is build output. A rule written from this
template doesn't change for Splunk, Elastic, Microsoft Sentinel or Defender XDR. What
changes is the backend and the processing pipeline that maps Sigma's field names to the
platform's. With [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```text
pip install sigma-cli
sigma plugin install splunk
sigma convert -t splunk -p splunk_windows rules/windows/process_creation/<rule>.yml
```

| Platform | Plugin | Target and pipeline |
| --- | --- | --- |
| Splunk | `splunk` | `-t splunk -p splunk_windows` (or `splunk_cim` for CIM data models) |
| Elastic Security | `elasticsearch` | `-t eql -p ecs_windows` |
| Defender XDR advanced hunting | `kusto` | `-t kusto -p microsoft_xdr` |
| Microsoft Sentinel | `kusto` | `-t kusto -p azure_monitor` |

`sigma list targets` and `sigma list pipelines` show the rest. In this repo,
`python tests/convert_rules.py` converts every rule for Elastic, Kusto and Splunk with the
repo's own pipelines (`pipelines/`), which also fix field mappings the built-in ones get
wrong.

Outside wachhund:

- `regression_tests_path` and `simulation` are SigmaHQ's own optional fields, so Sigma
  tools accept them. Keep them if you keep tests; delete them otherwise.
- `type: manual` simulation entries and the `validated` list in `info.yml` are this
  repo's additions. Sigma tools ignore them.
- If your platform names a field differently, map it in a processing pipeline. Don't
  rename the field in the rule, or it stops converting for everyone else.
