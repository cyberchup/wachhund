# Testing a Rule

Every rule is tested twice: automated checks on every pull request, then a live run
of its Atomic Red Team test in hauslab. Work through this checklist for each rule.
The reasons behind each step are in [WORKFLOW.md](WORKFLOW.md) and
[CONVENTIONS.md](CONVENTIONS.md).

| Layer | Who | Proves | Doesn't prove |
| --- | --- | --- | --- |
| [Automated checks](#part-1-automated-checks) | Anyone; CI on every pull request | The rule follows the conventions, converts for Elastic and Kusto, and its sample events match or miss as expected | That it fires on real data |
| [Live validation](#part-2-live-validation-in-hauslab) | Maintainer, in hauslab | The Elastic rule fires on the real events the atomic produces | Anything about the Kusto query |

## Part 1: Automated checks

Do this before opening a pull request. CI repeats it on the pull request.

One-time setup, from the repo root:

```text
python -m venv .venv
.venv\Scripts\activate          # Linux or macOS: source .venv/bin/activate
pip install -r requirements.txt
```

- [ ] **Samples exist.** `info.yml` lists true-positive events (`<rule id>.jsonl`)
      and benign near misses (`<rule id>_benign.jsonl`), each with an exact
      `match_count`.
- [ ] **Repo rules pass:** `python tests/check_rules.py --online`
- [ ] **Samples behave:** `python tests/regression_tests_runner.py <path to the rule>`
- [ ] **It converts:** `python tests/convert_rules.py <path to the rule>`. An
      unmapped field gets a mapping in `pipelines/`; never rename it in the rule.
- [ ] **The queries mean what the rule means.** Read the output in `build/elastic/`
      and `build/kusto/`. Look out for wildcards in the middle of a value, which
      Kusto splits into separate, unordered `contains` checks. Also look out for
      regex, which the Elastic (Lucene) query can't run in most forms. Plain
      `contains`, `startswith` and `endswith` values convert the same on both.
- [ ] **The full CI set passes.** Before pushing, run everything CI runs:

```text
pytest -q tests/unit
yamllint --strict .
sigma check --fail-on-error --fail-on-issues --validation-config tests/sigma_cli_conf.yml rules
python tests/check_rules.py --online
python tests/convert_rules.py
python tests/regression_tests_runner.py
```

## Part 2: Live validation in hauslab

Only the maintainer runs this part and decides whether a rule fired. Anyone can
follow the same steps in their own lab to try a rule, but only a confirmed hauslab
run is recorded as validation
([CONVENTIONS.md, section 6](CONVENTIONS.md#6-status-lifecycle)).

> **Lab hosts only.** Atomics run real attacker techniques. Never run them on a
> production or personal machine.

Take `<technique>` and `<atomic_guid>` from the rule's `simulation` entry.

### Before running the atomic

- [ ] **Invoke-AtomicRedTeam is installed** on the test host
      ([setup below](#install-invoke-atomicredteam)).
- [ ] **The telemetry is there.** The rule's `logsource` and `definition` say which
      events it needs. Search Discover for recent ones from the test host, using the
      table below. With no events the rule can't fire, and that's a collection
      problem to fix first, not a rule problem.

| Rule logsource | Search in Discover |
| --- | --- |
| `category: process_creation` | `event.provider:"Microsoft-Windows-Sysmon" and event.code:1`, or `event.code:4688`, with `process.command_line` filled in |
| `service: security` | `event.code:<the rule's EventID>` on the host that logs it, often a domain controller |
| Anything else | The event type that `definition` names |

- [ ] **The fields exist.** Open one of those events and check it has the fields
      the converted query uses. Multi-fields such as `process.executable.caseless`
      only appear in the index mapping. Look for them in the data view's field list
      under Stack Management → Data Views.
- [ ] **You know what the atomic does.** Run
      `Invoke-AtomicTest <technique> -TestGuids <atomic_guid> -ShowDetails` and
      read the commands, inputs, prerequisites, cleanup, and whether it needs
      elevation, a domain-joined host or a domain controller. Watch for side effects:
      password-guessing atomics can lock accounts (check the lockout threshold),
      and some atomics change settings or leave files behind.
- [ ] **The prerequisites are met:**
      `Invoke-AtomicTest <technique> -TestGuids <atomic_guid> -CheckPrereqs`, then
      `-GetPrereqs` if anything is missing.
- [ ] **The rule is deployed.** Take `elastic/<rule>.ndjson` from the CI run's
      `platform-queries` artifact or from `build/`. Import it under Kibana →
      Security → Rules → Detection rules (SIEM) → Import rules. It arrives
      enabled as `SIGMA - <rule title>`, runs every 5 minutes, looks back 5
      minutes, and searches Kibana's default index patterns.

### Run it and check

- [ ] Note the time, then run the atomic:
      `Invoke-AtomicTest <technique> -TestGuids <atomic_guid>`
- [ ] Clean up: `Invoke-AtomicTest <technique> -TestGuids <atomic_guid> -Cleanup`.
      Remove anything the atomic left that its cleanup doesn't cover.
- [ ] Wait at least one rule interval (5 minutes) plus ingest delay. Then look in
      Security → Alerts for `SIGMA - <rule title>`.
- [ ] **It fired:** go to [Record the validation](#record-the-validation).
      **It didn't:** work through the next section.

### If it didn't fire

Check in this order:

1. **Did the event arrive?** In Discover, set the time range around the run and
   search for something distinctive from the atomic, such as part of its command
   line. No event means a collection problem.
2. **Is it in an index the rule searches?** Compare the event's `_index` with the
   rule's index patterns. To point rules at hauslab's indices, set
   `options: {index_names: [...]}` under `elastic` in `pipelines/targets.yml`.
3. **Do the field names match?** Compare the event's fields with the converted
   query. Fix a mismatch with a mapping in `pipelines/elastic.yml`, not in the rule.
4. **Do the values match, including case?** Elastic compares some fields
   case-sensitively, for example `process.command_line`.
5. **Did the rule run cleanly?** Check the Execution results tab on the rule's
   page in Kibana for errors, warnings or gaps.
6. **Was it a timing miss?** If the event was indexed after the rule had already
   searched that window, raise the rule's **Additional look-back time** for the
   test and run the atomic again.

Fix the rule or the mapping on a new branch and start again from Part 1.

### Record the validation

Do this only after the maintainer confirms the rule fired.

- [ ] Follow [WORKFLOW.md, step 9](WORKFLOW.md#9-record-the-validation). Save the
      sanitized source event as `<rule id>_hauslab.jsonl` and add a test for it.
      Add a `validated` entry (`platform: elastic` and the date), set
      `status: test`, and open a pull request.

## Kusto: Defender XDR and Sentinel

hauslab runs Elastic only, so Kusto queries are checked for conversion but never
run there. A validation on Elastic says nothing about the Kusto query. To try one:

- [ ] Run the atomic on a device that sends its events to Defender XDR or Sentinel.
- [ ] Paste `kusto/<rule>.kql` into Advanced hunting (Defender XDR) or Logs
      (Sentinel), with a time range that covers the run, and check that it returns
      the event.
- [ ] Once the maintainer confirms it, record it as its own `validated` entry with
      `platform: defender-xdr` or `platform: sentinel`.

## Install Invoke-AtomicRedTeam

Install it once per test host, in PowerShell 5 or later. This command installs the
execution framework and the atomics folder to `C:\AtomicRedTeam`:

```text
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics
```

In a new PowerShell window, import the module before using it:

```text
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

- The atomics folder holds files that antivirus flags. On the lab host, either
  exclude `C:\AtomicRedTeam` or install with `-noPayloads` and fetch each test's
  files with `-GetPrereqs`.
- For other install options, such as the PowerShell Gallery, a container, or
  Windows Sandbox, see the
  [Invoke-AtomicRedTeam wiki](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing-Invoke-AtomicRedTeam).

Kibana menu names change between versions, but the steps stay the same.
