# Rule Conventions

Sigma rules in this repo follow SigmaHQ's conventions so they stay compatible
with upstream. Items marked **Repo rule** are stricter than SigmaHQ or specific
to this repo, and win where the two differ. The hard limits in
[CLAUDE.md](CLAUDE.md) (public-repo data hygiene, what "validated" means) are
restated in [Status lifecycle](#6-status-lifecycle) and
[Public-repo hygiene](#7-public-repo-hygiene).

Checked on 2026-10-05 against Sigma specification v2.1.0, SigmaHQ's validators,
and MITRE ATT&CK v19.2 (see [Sources](#sources)). Where SigmaHQ's prose docs and
its validators disagree, this file follows the validators, because they are what
SigmaHQ's CI enforces. CI checks most of this file automatically; see
[Tests and CI](#9-tests-and-ci). The order of work, from branch to hauslab
validation, is in [WORKFLOW.md](WORKFLOW.md).

## 1. Folder layout

Rules live under `rules/<product>/<category>/`, mirroring SigmaHQ's `rules/`
tree. Before creating a folder, check whether SigmaHQ already has one for that
log source and use its name.

```text
rules/
├── windows/
│   ├── process_creation/
│   ├── image_load/, network_connection/, dns_query/, driver_load/,
│   │   pipe_created/, process_access/, create_remote_thread/,
│   │   create_stream_hash/, process_tampering/, wmi_event/, ...
│   ├── file/{file_event,file_access,file_change,file_delete,file_rename}/
│   ├── registry/{registry_set,registry_add,registry_delete,registry_event}/
│   ├── powershell/{powershell_script,powershell_module,powershell_classic}/
│   └── builtin/<service>/          # event-log channels: security/, system/, windefend/, ...
├── linux/
│   ├── process_creation/, file_event/, network_connection/
│   ├── auditd/
│   └── builtin/<service>/          # sshd/, cron/, syslog/, ...
├── macos/{process_creation,file_event}/
├── cloud/<provider>/[<service>]/   # azure/signin_logs/, azure/audit_logs/, m365/, aws/, gcp/
├── identity/<provider>/            # okta/, onelogin/, ...
├── network/<product>/              # zeek/, dns/, firewall/, ...
└── web/{proxy_generic,webserver_generic}/
```

- The folder name is the logsource `category`. Windows event-log channels go
  under `builtin/<service>/` with `-` replaced by `_` (`bits-client` →
  `bits_client/`). Some upstream service folders are shortened
  (`codeintegrity-operational` → `code_integrity/`), so copy SigmaHQ's folder
  name rather than deriving it.
- SigmaHQ keeps special-purpose rules in separate root folders. Use one only
  when a rule fits it:

| Root | For | Required tag |
| --- | --- | --- |
| `rules-threat-hunting/` (same tree as `rules/`) | Hunting queries too broad to alert on | `detection.threat-hunting` |
| `rules-emerging-threats/<year>/{Exploits,Malware,TA}/<name>/` | A specific CVE, malware family, or threat actor | `detection.emerging-threats` |
| `deprecated/<product>/...` | Rules with `status: deprecated` | none |

## 2. File names

- Lowercase `a-z`, `0-9`, and `_` only, with a `.yml` extension.
- Keep names under 70 characters (spec guidance). SigmaHQ's CI rejects names
  over 90.
- Pattern: `<prefix><subject>_<behavior>.yml`. The prefix comes from the
  logsource (tables below). After it, name the tool or behavior. Common SigmaHQ
  tokens: `susp_`, `hktl_` (hack tool), `pua_` (potentially unwanted app),
  `lolbin_`, `renamed_`, `uac_bypass_`, or the binary name (`reg_`,
  `rundll32_`, `schtasks_`, `wmic_`).
- Correlation rule files start with `correlation_`.
- Examples from SigmaHQ: `proc_access_win_lsass_memdump.yml`,
  `registry_set_add_port_monitor.yml`, `win_security_dcsync.yml`,
  `lnx_auditd_alter_bash_profile.yml`.

Prefixes are from SigmaHQ's validator data (`sigmahq_filename.json`, version
20240809). Its prose filename doc is out of date in places, e.g. `wmi_event`
and `process_tampering`.

**Windows** (`product: windows`)

| Logsource | Prefix |
| --- | --- |
| `category: process_creation` | `proc_creation_win_` |
| `category: process_access` | `proc_access_win_` |
| `category: process_tampering` | `proc_tampering_` |
| `category: create_remote_thread` | `create_remote_thread_win_` |
| `category: create_stream_hash` | `create_stream_hash_` |
| `category: image_load` | `image_load_` |
| `category: driver_load` | `driver_load_win_` |
| `category: network_connection` | `net_connection_win_` |
| `category: dns_query` | `dns_query_win_` |
| `category: pipe_created` | `pipe_created_` |
| `category: raw_access_thread` | `raw_access_thread_` |
| `category: file_event`, `file_access`, `file_change`, `file_delete`, `file_rename` | `file_event_win_`, `file_access_win_`, `file_change_win_`, `file_delete_win_`, `file_rename_win_` |
| `category: file_executable_detected` | `file_executable_detected_win_` |
| `category: registry_set`, `registry_add`, `registry_delete`, `registry_event` | `registry_set_`, `registry_add_`, `registry_delete_`, `registry_event_` |
| `category: ps_script` | `posh_ps_` |
| `category: ps_module` | `posh_pm_` |
| `category: ps_classic_start` (and other `ps_classic_*`) | `posh_pc_` |
| `category: wmi_event` | `sysmon_wmi_` |
| `service: security` | `win_security_` |
| `service: system` | `win_system_` |
| `service: windefend` | `win_defender_` |
| `service: taskscheduler` | `win_taskscheduler_` |
| `service: wmi` | `win_wmi_` |
| `service: applocker` | `win_applocker_` |
| `service: bits-client` | `win_bits_client_` |
| `service: codeintegrity-operational` | `win_codeintegrity_` |
| `service: terminalservices-localsessionmanager` | `win_terminalservices_` |
| `service: openssh` | `win_sshd_openssh_` |
| `service: msexchange-management` | `win_exchange_` |
| `service: sysmon` | `sysmon_` |
| any other `service` | `win_<service>_` (`-` → `_`) |
| no category or service | `win_` |

**Linux and macOS**

| Logsource | Prefix |
| --- | --- |
| `product: linux`, `category: process_creation` | `proc_creation_lnx_` |
| `product: linux`, `category: file_event`, `file_access`, `file_change`, `file_delete` | `file_event_lnx_`, `file_access_lnx_`, `file_change_lnx_`, `file_delete_lnx_` |
| `product: linux`, `category: network_connection` | `net_connection_lnx_` |
| `product: linux`, `service: auditd`, `auth`, `sshd`, `cron`, `syslog`, `sudo`, ... | `lnx_<service>_` |
| `product: linux`, no category or service | `lnx_` |
| `product: macos`, `category: process_creation` | `proc_creation_macos_` |
| `product: macos`, `category: file_event` | `file_event_macos_` |
| `product: macos`, anything else | `macos_` |

**Cloud, identity, and product-less categories**

| Logsource | Prefix |
| --- | --- |
| `product: azure` | `azure_` |
| `product: m365` | `microsoft365_` |
| `product: aws` | `aws_` |
| `product: gcp` | `gcp_` |
| `product: okta` | `okta_` |
| `product: github` | `github_` |
| `category: dns` | `net_dns_` |
| `category: firewall` | `net_firewall_` |
| `category: proxy` | `proxy_` |
| `category: webserver` | `web_` |
| `category: antivirus` | `av_` |

For anything not listed, use the prefix in `sigmahq_filename.json`.

## 3. Rule structure and field order

Fields appear in this order. Formatting: 4-space indentation, single-quoted
strings, UTF-8, LF line endings.

```yaml
title: Potential Example Behavior Via Example.exe   # Title Case; wording matches level
id: <random UUIDv4>
related:                                            # optional
    - id: <UUID of the related rule>
      type: derived                                 # derived | obsolete | merged | renamed | similar
status: experimental
description: Detects <behavior> by <how it is observed>. <Why it matters.>
references:
    - <public URL; GitHub links pinned to a commit>
author: <public name or handle>
date: YYYY-MM-DD
modified: YYYY-MM-DD                                # optional; only after a meaningful change
tags:
    - attack.<tactic>
    - attack.t<NNNN>.<NNN>
logsource:
    category: process_creation
    product: windows
    definition: '<optional: telemetry or audit settings the rule needs>'
detection:
    selection_img:
        Image|endswith: '\example.exe'
    selection_cli:
        CommandLine|contains: '<value>'
    filter_main_<name>:
        ParentImage: '<path>'
    condition: all of selection_* and not 1 of filter_main_*
falsepositives:
    - <Specific and capitalized; or Unknown / Unlikely>
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/<rule file name without .yml>/info.yml
simulation:
    - type: atomic-red-team
      name: <atomic test name>
      technique: T<NNNN>.<NNN>
      atomic_guid: <auto_generated_guid of the atomic>
```

- **Required by SigmaHQ:** `title`, `id`, `status`, `description`,
  `references` (when a public source exists), `author`, `date`, `tags`,
  `logsource`, `detection`, `falsepositives`, `level`.
- **Repo rule, also required:** at least one ATT&CK tactic tag and one technique
  tag, `regression_tests_path`, and `simulation`.
- `fields` (optional) goes between `detection` and `falsepositives`. It is
  rarely useful.
- Spec v2 also allows `name`, `taxonomy`, `license`, and `scope`. Don't add
  them without a reason. `name` is only needed so a correlation rule can refer
  to the rule. `license` is for rules derived from SigmaHQ (see
  [section 8](#8-rules-derived-from-sigmahq)); put it after `description`, as
  in the spec.

## 4. Field rules

### title

- Title Case. These words may stay lowercase: a, an, and, as, at, by, for,
  from, in, new, of, on, or, over, the, through, to, via, with, without. Tokens
  containing `.`, `/`, or `_` may also be lowercase (`cmd.exe`).
- 120 characters at most. Don't start with "Detect" or "Detects", and don't
  end with a period. Use keyword style, not a sentence.
- Optional structure: `Prefix - Main Title - Suffix`. The prefix names a
  category or actor (`HackTool - `, `PUA - `). The suffix tells apart the same
  logic on different log sources (`- PowerShell`, `- Security`).
- The wording must match `level`:

| Level | Title wording |
| --- | --- |
| `informational`, `low` | Neutral; doesn't imply malice (`Net.exe Execution`) |
| `medium` | `Potential ...` |
| `high` | `Suspicious ...` |
| `critical` | Names the exact threat: `Malware ...`, `Exploit ...`, `... Attempt`, `<Actor> Activity` |

### id and related

- A freshly generated random UUIDv4, lowercase. Never reuse or hand-edit an id.
- Give the rule a new id when its logic changes substantially, or when it is
  derived from or merged with other rules. Link the old ids with `related`.
- `related.type` is one of `derived`, `obsolete`, `merged`, `renamed`,
  `similar`.

### status

See [Status lifecycle](#6-status-lifecycle).

### description

- Say what the rule detects, starting with `Detects`. At least 16 characters.
- No URLs (they go in `references`) and no "internal research".
- Use `|` for multi-line text.

### references

- Public sources, when one exists. GitHub and GitLab links must be permalinks
  pinned to a commit (`/blob/<40-char sha>/...`), not branch links.
- No attack.mitre.org links. ATT&CK goes in `tags`.
- **Repo rule:** never link to anything private (tickets, internal wikis, client
  documents).

### author

A public name or handle. Separate multiple authors with commas. Keep upstream
authors on derived rules ([section 8](#8-rules-derived-from-sigmahq)).

### date and modified

- ISO format: `YYYY-MM-DD`.
- Change `modified` only when the title, detection, level, or logsource
  changes, or when status becomes `deprecated`. It must be later than `date`,
  never equal to it.

### tags

See [Tags](#5-tags).

### logsource

- Lowercase values. Use a generic `category` (`process_creation`) rather than
  a product-specific `service` (Sysmon EID 1, Security 4688). SigmaHQ's
  validators flag the specific form.
- Use `definition` to state the telemetry or audit settings the rule needs
  (for example `'Requirements: Sysmon EID 1 or Security 4688 with command-line auditing'`).

### detection

- Use Sigma taxonomy field names (`Image`, `CommandLine`, `ParentImage`,
  `TargetObject`, ...), never platform-native ones (`process.command_line`,
  `ProcessCommandLine`). Mapping to ECS or Kusto is the pipeline's job.
- **Repo rule:** if Elastic or Kusto has no mapping for a field, flag it and add
  the mapping to the repo's custom pipeline, not to the rule.
- Put a single value on the same line (`Image|endswith: '\reg.exe'`). Write two
  or more values as a list.
- Name selections so conditions can use `1 of selection_*` or
  `all of selection_*`.
- Name exclusions `filter_main_*` when the rule's logic needs them or they
  cover default OS or software behavior. Name them `filter_optional_*` when
  they cover common third-party software.
- **Repo rule:** no environment-specific exclusions (see
  [Public-repo hygiene](#7-public-repo-hygiene)).

### falsepositives

- A list. Each entry starts with a capital letter and is specific
  ("Administrators running X during Y").
- Use `Unknown` if you don't know of any, and `Unlikely` if you don't expect
  any.
- Never `None`, `Pentest`, `Penetration Test`, or `Red Team`.
- **Repo rule:** describe software and behavior in general terms, never a
  client's tools, hosts, or accounts.

### level

| Level | Meaning |
| --- | --- |
| `informational` | Enrichment only; never alerts |
| `low` | Notable but rarely an incident; for hunting and correlation |
| `medium` | Needs review; expect false positives that depend on the environment, and tuning |
| `high` | Should alert; review promptly |
| `critical` | Almost certainly an incident; review immediately |

### regression_tests_path

**Repo rule: required.** Points to the rule's test definition, in SigmaHQ's
`info.yml` format. The test folder mirrors the rule's path:

```text
rules/windows/process_creation/proc_creation_win_example.yml
regression_data/rules/windows/process_creation/proc_creation_win_example/
├── info.yml
├── <rule id>.jsonl           # true-positive events
├── <rule id>_benign.jsonl    # look-alike events that must not match
└── <rule id>_hauslab.jsonl   # sanitized hauslab capture, added when the rule is validated
```

`info.yml`:

```yaml
id: <random UUIDv4 for this file>
description: <what the samples cover>
date: YYYY-MM-DD
author: <public name or handle>
rule_metadata:
    - id: <the rule's id>
      title: <the rule's title>
regression_tests_info:
    - name: Positive Detection Test
      type: jsonl
      match_count: 1
      path: regression_data/rules/windows/process_creation/proc_creation_win_example/<rule id>.jsonl
    - name: Benign Look-alike Test
      type: jsonl
      match_count: 0
      path: regression_data/rules/windows/process_creation/proc_creation_win_example/<rule id>_benign.jsonl
validated:                    # repo extension, see section 6; only after the maintainer confirms
    - platform: elastic
      date: YYYY-MM-DD
```

- Samples are JSON Lines (one event per line), stored next to `info.yml` and
  named after the rule id: `<rule id>.jsonl` or `<rule id>_<label>.jsonl`. A
  single event may instead be `<rule id>.json` with `type: json`. EVTX samples
  aren't supported; export the events as JSON.
- Every rule needs at least one true-positive test (`match_count` of 1 or more)
  and one benign test (`match_count: 0`). `match_count` must match exactly.
  This is stricter than SigmaHQ's runner, which only warns about extra matches
  and so can't fail a benign test.
- Synthetic samples use Sigma field names (`Image`, `CommandLine`, ...) and no
  `pipelines`. A document exported from hauslab's Elastic uses ECS names, so its
  test lists the pipelines conversion uses:
  `pipelines: [pipelines/elastic.yml, ecs_windows]`.
- Sample values follow [Public-repo hygiene](#7-public-repo-hygiene).
- Tests match the way the Sigma spec defines (strings are case-insensitive), not
  the way each platform does. Elastic compares some fields case-sensitively (for
  example `process.command_line`), so passing tests doesn't prove the Elastic
  query fires. Confirming that is what hauslab validation is for.

### simulation

**Repo rule: required.** This is the Atomic Red Team reference, in SigmaHQ's
format:

```yaml
simulation:
    - type: atomic-red-team
      name: AMSI Bypass - Create AMSIEnable Reg Key
      technique: T1685
      atomic_guid: 728eca7b-0444-4f6f-ac36-437e3d751dc0
```

- `atomic_guid` is the atomic's `auto_generated_guid`, and it is the stable
  key. `technique` must be the current ATT&CK ID. Atomic Red Team renamed its
  folders for ATT&CK v19: the test above moved from `atomics/T1562.001/` to
  `atomics/T1685/` with the same GUID. Some SigmaHQ rules still show the old ID.
- `type` is always `atomic-red-team`. A few SigmaHQ rules use `atomic`; don't
  copy that.
- `name` matches the atomic's `name` exactly.
- CI checks every entry against the Atomic Red Team repo: the technique folder
  exists, the GUID is in it, and the name matches.
- If no atomic covers the behavior, raise it with the maintainer. Don't point
  at a test that only roughly matches.

## 5. Tags

Tags are lowercase `namespace.value` with no spaces.

| Namespace | Format | Example | Use here |
| --- | --- | --- | --- |
| `attack` tactic | `attack.<tactic short name>` | `attack.execution` | Required |
| `attack` technique | `attack.tNNNN` or `attack.tNNNN.NNN` | `attack.t1059.001` | Required |
| `attack` group or software | `attack.gNNNN`, `attack.sNNNN` | `attack.g0016`, `attack.s0002` | When the rule targets one group or tool |
| `cve` | `cve.YYYY-NNNNN` | `cve.2021-44228` | Exploit rules |
| `car` | `car.YYYY-MM-NNN` | `car.2016-04-005` | Optional |
| `detection` | `detection.threat-hunting`, `detection.emerging-threats`, `detection.dfir` | `detection.threat-hunting` | Exactly one in a `rules-*` root; none elsewhere |
| `stp` | Analytic score 1-5, optionally followed by event score `a`, `u`, or `k` | `stp.4`, `stp.3k` | Optional robustness score |
| `d3fend` | `d3fend.d3-<id>` | `d3fend.d3-am` | Not used |
| `tlp` | — | — | Not used: the repo is public, so everything is TLP:CLEAR |

ATT&CK tactic tags (Enterprise v19.2):

`attack.reconnaissance`, `attack.resource-development`, `attack.initial-access`,
`attack.execution`, `attack.persistence`, `attack.privilege-escalation`,
`attack.stealth`, `attack.defense-impairment`, `attack.credential-access`,
`attack.discovery`, `attack.lateral-movement`, `attack.collection`,
`attack.command-and-control`, `attack.exfiltration`, `attack.impact`

> **ATT&CK v19 removed `defense-evasion`.** TA0005 is now Stealth
> (`attack.stealth`). A new tactic, Defense Impairment (TA0112,
> `attack.defense-impairment`), was added, and some techniques got new IDs.
> For example, Disable or Modify Tools is now T1685; it was T1562.001.
> SigmaHQ has fully migrated: none of its rules use `attack.defense-evasion`
> any more. Older rules, blog posts, and generated drafts still use the
> pre-v19 tags and IDs, so check every technique on attack.mitre.org before
> tagging it. `sigma check` (pySigma 1.5.1) rejects the old tags and IDs.

Every technique tag needs the tag for every tactic ATT&CK lists under that
technique. SigmaHQ's validator flags any that are missing. For example,
`attack.t1059.001` needs `attack.execution`.

## 6. Status lifecycle

**Repo rule.** SigmaHQ starts every rule at `experimental` and promotes it by
age (to `test` after 300 days without changes). This repo promotes only on
evidence:

| Status | Meaning | Requirement |
| --- | --- | --- |
| `experimental` | Default for every new rule. It converts on both primary targets and the sample events behave as expected. **Not validated.** | None |
| `test` | Confirmed to fire in hauslab | The maintainer confirms it fired in hauslab. Then `info.yml` gets a `validated` entry (platform and date) and a test for the sanitized capture |
| `stable` | Ready for production | The maintainer decides; nothing else promotes a rule to `stable` |
| `deprecated` | Replaced or covered by another rule | Link the replacement with `related`, set `modified`, move the file to `deprecated/` |
| `unsupported` | Can't be used as written (for example, it needs fields no backend supports) | None |

- "Validated" means `test` or `stable`, nothing else. A rule that converts
  cleanly or passes its sample-event tests "converts" or "passes tests"; it is
  not "validated".
- CI enforces the gate: `test` or `stable` needs at least one `validated` entry
  in `info.yml`, and `experimental` must have none. CI can't see whether the
  rule really fired, so only add an entry after the maintainer confirms it.
- `validated.platform` names where the rule fired: `elastic`, `defender-xdr`,
  `sentinel`, `cortex-xdr`, or `sentinelone`. A validation on Elastic (what
  hauslab runs) says nothing about the Kusto query.
- Never promote automatically or by age.

## 7. Public-repo hygiene

**Repo rule.** This repo is public. These rules cover rule files, sample events,
comments, commit messages, and pull request text.

- Never include client-derived data: names, hostnames, usernames or UPNs,
  tenant or subscription IDs, internal domains or IP ranges, or
  environment-specific exclusions.
- Example values come from hauslab only: hosts such as `ws01.hauslab.local` and
  `dc01.hauslab.local`, accounts such as `labuser@hauslab.local` and
  `HAUSLAB\labuser`.
- For external values (attacker IPs, C2 domains), use reserved documentation
  values: IPs in `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`
  (RFC 5737), and domains under `example.com` (RFC 2606).
- Sanitize hauslab captures before committing. Replace SIDs, GUIDs, device IDs,
  tenant and subscription IDs, and public IPs with obviously fake values.
- Tuning for a particular environment never goes in a rule. Keep it outside
  this repo, in a private Sigma filter or a platform exception.

## 8. Rules derived from SigmaHQ

SigmaHQ rules are licensed under the Detection Rule License (DRL) 1.1, which
requires attribution. When you adapt one:

- Give it a new `id`, and add `related` with the upstream id and
  `type: derived`.
- Keep the upstream `author` value and add yours after a comma.
- Add a permalink to the upstream rule file to `references`.
- Add `license: DRL-1.1` (its SPDX ID) after `description`.
- DRL 1.1 also requires that alerts produced by the rule keep the author
  attribution, so the build must carry `author` into the converted platform
  rule.

## 9. Tests and CI

CI (`.github/workflows/ci.yml`) runs on pushes to `main` and on pull requests.
Every step runs even if an earlier one failed, so a single run reports every
problem:

| Step | Fails when |
| --- | --- |
| `pytest -q tests/unit` | the repo's own scripts misbehave |
| `yamllint --strict .` | YAML formatting breaks section 3, including CRLF line endings |
| `sigma check ... rules*` | any pySigma or SigmaHQ validator reports an issue (all validators are on, a superset of SigmaHQ's set) |
| `python tests/check_rules.py --online` | a rule breaks a **Repo rule** in this file |
| `python tests/convert_rules.py` | a rule doesn't convert for Elastic or Kusto, or uses a field no pipeline maps (Splunk problems are reported but don't fail CI) |
| `python tests/regression_tests_runner.py` | a true-positive sample doesn't match, or a benign one does |

Conversion picks each target's backend and pipelines by logsource, as set in
`pipelines/targets.yml`:

- **Elastic:** Lucene queries packaged as Elastic Security rules
  (`siem_rule_ndjson`). Windows rules go through `ecs_windows` (Winlogbeat-style
  ECS) and macOS rules through `ecs_macos_esf`. Every other product needs its
  mappings in `pipelines/elastic.yml`.
- **Kusto:** Defender XDR advanced hunting tables through `microsoft_xdr`.
  Windows Security log rules go to Sentinel's `SecurityEvent` table through
  `azure_monitor`. Sentinel ASIM isn't used: in pySigma-backend-kusto 1.0.1 its
  pipeline fails on `OriginalFileName`.
- **Splunk (best-effort):** plain SPL through `splunk_windows`, which keeps
  Sigma's field names (the Windows event field names). The queries aren't scoped
  to an index; add yours when deploying. Problems are reported in the CI summary
  but don't fail CI.
- Converted queries are uploaded as the `platform-queries` artifact:
  `elastic/*.ndjson` (importable in Kibana), `kusto/*.kql` and `splunk/*.spl`.
  They're build output and are never committed.

When conversion flags a field, add a mapping to `pipelines/elastic.yml` or
`pipelines/kusto.yml` that points at a field hauslab's data really has. Don't
rename the field in the rule; rules keep Sigma field names.

Defaults to confirm against hauslab:

- `ecs_windows` queries `.caseless` multi-fields such as
  `process.executable.caseless`. Check that hauslab's index mappings have them.
- Elastic rules use Kibana's default index patterns. To use hauslab's, set
  `options: {index_names: [...]}` under `elastic` in `pipelines/targets.yml`.

To run the same checks locally, from the repo root:

```text
python -m venv .venv
.venv\Scripts\activate          # Linux or macOS: source .venv/bin/activate
pip install -r requirements.txt
pytest -q tests/unit
yamllint --strict .
sigma check --fail-on-error --fail-on-issues --validation-config tests/sigma_cli_conf.yml rules
python tests/check_rules.py --online
python tests/convert_rules.py
python tests/regression_tests_runner.py
```

Set your editor to LF line endings. `.gitattributes` converts files on commit,
but yamllint checks the working copy.

## Sources

All checked 2026-10-05.

- Sigma rules specification v2.1.0 and tags appendix:
  <https://github.com/SigmaHQ/sigma-specification/tree/main/specification>
- SigmaHQ rule, filename, and title conventions:
  <https://github.com/SigmaHQ/sigma-specification/tree/main/sigmahq>
- SigmaHQ validators and filename-prefix data (`tools/sigmahq_filename.json`):
  <https://github.com/SigmaHQ/pySigma-validators-sigmaHQ>
- SigmaHQ regression tests (`regression_tests_path`, `info.yml`):
  <https://github.com/SigmaHQ/sigma/blob/master/regression_data/README.md>
- MITRE ATT&CK Enterprise tactics (v19.2):
  <https://attack.mitre.org/tactics/enterprise/>
- Detection Rule License 1.1:
  <https://github.com/SigmaHQ/Detection-Rule-License>
