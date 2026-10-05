# CLAUDE.md

This project is a public detection-as-code repo. Sigma rules are the single
source of truth; platform queries are build artifacts.

- **Repo:** github.com/[user]/wachhund (canonical)
- **CI:** GitHub Actions
- **Targets:** Elastic (primary, validated in hauslab) and Kusto (Defender XDR /
  Sentinel). Cortex XDR and SentinelOne are best-effort.

## For every Sigma rule you write or review

- Follow SigmaHQ naming, folder, and metadata conventions (see
  [CONVENTIONS.md](CONVENTIONS.md)).
- Include UUID, status, ATT&CK tags, false positives, and level.
- Pair it with a test: an Atomic Red Team reference plus sample true-positive
  and benign events.
- Confirm it converts on both primary targets and flag any field that needs a
  custom pipeline mapping.

## Commands

Run from the repo root; CI runs the same steps (CONVENTIONS.md, section 9):

```text
pytest -q tests/unit
yamllint --strict .
sigma check --fail-on-error --fail-on-issues --validation-config tests/sigma_cli_conf.yml rules
python tests/check_rules.py --online
python tests/convert_rules.py
python tests/regression_tests_runner.py
```

## Hard limits

- This repo is public. Never include client-derived data: names, hostnames,
  UPNs, tenant IDs, or environment-specific exclusions. Use hauslab.local
  examples only.
- Don't describe a rule as validated unless I've confirmed it fired in hauslab.
