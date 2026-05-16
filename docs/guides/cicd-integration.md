# CI/CD Integration

---

## GitHub Actions - reusable action

The simplest integration. Uses `action.yml` at the repo root.

```yaml
# .github/workflows/security.yml
name: Bawbel Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Bawbel scan
        uses: bawbel/scanner@v1
        with:
          path: ./skills/
          fail-on-severity: high
          format: sarif

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bawbel-results.sarif
```

### Action inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Path to scan |
| `recursive` | `true` | Scan recursively |
| `fail-on-severity` | none | Exit 2 if findings at or above: `critical`, `high`, `medium`, `low` |
| `format` | `text` | `text`, `json`, or `sarif` |
| `no-ignore` | `false` | Disable all suppressions (audit mode) |
| `version` | `latest` | Specific `bawbel-scanner` version |
| `extras` | `""` | Additional pip extras e.g. `yara,semgrep` |

---

## GitHub Actions - direct

```yaml
jobs:
  bawbel-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip

      - name: Install Bawbel Scanner
        run: pip install "bawbel-scanner[all]"

      - name: Scan
        run: |
          bawbel scan ./skills/ --recursive \
            --format sarif \
            --fail-on-severity high \
            > bawbel.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: bawbel.sarif

      # Optional: with LLM engine
      - name: Scan with LLM analysis
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: bawbel scan ./skills/ --recursive --fail-on-severity high
```

---

## GitLab CI

```yaml
bawbel-scan:
  stage: test
  image: python:3.12
  script:
    - pip install "bawbel-scanner[all]"
    - bawbel scan ./skills/ --recursive --format sarif > bawbel.sarif
    - bawbel scan ./skills/ --recursive --fail-on-severity high
  artifacts:
    reports:
      sast: bawbel.sarif
    when: always
```

---

## Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/bawbel/scanner
    rev: v1.2.0
    hooks:
      - id: bawbel-scan
```

Install and run:

```bash
pip install pre-commit
pre-commit install
pre-commit run bawbel-scan --all-files
```

The hook scans staged files. It does not block commits by default — add `--fail-on-severity high` in `args` to block on findings.

```yaml
      - id: bawbel-scan
        args: ["--fail-on-severity", "high"]
```

---

## Docker

```bash
# Build
docker build --target production -t bawbel/scanner:1.2.0 .

# Scan a local directory
docker run --rm \
  -v /path/to/skills:/scan:ro \
  bawbel/scanner:1.2.0 scan /scan --recursive \
    --format sarif > bawbel.sarif

# Fail on high
docker run --rm \
  -v /path/to/skills:/scan:ro \
  bawbel/scanner:1.2.0 scan /scan --recursive \
    --fail-on-severity high
echo "Exit: $?"
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean scan or findings below threshold |
| `1` | `bawbel report` found vulnerabilities |
| `2` | `bawbel scan --fail-on-severity` threshold breached |

---

## Suppressing false positives in CI

Add `.bawbelignore` to your repo root to suppress files by glob pattern:

```
# .bawbelignore
docs/**
tests/fixtures/**
examples/**
```

For individual lines, use inline comments:

```markdown
fetch docs from https://docs.example.com  <!-- bawbel-ignore: bawbel-external-fetch -->
```

Run with `--no-ignore` to see all findings including suppressed ones (audit mode).
