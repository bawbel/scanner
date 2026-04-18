# CI/CD Integration — Bawbel Scanner

Bawbel Scanner integrates with every major CI/CD platform.
All integrations are in [bawbel-integrations](https://github.com/bawbel/bawbel-integrations).

---

## Exit Codes

All integrations use consistent exit codes:

| Code | Meaning | CI/CD behaviour |
|---|---|---|
| `0` | Clean — no findings | Pipeline passes |
| `1` | Findings below threshold | Pipeline passes (configurable) |
| `2` | Findings at or above `--fail-on-severity` | **Pipeline fails** |

---

## GitHub Actions

```yaml
# .github/workflows/scan-skills.yml
name: Scan AI Components

on:
  push:
    paths: ['**.md', '**/mcp*.json']
  pull_request:

jobs:
  bawbel-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install Bawbel Scanner
        run: pip install bawbel-scanner

      - name: Scan AI components
        run: bawbel scan . --recursive --fail-on-severity high --format sarif --output bawbel.sarif

      - name: Upload results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: bawbel.sarif
```

---

## GitLab CI

```yaml
# .gitlab-ci.yml
bawbel-scan:
  image: python:3.12-slim
  stage: test
  script:
    - pip install bawbel-scanner
    - bawbel scan . --recursive --fail-on-severity high --format sarif --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

---

## Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Scan AI Components') {
            steps {
                sh 'pip install bawbel-scanner'
                sh 'bawbel scan . --recursive --fail-on-severity high --format sarif --output bawbel.sarif'
            }
        }
    }
}
```

---

## CircleCI

```yaml
version: 2.1
jobs:
  bawbel-scan:
    docker:
      - image: python:3.12-slim
    steps:
      - checkout
      - run: pip install bawbel-scanner
      - run: bawbel scan . --recursive --fail-on-severity high
```

---

## Bitbucket Pipelines

```yaml
pipelines:
  default:
    - step:
        name: Scan AI Components
        image: python:3.12-slim
        script:
          - pip install bawbel-scanner
          - bawbel scan . --recursive --fail-on-severity high
```

---

## Azure DevOps

```yaml
steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'
  - script: pip install bawbel-scanner
  - script: bawbel scan . --recursive --fail-on-severity high --format sarif --output bawbel.sarif
  - task: PublishTestResults@2
    inputs:
      testResultsFormat: JUnit
      testResultsFiles: bawbel.sarif
```

---

## pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/bawbel/bawbel-integrations
    rev: v0.1.0
    hooks:
      - id: bawbel-scan
        args: [--fail-on-severity, high]
```

---

## Severity Threshold Guide

| Team maturity | Recommended threshold |
|---|---|
| Starting out | `--fail-on-severity critical` |
| Established pipeline | `--fail-on-severity high` |
| Security-first | `--fail-on-severity medium` |
