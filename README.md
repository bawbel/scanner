# Bawbel Scanner

**Agentic AI component security scanner — detects AVE vulnerabilities before they reach production.**

[![PyPI version](https://badge.fury.io/py/bawbel-scanner.svg)](https://pypi.org/project/bawbel-scanner/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://pypi.org/project/bawbel-scanner/)
[![AVE Standard](https://img.shields.io/badge/standard-AVE-teal.svg)](https://github.com/bawbel/bawbel-ave)

Bawbel Scanner scans agentic AI components — SKILL.md files, MCP server manifests,
system prompts, and agent plugins — for security vulnerabilities mapped to the
[AVE (Agentic Vulnerability Enumeration)](https://github.com/bawbel/bawbel-ave) standard.

---

## Install

```bash
pip install bawbel-scanner
```

With optional engines:

```bash
pip install "bawbel-scanner[yara]"      # YARA rules
pip install "bawbel-scanner[semgrep]"   # Semgrep rules
pip install "bawbel-scanner[all]"       # everything
```

---

## Quick Start

```bash
# Check version and active detection engines
bawbel version
bawbel --version

# Scan a SKILL.md file
bawbel scan ./my-skill.md

# Scan a directory
bawbel scan ./skills/ --recursive

# Full report with remediation instructions
bawbel report ./my-skill.md

# Fail CI on high severity
bawbel scan ./skills/ --fail-on-severity high

# Output formats
bawbel scan ./skills/ --format json     # JSON for tooling
bawbel scan ./skills/ --format sarif    # SARIF for GitHub Security tab
```

**Example output:**

```
Bawbel Scanner v0.1.0

Scanning:  malicious-skill.md
Type:      skill

FINDINGS
🔴  CRITICAL  AVE-2026-00001  External instruction fetch detected
   Line 7 · pattern engine
   OWASP: ASI01, ASI08

🟠  HIGH      —               Goal override instruction detected
   Line 17 · pattern engine
   OWASP: ASI01, ASI08

SUMMARY
Risk score:   9.4 / 10  CRITICAL
Findings:     2
Scan time:    5ms
```

---

## Use as a Library

```python
from scanner import scan

result = scan("/path/to/skill.md")

if result.is_clean:
    print("Clean")
else:
    for finding in result.findings:
        print(f"[{finding.severity.value}] {finding.title}")
    print(f"Risk score: {result.risk_score:.1f} / 10")
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Bawbel scan
  run: |
    pip install bawbel-scanner
    bawbel scan ./skills/ --recursive --fail-on-severity high
```

### Pre-commit

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: bawbel-scan
        name: Bawbel Scanner — agentic AI component security scan
        entry: bawbel scan
        language: system        # uses your venv where bawbel-scanner is installed
        pass_filenames: true
        types: [markdown]       # scans .md files on every commit
        args: ["--fail-on-severity", "high"]
```

Then install:

```bash
pip install bawbel-scanner
pre-commit install
```

---

## Detection Stages

| Stage | Engine | Requires | Coverage |
|---|---|---|---|
| 1a | Pattern matching | Nothing (stdlib) | 15 rules, always runs |
| 1b | YARA | `yara-python` | Binary + text pattern matching |
| 1c | Semgrep | `semgrep` | Structural pattern matching |
| 2 | LLM semantic | API key | Nuanced prompt injection |
| 3 | Behavioral | Docker + eBPF | Runtime behaviour (v1.0) |

**15 built-in pattern rules** cover: goal override, jailbreak, hidden instructions,
external fetch, tool call injection, permission escalation, credential exfiltration,
PII exfiltration, shell injection, destructive commands, cryptocurrency drain,
trust escalation, persistence, MCP tool poisoning, system prompt extraction.

---

## AVE Standard

Every finding maps to an AVE record — the CVE equivalent for agentic AI components.

- Browse records: [github.com/bawbel/bawbel-ave](https://github.com/bawbel/bawbel-ave)
- Report a new vulnerability: open an issue on bawbel-ave

---

## Documentation

[bawbel.io/docs](https://bawbel.io/docs) · [Getting Started](docs/guides/getting-started.md) · [API Reference](docs/api/scan.md)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by [Bawbel](https://bawbel.io) · [bawbel.io@gmail.com](mailto:bawbel.io@gmail.com)