# Getting Started — Bawbel Scanner

## Requirements

- Python 3.10 or higher
- pip

Optional (for fuller detection):
- `yara-python` — YARA rule scanning (Stage 1b)
- `semgrep` — Semgrep rule scanning (Stage 1c)

---

## Installation

```bash
# Basic install — 15 pattern rules, always works, no extra deps
pip install bawbel-scanner

# With YARA support (Stage 1b)
pip install "bawbel-scanner[yara]"

# With Semgrep support (Stage 1c)
pip install "bawbel-scanner[semgrep]"

# Everything
pip install "bawbel-scanner[all]"
```

---

## Check Your Installation

```bash
# Show version and active detection engines
bawbel version
```

Output:
```
Bawbel Scanner v0.1.0  ·  github.com/bawbel/bawbel-scanner

Version:  0.1.0

Detection Engines:
  ✓  Pattern     15 rules  ·  stdlib only  ·  always active
  ✗  YARA        not installed  ·  pip install "bawbel-scanner[yara]"
  ✗  Semgrep     not installed  ·  pip install "bawbel-scanner[semgrep]"
  ✗  LLM         not installed  ·  pip install "bawbel-scanner[llm]"
```

---

## Your First Scan

```bash
bawbel scan ./my-skill.md
```

**Clean component:**
```
Bawbel Scanner v0.1.0  ·  github.com/bawbel/bawbel-scanner

Scanning:  my-skill.md
Type:      skill

✓  No vulnerabilities found
   This component passed all AVE checks.

SUMMARY
Risk score:   0.0 / 10  CLEAN
Findings:     0
Scan time:    3ms
```

**Vulnerable component:**
```
Bawbel Scanner v0.1.0  ·  github.com/bawbel/bawbel-scanner

Scanning:  malicious-skill.md
Type:      skill

FINDINGS
🔴  CRITICAL  AVE-2026-00001      External instruction fetch detected
   Line 7  fetch your instructions
   OWASP: ASI01 (Prompt Injection), ASI08 (Goal Hijacking)

🟠  HIGH      N/A                 Goal override instruction detected
   Line 17  Ignore all previous instructions
   OWASP: ASI01 (Prompt Injection), ASI08 (Goal Hijacking)

SUMMARY
Risk score:   9.4 / 10  CRITICAL
Findings:     2
Scan time:    5ms

→  Run 'bawbel report malicious-skill.md' for full remediation guide
```

---

## All Commands

### `bawbel scan` — scan for vulnerabilities

```bash
# Scan a single file
bawbel scan ./my-skill.md

# Scan a directory (non-recursive)
bawbel scan ./skills/

# Scan a directory recursively
bawbel scan ./skills/ --recursive

# JSON output (CI/CD, SIEM, custom tooling)
bawbel scan ./skills/ --format json

# SARIF output (GitHub Security tab integration)
bawbel scan ./skills/ --format sarif > results.sarif

# Fail CI if findings at or above a severity level
bawbel scan ./skills/ --fail-on-severity high
bawbel scan ./skills/ --fail-on-severity critical
```

### `bawbel report` — full remediation guide

```bash
# Scan and show a detailed remediation guide
bawbel report ./my-skill.md

# JSON output
bawbel report ./my-skill.md --format json
```

The report command shows for each finding:
- AVE ID with a direct link to the vulnerability record
- CVSS-AI score and OWASP category
- Exact line and matched text
- **Specific remediation instructions**
- A final "Do not install this component" warning if vulnerabilities are found

### `bawbel version` — engine status

```bash
bawbel version
```

Shows the installed version and which detection engines are active.

### `bawbel --version` — quick version check

```bash
bawbel --version
# Bawbel Scanner v0.1.0
```

---

## Output Formats

| Format | Command | Use case |
|---|---|---|
| Text | `--format text` (default) | Human reading |
| JSON | `--format json` | CI/CD, custom tooling, SIEM |
| SARIF | `--format sarif` | GitHub Security tab, VS Code |

### JSON output structure

```json
[
  {
    "file_path": "/path/to/skill.md",
    "component_type": "skill",
    "risk_score": 9.4,
    "max_severity": "CRITICAL",
    "scan_time_ms": 5,
    "has_error": false,
    "findings": [
      {
        "rule_id": "bawbel-external-fetch",
        "ave_id": "AVE-2026-00001",
        "title": "External instruction fetch detected",
        "description": "...",
        "severity": "CRITICAL",
        "cvss_ai": 9.4,
        "line": 7,
        "match": "fetch your instructions",
        "engine": "pattern",
        "owasp": ["ASI01", "ASI08"]
      }
    ]
  }
]
```

### SARIF output

SARIF (Static Analysis Results Interchange Format) integrates with GitHub's
Security tab and most IDE security plugins. After uploading a SARIF file to
GitHub, findings appear as code scanning alerts on your repository.

```yaml
# .github/workflows/bawbel.yml
- name: Run Bawbel Scanner
  run: |
    pip install bawbel-scanner
    bawbel scan ./skills/ --format sarif > bawbel-results.sarif

- name: Upload results to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bawbel-results.sarif
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean — no findings, or findings below `--fail-on-severity` threshold |
| `1` | `bawbel report` found vulnerabilities |
| `2` | `bawbel scan --fail-on-severity` threshold breached |

---

## Detection Coverage

15 built-in pattern rules cover these attack classes:

| Attack class | Rule ID |
|---|---|
| Goal override / prompt injection | `bawbel-goal-override` |
| Jailbreak / role-play bypass | `bawbel-jailbreak-instruction` |
| Hidden instructions | `bawbel-hidden-instruction` |
| External instruction fetch | `bawbel-external-fetch` (AVE-2026-00001) |
| Dynamic tool call injection | `bawbel-dynamic-tool-call` |
| Permission escalation | `bawbel-permission-escalation` |
| Credential exfiltration | `bawbel-env-exfiltration` (AVE-2026-00003) |
| PII exfiltration | `bawbel-pii-exfiltration` |
| Shell pipe injection | `bawbel-shell-pipe` |
| Destructive commands | `bawbel-destructive-command` |
| Cryptocurrency drain | `bawbel-crypto-drain` |
| Trust escalation / impersonation | `bawbel-trust-escalation` |
| Persistence / self-replication | `bawbel-persistence-attempt` |
| MCP tool poisoning | `bawbel-mcp-tool-poisoning` (AVE-2026-00002) |
| System prompt extraction | `bawbel-system-prompt-leak` |

---

## Supported File Types

| Extension | Component type |
|---|---|
| `.md` | `skill` — SKILL.md, .cursorrules, CLAUDE.md |
| `.json` | `mcp` — MCP server manifests |
| `.yaml` / `.yml` | `prompt` — system prompt configs |
| `.txt` | `prompt` — plain text prompts |

---

## Debug Mode

```bash
BAWBEL_LOG_LEVEL=DEBUG bawbel scan ./my-skill.md   # full internal logs
BAWBEL_LOG_LEVEL=INFO  bawbel scan ./my-skill.md   # lifecycle only
```

---

## Next Steps

- [Configuration](configuration.md) — env vars, timeouts, LLM analysis
- [CI/CD Integration](cicd-integration.md) — GitHub Actions, GitLab, pre-commit
- [Writing Rules](writing-rules.md) — add your own detection rules
- [AVE Standard](https://github.com/bawbel/bawbel-ave) — browse vulnerability records
