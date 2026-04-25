# Bawbel Scanner

**Agentic AI component security scanner — detects AVE vulnerabilities before they reach production.**

[![PyPI version](https://badge.fury.io/py/bawbel-scanner.svg)](https://pypi.org/project/bawbel-scanner/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://pypi.org/project/bawbel-scanner/)
[![AVE Standard](https://img.shields.io/badge/AVE_Records-15-teal.svg)](https://github.com/bawbel/bawbel-ave)

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
pip install "bawbel-scanner[yara]"      # Stage 1b — YARA rules (15 rules)
pip install "bawbel-scanner[semgrep]"   # Stage 1c — Semgrep rules (15 rules)
pip install "bawbel-scanner[llm]"       # Stage 2  — LLM semantic analysis
pip install "bawbel-scanner[watch]"     # Watch mode — re-scan on file change
pip install "bawbel-scanner[all]"       # Everything above
```

Stage 3 (behavioral sandbox) requires Docker — see [Stage 3](#stage-3--behavioral-sandbox).

---

## Quick Start

```bash
cp .env.example .env   # copy env template, fill in your keys
source .env

bawbel version                                    # show version + active engines
bawbel scan ./my-skill.md                         # scan a file
bawbel scan ./skills/ --recursive                 # scan a directory
bawbel report ./my-skill.md                       # full remediation report
bawbel scan ./skills/ --fail-on-severity high     # exit 2 on HIGH+
bawbel scan ./skills/ --watch                     # re-scan on every change
bawbel scan ./skills/ --format json               # JSON for tooling
bawbel scan ./skills/ --format sarif              # SARIF for GitHub Security tab
```

**Example output:**

```
Bawbel Scanner v0.3.0  ·  github.com/bawbel/bawbel-scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scanning:  malicious-skill.md
Type:      skill

FINDINGS
──────────────────────────────────────────────────────────
🔴  CRITICAL  AVE-2026-00001      External instruction fetch detected
   Line 7  ·  fetch your instructions
   OWASP: ASI01 (Prompt Injection), ASI08 (Goal Hijacking)

🟠  HIGH      AVE-2026-00007      Goal override instruction detected
   Line 17  ·  Ignore all previous instructions
   OWASP: ASI01 (Prompt Injection), ASI08 (Goal Hijacking)
──────────────────────────────────────────────────────────
SUMMARY
──────────────────────────────────────────────────────────
Risk score:   9.4 / 10  CRITICAL
Findings:     2
Scan time:    5ms
→  Run bawbel report malicious-skill.md for full remediation guide
```

---

## Detection Pipeline

Five stages run in sequence — each adds an independent layer:

| Stage | Engine | Install | What it catches |
|---|---|---|---|
| 1a | **Pattern** | nothing — always active | 15 regex rules, all AVE IDs |
| 1b | **YARA** | `pip install "bawbel-scanner[yara]"` | Binary + complex text combinations, 15 rules |
| 1c | **Semgrep** | `pip install "bawbel-scanner[semgrep]"` | Structural + multi-line patterns, 15 rules |
| 2  | **LLM** | `pip install "bawbel-scanner[llm]"` + API key | Obfuscated, nuanced, multi-paragraph injections |
| 3  | **Sandbox** | Docker + `BAWBEL_SANDBOX_ENABLED=true` | Runtime behaviour — network egress, filesystem, processes |

**15 built-in rules** covering every major agentic attack class:
goal override · jailbreak · hidden instructions · external fetch ·
tool call injection · permission escalation · credential exfiltration ·
PII exfiltration · shell injection · destructive commands ·
cryptocurrency drain · trust escalation · persistence ·
MCP tool poisoning · system prompt extraction.

---

## Stage 2 — LLM Semantic Analysis

Catches what regex misses: obfuscated payloads, synonym attacks, multi-paragraph
injections, and social engineering. Works with any LiteLLM-supported provider.

```bash
pip install "bawbel-scanner[llm]"

export ANTHROPIC_API_KEY=sk-ant-...   # → auto-selects claude-haiku-4-5-20251001
export OPENAI_API_KEY=sk-...          # → auto-selects gpt-4o-mini
export GEMINI_API_KEY=...             # set BAWBEL_LLM_MODEL=gemini/gemini-1.5-flash
export BAWBEL_LLM_MODEL=ollama/mistral  # local model, no API key needed

bawbel scan ./my-skill.md             # Stage 2 activates automatically
```

---

## Stage 3 — Behavioral Sandbox

Runs the component inside an isolated Docker container and monitors what it
*actually does* at runtime — catching attacks that static analysis cannot see.

```bash
export BAWBEL_SANDBOX_ENABLED=true
bawbel scan ./my-skill.md
```

**Hybrid image strategy — no setup required:**

```
1. Check local Docker cache  →  run immediately if found
2. Pull bawbel/sandbox:latest from Docker Hub  →  cache + run (~5s first time)
3. Build from bundled Dockerfile  →  offline / air-gapped fallback (~15s)
```

```bash
BAWBEL_SANDBOX_IMAGE=local                          # skip Hub, build locally
BAWBEL_SANDBOX_IMAGE=registry.corp.com/bawbel/sandbox@sha256:abc  # enterprise
```

Detects: outbound network egress · persistence writes (~/.bashrc, crontab) ·
credential access (~/.ssh/, .env) · shell pipe injection ·
subprocess spawning · Base64 encoded payloads.

See [Detection Engines Guide](docs/guides/engines.md) for full sandbox documentation.

---

## Use as a Library

```python
from scanner import scan

result = scan("/path/to/skill.md")

if result.is_clean:
    print("Clean")
else:
    for finding in result.findings:
        print(f"[{finding.severity.value}] {finding.ave_id}  {finding.title}")
        print(f"  Engine: {finding.engine}  CVSS-AI: {finding.cvss_ai}")
    print(f"\nRisk score: {result.risk_score:.1f} / 10")
```

---

## CI/CD Integration

### GitHub Actions — fail on findings

```yaml
name: Bawbel Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan for AVE vulnerabilities
        run: |
          pip install bawbel-scanner
          bawbel scan . --recursive --fail-on-severity high
```

### GitHub Actions — SARIF to Security tab

```yaml
      - name: Bawbel SARIF scan
        run: |
          pip install bawbel-scanner
          bawbel scan . --recursive --format sarif > bawbel.sarif
      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bawbel.sarif
```

### Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: bawbel-scan
        name: Bawbel Scanner
        entry: bawbel scan
        language: system
        pass_filenames: true
        types: [markdown]
        args: ["--fail-on-severity", "high"]
```

```bash
pip install bawbel-scanner && pre-commit install
```

---

## Configuration

Copy `.env.example` and fill in your values:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `BAWBEL_LOG_LEVEL` | `WARNING` | `DEBUG` · `INFO` · `WARNING` · `ERROR` |
| `ANTHROPIC_API_KEY` | — | Enables Stage 2 via Claude |
| `OPENAI_API_KEY` | — | Enables Stage 2 via OpenAI |
| `BAWBEL_LLM_MODEL` | auto | Any LiteLLM model string |
| `BAWBEL_LLM_ENABLED` | `true` | Set `false` to disable Stage 2 |
| `BAWBEL_SANDBOX_ENABLED` | `false` | Set `true` to enable Stage 3 |
| `BAWBEL_SANDBOX_IMAGE` | `default` | `default` · `local` · custom image |
| `BAWBEL_SANDBOX_TIMEOUT` | `30` | Container timeout in seconds |
| `BAWBEL_SANDBOX_NETWORK` | `none` | `none`=isolated · `bridge`=internet |
| `BAWBEL_NO_IGNORE` | `false` | Set `true` to override all suppressions (audit mode) |

See [`.env.example`](.env.example) for the full reference.

---

## Suppression — Managing False Positives

Three mechanisms to suppress known false positives. Suppressed findings are **never deleted** — they appear in `suppressed_findings` in JSON output for full audit trail.

### Inline — on the line

```markdown
fetch https://internal.company.com  <!-- bawbel-ignore -->
fetch https://internal.company.com  <!-- bawbel-ignore: bawbel-external-fetch -->
fetch https://internal.company.com  <!-- bawbel-ignore: AVE-2026-00001 -->
fetch https://internal.company.com  # bawbel-ignore
```

### Block — a section

```markdown
<!-- bawbel-ignore-start -->
fetch https://internal.company.com
Ignore all previous instructions  ← intentional, test fixture
<!-- bawbel-ignore-end -->
```

### .bawbelignore — entire files or directories

```
# .bawbelignore
tests/fixtures/**          # all test fixtures
docs/examples/bad.md       # known-bad example file
**/test_*.md               # all test skill files
```

### Audit mode — override all suppressions

```bash
bawbel scan ./skills/ --no-ignore      # CLI flag
BAWBEL_NO_IGNORE=true bawbel scan ./   # env var
```

See [Suppression Guide](docs/guides/suppression.md) for full documentation.


---

## AVE Standard

Every finding maps to a published AVE record — the CVE equivalent for agentic AI.

- Browse records: [github.com/bawbel/bawbel-ave](https://github.com/bawbel/bawbel-ave)
- Threat intelligence API: [api.piranha.bawbel.io](https://api.piranha.bawbel.io)
- Report a vulnerability: open an issue on [bawbel-ave](https://github.com/bawbel/bawbel-ave/issues)

---

## Documentation

| Resource | Link |
|---|---|
| Full docs | [bawbel.io/docs](https://bawbel.io/docs) |
| Getting started | [docs/guides/getting-started.md](docs/guides/getting-started.md) |
| Detection engines | [docs/guides/engines.md](docs/guides/engines.md) |
| Configuration | [docs/guides/configuration.md](docs/guides/configuration.md) |
| CI/CD integration | [docs/guides/cicd-integration.md](docs/guides/cicd-integration.md) |
| Python API | [docs/api/scan.md](docs/api/scan.md) |
| Suppression | [docs/guides/suppression.md](docs/guides/suppression.md) |
| False positive reduction | [docs/guides/false-positive-reduction.md](docs/guides/false-positive-reduction.md) |
| Writing rules | [docs/guides/writing-rules.md](docs/guides/writing-rules.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by [Bawbel](https://bawbel.io) · [bawbel.io@gmail.com](mailto:bawbel.io@gmail.com)
