# Bawbel Scanner

**Agentic AI component security scanner — detects AVE vulnerabilities before they reach production.**

[![PyPI version](https://badge.fury.io/py/bawbel-scanner.svg)](https://pypi.org/project/bawbel-scanner/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://pypi.org/project/bawbel-scanner/)
[![AVE Standard](https://img.shields.io/badge/AVE_Records-40-teal.svg)](https://github.com/bawbel/bawbel-ave)

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
pip install "bawbel-scanner[yara]"      # Stage 1b — YARA rules (39 rules)
pip install "bawbel-scanner[semgrep]"   # Stage 1c — Semgrep rules (41 rules)
pip install "bawbel-scanner[llm]"       # Stage 2  — LLM semantic analysis
pip install "bawbel-scanner[magika]"    # Stage 0  — file type verification (Google Magika)
pip install "bawbel-scanner[watch]"     # Watch mode — re-scan on file change
pip install "bawbel-scanner[all]"       # Everything: yara + semgrep + llm + magika + watch
```

Stage 3 (behavioral sandbox) requires Docker — see [Stage 3](#stage-3--behavioral-sandbox).

---

## Quick Start

```bash
cp .env.example .env   # copy env template, fill in your keys
source .env

bawbel version                                       # show version + active engines
bawbel scan ./my-skill.md                            # scan a file
bawbel scan ./skills/ --recursive                    # scan a directory
bawbel scan-server-card https://api.example.com      # scan an MCP server-card
bawbel report ./my-skill.md                          # full remediation report
bawbel scan ./skills/ --fail-on-severity high        # exit 2 on HIGH+
bawbel scan ./skills/ --watch                        # re-scan on every change
bawbel scan ./skills/ --format json                  # JSON for tooling
bawbel scan ./skills/ --format sarif                 # SARIF for GitHub Security tab
bawbel pin ./skills/                                 # hash skill files → .bawbel-pins.json
bawbel check-pins ./skills/                          # check for rug pull drift
```

**Example output:**

```
Bawbel Scanner v1.0.1  ·  github.com/bawbel/bawbel-scanner
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

## Scanning MCP Server-Cards

MCP server-cards (`.well-known/mcp-server-card/server.json`) are the new
auto-discovery mechanism for MCP 2026. An agent fetches the card on connection
and reads all tool descriptions before making a single call — making it a
critical attack surface.

```bash
# Scan a server-card by base URL
bawbel scan-server-card https://api.example.com

# Fetches: https://api.example.com/.well-known/mcp-server-card/server.json
# Scans: all tool names, descriptions, parameter descriptions, config schemas
# Output: same JSON/SARIF/text format as bawbel scan

# JSON output
bawbel scan-server-card https://api.example.com --format json

# CI mode — fail on HIGH+
bawbel scan-server-card https://api.example.com --fail-on-severity high
```

A poisoned server-card can inject behavioral instructions into the agent before
it makes a single tool call. `bawbel scan-server-card` is the only dedicated
scanner for this attack surface.

---

## False Positive Reduction

Bawbel ships a 5-layer false positive reduction system:

| Layer | Mechanism | FP reduction |
|---|---|---|
| FP-1 | Code fence stripping — ` ``` ` blocks skipped before static analysis | ~60% |
| FP-2 | Preceding-line context — "Never do this:" suppresses the line below | ~15% |
| FP-3 | Confidence scoring — table rows, headings, `docs/` paths penalised | ~10% |
| FP-4 | **Meta-analyzer** — one LLM call per file validates medium-confidence findings | ~7% |
| FP-5 | File-type profiles — documentation scanned at higher threshold (0.85) | ~3% |

The meta-analyzer (FP-4) sends all findings as enriched context to the LLM in a single
call — not a general security scan, but a targeted false-positive filter. Requires
`BAWBEL_LLM_ENABLED=true` and an API key. Skips silently if not configured.

See [False Positive Reduction guide](docs/guides/false-positive-reduction.md) for full details.

---

## Detection Pipeline

Six stages run in sequence:

| Stage | Engine | Install | What it catches |
|---|---|---|---|
| 0  | **Magika** | `pip install "bawbel-scanner[magika]"` | Content-type verification — catches supply chain attacks (ELF disguised as .md, pickle as .yaml) |
| 1a | **Pattern** | nothing — always active | 37 regex rules, all AVE IDs |
| 1b | **YARA** | `pip install "bawbel-scanner[yara]"` | Binary + complex text combinations, 39 rules |
| 1c | **Semgrep** | `pip install "bawbel-scanner[semgrep]"` | Structural + multi-line patterns, 41 rules |
| 2  | **LLM** | `pip install "bawbel-scanner[llm]"` + API key | Obfuscated, nuanced, multi-paragraph injections |
| 3  | **Sandbox** | Docker + `BAWBEL_SANDBOX_ENABLED=true` | Runtime behaviour — network egress, filesystem, processes |

**40 built-in AVE records** covering the full agentic attack surface:
goal override · jailbreak · hidden instructions · external fetch ·
tool call injection · permission escalation · credential exfiltration ·
PII exfiltration · shell injection · destructive commands ·
cryptocurrency drain · trust escalation · persistence ·
MCP tool poisoning · system prompt extraction · RAG injection ·
MCP server impersonation · tool result manipulation · memory poisoning ·
cross-agent A2A injection · autonomous action · scope creep ·
context manipulation · content type mismatch · conversation history injection ·
tool output exfiltration · multi-turn persistence · file prompt injection ·
role claim escalation · feedback poisoning · network reconnaissance ·
unsafe deserialization · supply chain skill import · lateral movement ·
vision prompt injection · excessive agency · covert channel ·
insecure output injection · and more.

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
BAWBEL_SANDBOX_IMAGE=local                           # skip Hub, build locally
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

### GitHub Actions — official action

```yaml
# .github/workflows/bawbel.yml
name: Bawbel Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: bawbel/bawbel-integrations@v1
        id: bawbel
        with:
          path: .
          fail-on-severity: high
          format: sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.bawbel.outputs.sarif-file }}
```

**Action inputs:** `path`, `fail-on-severity`, `format`, `recursive`, `no-ignore`, `version`, `extras`
**Action outputs:** `sarif-file`, `findings-count`, `risk-score`, `result`

See [bawbel/bawbel-integrations](https://github.com/bawbel/bawbel-integrations) for
full documentation and examples.

### VS Code Extension

Install **Bawbel Scanner** from the VS Code Marketplace. Auto-installs
the CLI on first activation. Inline diagnostics, status bar, auto-scan on save,
right-click suppress false positives with inline `<!-- bawbel-ignore -->` comments.

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

## Tool Pinning — Rug Pull Detection

A rug pull is when an MCP server or skill file changes its content **after**
you installed and audited it. You scan it today — it's clean. Three weeks later
the tool description silently changes to exfiltrate every user query. Your last
scan was clean. Nothing in CI caught it.

`bawbel pin` hashes your skill files and saves the hashes to `.bawbel-pins.json`.
Commit that file. On every subsequent scan, `bawbel check-pins` detects any hash
that has changed since you pinned it.

```bash
# 1. Audit first
bawbel scan ./skills/ --recursive

# 2. Pin once satisfied
bawbel pin ./skills/

# 3. Commit pins — team shares them automatically
git add .bawbel-pins.json
git commit -m "chore: pin skill files"

# 4. Check for drift on every build
bawbel check-pins ./skills/ --fail-on-drift
```

**Why `.bawbel-pins.json` beats Snyk's `~/.mcp-scan`:**

| | Bawbel | Snyk |
|---|---|---|
| Visible in `git diff` | ✅ | ✗ |
| Reviewable in PRs | ✅ | ✗ |
| Shared with team automatically | ✅ | ✗ |
| Audit trail (`pinned_by`) | ✅ | ✗ |

When a skill file is legitimately updated, re-pin it after scanning:

```bash
bawbel scan skills/search.md          # verify it's still clean
bawbel pin skills/search.md --update  # update the pin
git add skills/search.md .bawbel-pins.json
git commit -m "update skill + re-pin"
```

The PR shows both the skill change and the pin update — reviewers see exactly
what changed and that it was re-audited.

See [Tool Pinning Guide](docs/guides/pinning.md) for full documentation.

---

## Suppression — Managing False Positives

Three mechanisms to suppress known false positives. Suppressed findings are **never deleted** — they appear in `suppressed_findings` in JSON output for full audit trail.

### Inline — on the line (preferred)

```markdown
fetch https://internal.company.com  <!-- bawbel-ignore -->
fetch https://internal.company.com  <!-- bawbel-ignore: bawbel-external-fetch -->
fetch https://internal.company.com  <!-- bawbel-ignore: AVE-2026-00001 -->
fetch https://internal.company.com  # bawbel-ignore
fetch https://internal.company.com  # bawbel-ignore: bawbel-external-fetch, AVE-2026-00007
```

The VS Code extension inserts these automatically via right-click → Ignore this line.

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
| Tool pinning | [docs/guides/pinning.md](docs/guides/pinning.md) |
| False positive reduction | [docs/guides/false-positive-reduction.md](docs/guides/false-positive-reduction.md) |
| Writing rules | [docs/guides/writing-rules.md](docs/guides/writing-rules.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by [Bawbel](https://bawbel.io) · [bawbel.io@gmail.com](mailto:bawbel.io@gmail.com)
