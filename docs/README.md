# Bawbel Scanner - Documentation

**Agentic AI component security scanner.**
Detects AVE vulnerabilities in SKILL.md files, MCP servers, system prompts,
and agent plugins before they reach production.

```
AVE Standard:  github.com/bawbel/ave
PyPI:          pip install bawbel-scanner
Source:        github.com/bawbel/scanner
```

---

## Start here

| Document | What it covers |
|---|---|
| [Getting Started](getting-started.md) | Installation, first scan, all commands, output formats |
| [Configuration](configuration.md) | Environment variables, `bawbel.yml`, engine toggles |
| [Detection Engines](engines.md) | Pattern, YARA, Semgrep, LLM, Sandbox - full engine guide |

---

## Guides

| Document | What it covers |
|---|---|
| [guides/writing-rules.md](guides/writing-rules.md) | Add pattern, YARA, and Semgrep rules |
| [guides/cicd-integration.md](guides/cicd-integration.md) | GitHub Actions, GitLab CI, pre-commit |
| [guides/mcp-server-scanning.md](guides/mcp-server-scanning.md) | Scan MCP server cards, conformance scoring |
| [guides/suppression.md](guides/suppression.md) | Suppress false positives with bawbel-ignore |

---

## Reference

| Document | What it covers |
|---|---|
| [conformance.md](conformance.md) | MCP spec conformance scoring |
| [pinning.md](pinning.md) | Rug pull detection, hash pinning |
| [toxic-flows.md](toxic-flows.md) | Toxic flow chain detection |
| [api/scan.md](api/scan.md) | Python API - `scan()`, `ScanResult`, `Finding` |
| [api/engines.md](api/engines.md) | Python API - engine contracts |
| [api/conformance.md](api/conformance.md) | Python API - conformance scorer |

---

## Architecture decisions

| Document | Decision |
|---|---|
| [decisions/001-aivss-scoring.md](decisions/001-aivss-scoring.md) | Why OWASP AIVSS v0.8 instead of CVSS |
| [decisions/002-fp-pipeline.md](decisions/002-fp-pipeline.md) | Five-layer false positive reduction |
| [decisions/003-engine-architecture.md](decisions/003-engine-architecture.md) | Why five independent engines |
| [decisions/004-toxic-flows.md](decisions/004-toxic-flows.md) | Toxic flow chain detection design |

---

## Quick reference

```bash
# Install
pip install "bawbel-scanner[all]"

# Scan
bawbel scan ./skills/my-skill.md
bawbel scan ./skills/ --recursive --format sarif

# Report
bawbel report ./skills/my-skill.md

# MCP conformance
bawbel conform https://api.example.com
bawbel ssc https://api.example.com

# Pin skill files (rug pull protection)
bawbel pin ./skills/
bawbel check-pins ./skills/

# Version and engine status
bawbel version
```
