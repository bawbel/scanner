# Bawbel Scanner — Documentation

## What is this?

Bawbel Scanner is an open-source CLI tool that scans agentic AI components
(SKILL.md files, MCP server manifests, system prompts, plugins) for security
vulnerabilities mapped to the [AVE standard](https://github.com/bawbel/bawbel-ave).

---

## Documentation Index

### Guides — for developers and users

| Document | Description |
|---|---|
| [Getting Started](guides/getting-started.md) | Install, all commands, output formats, detection coverage |
| [Configuration](guides/configuration.md) | Environment variables, config options |
| [CI/CD Integration](guides/cicd-integration.md) | GitHub Actions, GitLab, Jenkins, CircleCI |
| [Docker](guides/docker.md) | Running via Docker and Docker Compose |
| [Publishing](guides/publishing.md) | Publish to PyPI — step by step |
| [Writing Rules](guides/writing-rules.md) | All 15 built-in rules, OWASP mapping, adding new rules |
| [Detection Engines](guides/engines.md) | All 5 engines explained — purpose, how it works, what it detects, how to use |
| [Adding an Engine](guides/adding-engine.md) | Add a new detection stage |

### API Reference — for contributors

| Document | Description |
|---|---|
| [scan()](api/scan.md) | Python API + all CLI commands (scan, report, version) + output formats |
| [Finding](api/finding.md) | Finding dataclass |
| [ScanResult](api/scan-result.md) | ScanResult dataclass |
| [Engines](api/engines.md) | Engine interface contract |
| [Utils](api/utils.md) | Utility classes reference |
| [Messages](api/messages.md) | Error codes and log messages |

### Decisions — why things are the way they are

| Document | Description |
|---|---|
| [ADR-001: Engine separation](decisions/adr-001-engine-separation.md) | Why each engine is a separate file |
| [ADR-002: OOP utils](decisions/adr-002-oop-utils.md) | Why utils uses classes with function aliases |
| [ADR-003: Error codes](decisions/adr-003-error-codes.md) | Why errors use E-codes not raw messages |
| [ADR-004: No exceptions from scan()](decisions/adr-004-no-exceptions.md) | Why scan() never raises |

---

## Quick Reference

```bash
# Copy example env file
cp .env.example .env
# edit .env with your keys

# Install
pip install bawbel-scanner

# Check version and active engines
bawbel version
bawbel --version

# Scan a file
bawbel scan ./my-skill.md

# Scan a directory recursively
bawbel scan ./skills/ --recursive

# Full remediation report
bawbel report ./my-skill.md

# Fail CI on high severity
bawbel scan ./skills/ --fail-on-severity high

# Output formats
bawbel scan ./skills/ --format json           # JSON for SIEM / tooling
bawbel scan ./skills/ --format sarif          # SARIF for GitHub Security tab

# Enable debug logging
BAWBEL_LOG_LEVEL=DEBUG bawbel scan ./my-skill.md
```

---

## AVE Standard

Every finding maps to an AVE record.
Browse records: [github.com/bawbel/bawbel-ave](https://github.com/bawbel/bawbel-ave)
