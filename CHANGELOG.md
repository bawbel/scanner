# Changelog

All notable changes to bawbel-scanner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.1.0] — 2026-04-19

First public release.

### Added

**CLI**
- `bawbel scan` — scan a file or directory with `--recursive`, `--fail-on-severity`, and `--format text|json|sarif`
- `bawbel report` — full remediation guide per finding: AVE ID, CVSS-AI score, OWASP mapping, specific fix instructions
- `bawbel version` — show installed version and active detection engine status
- `bawbel --version` — quick version string for CI scripts

**Detection**
- 15 built-in pattern rules (3 CRITICAL, 10 HIGH, 2 MEDIUM) covering all major agentic AI attack classes
- Stage 1a: pattern matching engine — stdlib only, zero dependencies, always runs
- Stage 1b: YARA engine — optional, requires `yara-python`, 3 rules
- Stage 1c: Semgrep engine — optional, requires `semgrep`, 5 rules
- Stage 2: LLM semantic analysis — enabled by setting `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`

**Output formats**
- `text` — human-readable terminal output with severity icons
- `json` — structured output for CI/CD pipelines and SIEM integration
- `sarif` — SARIF 2.1.0 for GitHub Security tab and IDE plugins

**Core**
- `scan()` public API — never raises, all errors captured in `ScanResult.error`
- Stable error codes E001–E020 in `scanner/messages.py`
- OOP utility classes — `Logger`, `PathValidator`, `FileReader`, `SubprocessRunner`, `JsonParser`, `TextSanitiser`
- Security hardening — symlink protection, 10MB file size limit, no exception detail exposed to users

**Docker**
- Three build targets: `production` (minimal, non-root), `dev` (hot-reload shell), `test` (runs test suite and exits)
- Docker Compose with 7 services: `scan`, `report`, `scan-json`, `scan-sarif`, `dev`, `test`, `audit`

**Developer experience**
- 145 passing tests including golden fixture, security invariants, CLI tests, pattern rule tests
- `CONTRIBUTING.md` and `SECURITY.md`
- Full documentation at `bawbel.io/docs` — getting started, CLI reference, writing rules, CI/CD, Docker, Python API

### AVE Records Covered
- `AVE-2026-00001` — Metamorphic payload via external instruction fetch (CRITICAL 9.4)
- `AVE-2026-00002` — MCP tool description prompt injection (HIGH 8.7)
- `AVE-2026-00003` — Environment variable exfiltration (HIGH 8.5)

[0.1.0]: https://github.com/bawbel/bawbel-scanner/releases/tag/v0.1.0
