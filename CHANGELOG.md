# Changelog

All notable changes to bawbel-scanner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.2.0] — 2026-04-20

### Added
- **LLM Stage 2** — semantic analysis via [LiteLLM](https://docs.litellm.ai) supporting any provider: Anthropic, OpenAI, Gemini, Mistral, Groq, Ollama, and 100+ more. Install with `pip install "bawbel-scanner[llm]"`. Set `BAWBEL_LLM_MODEL` or a provider API key to activate.
- **Full AVE ID coverage** — all 15 pattern rules now linked to AVE records (00001–00015). Every finding shows a clickable AVE ID.
- **7 new AVE records** — AVE-2026-00009 through AVE-2026-00015 covering jailbreak, hidden instruction, dynamic tool call, permission escalation, PII exfiltration, trust escalation, and system prompt leak.
- `BAWBEL_LLM_MODEL` env var — explicit model override for any LiteLLM model string
- `BAWBEL_LLM_ENABLED` env var — set `false` to disable Stage 2 entirely
- `bawbel version` now shows the active LLM model name when Stage 2 is enabled

### Fixed
- Semgrep `code=7` — YAML escaping and float metadata values in `ave_rules.yaml` broke validation on semgrep v1.159.0. Fixed: double-quoted regex patterns, quoted float scores.
- Semgrep URL fetch rule regex — original pattern required literal `(` so missed natural language like `fetch your instructions from https://...`. Fixed with language-aware pattern.
- `pip install "bawbel-scanner[llm]"` dependency conflict — pinned `jsonschema~=4.25.1` to resolve conflict between semgrep and litellm.
- `requirements.txt` — removed unused `requests` dependency.

### Changed
- LLM Stage 2 rewritten to use LiteLLM instead of provider-specific packages. Breaking change: `pip install "bawbel-scanner[llm]"` now installs `litellm` instead of `anthropic+openai`.
- `[llm]` extra: `litellm>=1.30.0` (was `litellm>=1.30.0` with wrong deps)
- `[all]` extra updated to match

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
- Stage 2: LLM semantic analysis via LiteLLM — works with any provider (Anthropic, OpenAI, Gemini, Mistral, Ollama, and more). Enable with `pip install "bawbel-scanner[llm]"` and set `BAWBEL_LLM_MODEL` or a provider API key

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
