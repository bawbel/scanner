# Changelog

All notable changes to bawbel-scanner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.1.0] — 2026-04-17

First public release.

### Added
- Core scan engine with three-stage detection pipeline
- **Stage 1a** — Pattern matching engine (stdlib only, always runs)
- **Stage 1b** — YARA detection engine (optional, requires `yara-python`)
- **Stage 1c** — Semgrep detection engine (optional, requires `semgrep`)
- AVE finding schema — `Finding` and `ScanResult` data models
- 5 built-in pattern rules covering goal override, external fetch, permission escalation, env exfiltration, shell pipe injection
- CLI — `bawbel scan`, `--recursive`, `--format json`, `--fail-on-severity`
- Docker support — multi-stage Dockerfile and docker-compose.yml
- 125 passing tests including golden fixture, security invariants, unit and integration tests
- Security hardening — symlink protection, file size limits, no exception exposure
- `scan()` never raises — all errors returned in `ScanResult.error`
- Stable error codes E001–E020 in `scanner/messages.py`
- OOP utility classes — `Logger`, `PathValidator`, `FileReader`, `SubprocessRunner`, `JsonParser`, `TextSanitiser`
- Full documentation — guides, API reference, architecture decision records

### AVE Records Covered
- `AVE-2026-00001` — Metamorphic payload via external config fetch (CRITICAL 9.4)
- `AVE-2026-00002` — MCP tool description prompt injection (HIGH 8.7)
- `AVE-2026-00003` — Environment variable exfiltration (HIGH 8.5)

[0.1.0]: https://github.com/bawbel/bawbel-scanner/releases/tag/v0.1.0
