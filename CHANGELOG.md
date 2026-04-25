# Changelog

All notable changes to bawbel-scanner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-04-25

### Added

- **GitHub Actions** — `bawbel/bawbel-integrations@v1` official action. One-line CI/CD integration: installs scanner, runs scan, uploads SARIF to GitHub Security tab. Inputs: `path`, `fail-on-severity`, `format`, `recursive`, `no-ignore`, `version`, `extras`. See [bawbel/bawbel-integrations](https://github.com/bawbel/bawbel-integrations).
- **VS Code Extension** — zero-setup extension (search "Bawbel Scanner" in Marketplace). Auto-installs CLI on first activation. Inline diagnostics, status bar, auto-scan on save, `Cmd+Shift+B` shortcut. Source: [bawbel/bawbel-integrations/vscode](https://github.com/bawbel/bawbel-integrations/tree/main/vscode).
- **False positive reduction roadmap** — `docs/guides/false-positive-reduction.md` documents the 8-point strategy.
- **AVE records 16–24** — 9 new pattern rules covering: RAG injection (00016), MCP impersonation (00017), tool result manipulation (00018), agent memory poisoning (00019), A2A cross-agent injection (00020), autonomous action without confirmation (00021), scope creep (00022), context window manipulation (00023), conversation history injection (00025). Total: 24 pattern rules.
- **`bawbel init`** command — generates `.bawbelignore` and `bawbel.yml` in project root, discovers skill/MCP files, shows next steps.
- **`scanner/engines/meta_analyzer.py`** — meta-analysis FP filter (FP-4).
- **`scanner/engines/magika_engine.py`** — Stage 0 file type verification.
- **FP-4 meta-analysis LLM filter** (`scanner/engines/meta_analyzer.py`) — enriched FP filter. One LLM call per file covers all medium-confidence findings (0.35–0.80). Sends file metadata + finding context to LLM. Verdicts: real (confidence +0.15) | false_positive (suppressed) | needs_review (confidence −0.05). Skips silently if no LLM configured.
- **FP-5 file-type scan profiles** (`_classify_file()` in `scanner/scanner.py`) — files classified as skill/mcp_manifest/documentation/unknown. Profile thresholds: skill=0.60, mcp_manifest=0.55, documentation=0.85, unknown=0.80. Classification based on filename and path segments.
- `BAWBEL_META_ANALYZER_ENABLED` env var — disable meta-analysis FP filter (default: true).
- `BAWBEL_META_MIN_CONFIDENCE` / `BAWBEL_META_MAX_CONFIDENCE` — range for meta-analysis (default: 0.35–0.80).
- **Priority 1 implemented: code fence stripping** — `_strip_code_fences()` in `scanner/scanner.py`. Content inside ` ``` ` and `~~~` blocks is replaced with blank lines before Pattern, YARA, and Semgrep analysis. Line numbers remain accurate. Sandbox (Stage 3) and suppression still receive the original content. Expected FP reduction: ~60%%. 12 new tests in `TestCodeFenceStripping`.

- **Inline suppression** — add `<!-- bawbel-ignore -->` on any line to suppress all findings on that line. Rule-specific: `<!-- bawbel-ignore: bawbel-external-fetch -->` or by AVE ID: `<!-- bawbel-ignore: AVE-2026-00001 -->`. Also supports `# bawbel-ignore` and `// bawbel-ignore`.
- **Block suppression** — wrap sections with `<!-- bawbel-ignore-start -->` / `<!-- bawbel-ignore-end -->` to suppress all findings in the block. Also supports `# bawbel-ignore-start/end`.
- **`.bawbelignore` file** — gitignore-style path patterns to suppress entire files or directories (e.g. `tests/fixtures/**`, `docs/examples/bad.md`, `**/test_*.md`).
- **`--no-ignore` flag** — `bawbel scan ./skills/ --no-ignore` overrides ALL suppressions for security audits. Also `BAWBEL_NO_IGNORE=true`.
- Suppressed findings move to `ScanResult.suppressed_findings` — never hidden from JSON/SARIF output, always auditable.
- Summary line shows suppressed count: `Suppressed: 2  (run with --no-ignore to see all)`
- Every suppression logged at INFO level for audit trail.

---

## [0.3.0] — 2026-04-21

### Added
- **Full YARA coverage — 15/15 rules** — added 12 new YARA rules covering AVE-2026-00004 through 00015. Every attack class now has pattern, YARA, and Semgrep detection.
- **Full Semgrep coverage — 15/15 rules** — added 10 new Semgrep rules covering AVE-2026-00007 through 00015. All rules validated against semgrep v1.159.0.
- **Stage 3 behavioral sandbox — hybrid image strategy** (`scanner/engines/sandbox_engine.py`):
  - Docker container isolates execution — `--network none`, `--memory 256m`, `--cap-drop ALL`, `--read-only`
  - **Hybrid image resolution** — no setup required: local cache → Docker Hub pull → bundled local build fallback
  - Works offline and in air-gapped environments via bundled `scanner/sandbox/Dockerfile`
  - `scanner/sandbox/harness.py` — text-based analysis harness runs inside the container (v0.3.x); eBPF tracing in v1.0
  - Enable with `BAWBEL_SANDBOX_ENABLED=true`
- **`[watch]` extra** — `pip install "bawbel-scanner[watch]"` installs `watchdog` for `bawbel scan --watch`
- **`.env.example`** — complete environment variable template with all options, defaults, and examples
- **`docs/guides/engines.md`** — comprehensive detection engines guide covering all 5 stages with diagrams, IOC tables, and testing guide
- `bawbel version` now shows Stage 3 sandbox status — active / Docker not running / disabled
- New env vars: `BAWBEL_SANDBOX_ENABLED`, `BAWBEL_SANDBOX_IMAGE`, `BAWBEL_SANDBOX_TIMEOUT`, `BAWBEL_SANDBOX_NETWORK`

### Fixed
- **YARA `SyntaxError`** — `$pii10` declared but not referenced in `AVE_PIIExfiltration` condition; duplicate `$pipe11` string. Both fixed.
- **Cross-engine duplicate findings** — deduplication now uses a two-pass strategy: pass 1 deduplicates by `rule_id`, pass 2 deduplicates by `ave_id` across engines. Pattern engine findings take priority over YARA/Semgrep for the same AVE ID. Eliminates the "requires login" noise from semgrep findings overlapping with pattern findings.
- **Sandbox wiring** — sandbox call was a `# Future:` comment in `scanner.py`, never actually ran. Now properly wired into the pipeline.
- **Sandbox warning when image missing** — previously skipped silently; now logs a clear warning pointing to `docs/guides/engines.md`.

### Changed
- `BAWBEL_SANDBOX_IMAGE` default changed from `bawbel/sandbox:latest` to `default` — triggers hybrid resolution instead of a direct image reference
- Deduplication contract updated to two-pass strategy (see Fixed above)

### Detection coverage (v0.3.0)

| Engine  | Rules | AVE IDs covered | Status |
|---------|-------|-----------------|--------|
| Pattern | 15/15 | 00001–00015 | ✓ always active |
| YARA    | 15/15 | 00001–00015 | ✓ requires `[yara]` |
| Semgrep | 15/15 | 00001–00015 | ✓ requires `[semgrep]` |
| LLM     | all   | semantic analysis | ✓ requires `[llm]` + API key |
| Sandbox | 15 IOC patterns | network, fs, process | ✓ requires Docker |

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

---

[1.0.0]: https://github.com/bawbel/bawbel-scanner/releases/tag/v1.0.0
