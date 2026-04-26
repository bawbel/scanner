# Changelog

All notable changes to bawbel-scanner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

# [1.0.0] — 2026-04-25

### Added

**Detection — Pattern Engine (37 rules, AVE-2026-00001 to 00040)**

- **AVE records 16–25** — 10 new agentic-native attack classes:
  RAG injection (00016), MCP server impersonation (00017), tool result manipulation (00018),
  agent memory poisoning (00019), A2A cross-agent injection (00020), autonomous action
  without confirmation (00021), scope creep (00022), context window flooding (00023),
  content-type mismatch / binary disguised as skill — Magika only (00024),
  conversation history injection (00025).
- **AVE records 26–40** — 15 new advanced attack classes:
  tool output exfiltration (00026), multi-turn instruction persistence (00027),
  file/document prompt injection (00028), homoglyph and Unicode obfuscation — YARA only (00029),
  false role claim privilege escalation (00030), feedback loop and RLHF poisoning (00031),
  internal network reconnaissance (00032), unsafe deserialization and eval (00033),
  dynamic third-party skill import supply chain (00034), sensor/telemetry falsification —
  YARA only (00035), lateral movement via internal pivot (00036),
  vision/image prompt injection (00037), excessive agency / unbounded tool use (00038),
  steganographic covert channel exfiltration (00039), insecure output handling /
  SQL-XSS-shell injection (00040).
- Pattern engine: **37 rules** total (up from 15 in v0.3.0), covering AVE-2026-00001
  through 00040 with intentional gaps: 00024 (Magika engine), 00029 and 00035 (YARA engine).

**Detection — YARA Engine (39 rules)**

- 24 new YARA rules added (was 15, now 39):
  - AVE-2026-00016 through 00025 — all agentic-native attack classes
  - AVE-2026-00026 through 00040 — all advanced attack classes
  - `AVE_HomoglyphAttack` (00029) — binary-level detection of zero-width characters
    (U+200B–U+200D, U+2060, U+FEFF) and bidirectional override codes (U+202E, U+202D)
  - `AVE_EnvManipulation` (00035) — sensor and telemetry falsification patterns

**Detection — Semgrep Engine (41 rules)**

- 26 new Semgrep rules added (was 15, now 41):
  - AVE-2026-00002 through 00005 — MCP tool poisoning, env exfiltration, shell pipe,
    destructive command (previously missing from Semgrep)
  - AVE-2026-00016 through 00025 — all agentic-native attack classes
  - AVE-2026-00026 through 00040 — all advanced attack classes
- Fixed: 4 original rules missing `ave_id` metadata
  (`ave-hardcoded-secret-in-skill`, `ave-base64-encoded-payload`,
  `ave-shell-injection-pattern`, `ave-rm-rf-pattern`)
- Fixed: `ave-base64-encoded-payload` severity corrected `WARNING` → `ERROR` (HIGH 7.9)

**Detection — Stage 0 Magika Engine**

- `scanner/engines/magika_engine.py` — ML-based file type verification (Stage 0).
  Runs before all text analysis. Catches ELF binaries, Windows PE32, Python pickles,
  PHP scripts, and shell scripts disguised as `.md`, `.yaml`, `.json`, or `.txt` skill files.
  Mapped to AVE-2026-00024. Install with `pip install "bawbel-scanner[magika]"`.

**Detection — Meta-Analyzer (FP-4)**

- `scanner/engines/meta_analyzer.py` — LLM-based false positive filter.
  One call per file covers all medium-confidence findings (0.35–0.80).
  Verdicts: `real` (+0.15 confidence), `false_positive` (suppressed), `needs_review` (−0.05).
  Skips silently if no LLM configured.
- `BAWBEL_META_ANALYZER_ENABLED` env var (default: `true`)
- `BAWBEL_META_MIN_CONFIDENCE` / `BAWBEL_META_MAX_CONFIDENCE` — analysis range

**False Positive Reduction — 5-layer system**

- **FP-1 — Code fence stripping**: `_strip_code_fences()` replaces content inside ` ``` `
  and `~~~` blocks with blank lines before pattern/YARA/Semgrep analysis.
  Line numbers remain accurate. Sandbox and suppression receive original content.
  ~60% FP reduction on documentation files.
- **FP-2 — Negation context**: preceding-line context analysis suppresses findings where
  the trigger phrase is clearly an example or warning ("never do this:", "bad example:").
- **FP-3 — Confidence scoring**: per-finding confidence scores (0.0–1.0) with
  context-aware penalties (docs path, code fences, negation) and boosts
  (first 30 lines, multi-engine agreement, skill filename).
- **FP-4 — Meta-analyzer**: LLM secondary review of medium-confidence findings.
- **FP-5 — File-type scan profiles**: classification into `skill` / `mcp_manifest` /
  `documentation` / `unknown` with different confidence thresholds per type
  (skill=0.60, mcp_manifest=0.55, documentation=0.85, unknown=0.80).
- Validation: 21 documentation files → 0 active findings.

**Suppression system**

- **Inline suppression** — `<!-- bawbel-ignore -->` suppresses all findings on that line.
  Rule-specific: `<!-- bawbel-ignore: bawbel-external-fetch -->`.
  AVE ID specific: `<!-- bawbel-ignore: AVE-2026-00001 -->`.
  Also supports `# bawbel-ignore` and `// bawbel-ignore` comment styles.
- **Block suppression** — `<!-- bawbel-ignore-start -->` / `<!-- bawbel-ignore-end -->`
  wraps entire sections. Supports `#` and `//` comment styles.
- **`.bawbelignore` file** — gitignore-style path patterns to suppress files or directories.
- **`--no-ignore` flag** — overrides ALL suppressions for security audits.
  Also `BAWBEL_NO_IGNORE=true`.
- Suppressed findings move to `ScanResult.suppressed_findings` — always present in
  JSON/SARIF output for audit completeness.
- Every suppression logged at INFO level.

**CLI — new commands and flags**

- **`bawbel init`** — scaffolds `.bawbelignore`, `bawbel.yml`, and CI workflow in project root.
  Discovers skill and MCP files, shows next steps.
- **`bawbel scan --watch`** — watch mode. Re-scans on every file change using `watchdog`.
  Install with `pip install "bawbel-scanner[watch]"`. Works with `--recursive`.
- **`bawbel report`** — full remediation guide: AVE ID, CVSS-AI score, OWASP mapping,
  step-by-step fix instructions per finding.

**Integrations**

- **GitHub Action** — `uses: bawbel/bawbel-integrations@v1`. One-line CI/CD integration:
  installs scanner, runs scan, uploads SARIF to GitHub Security tab.
  Inputs: `path`, `fail-on-severity`, `format`, `recursive`, `no-ignore`, `version`, `extras`.
- **VS Code Extension** — search "Bawbel Scanner" in Marketplace. Zero setup.
  Auto-installs CLI on first activation. Inline diagnostics, status bar,
  auto-scan on save, `Cmd+Shift+B` shortcut.
- **Docker** — three build targets: `production` (minimal, non-root), `dev` (hot-reload),
  `test` (runs suite and exits). Docker Compose with 7 services.

**PiranhaDB API**

- `api.piranha.bawbel.io` updated to serve all 40 AVE records.
- `sync_records.py` — syncs records automatically from `bawbel/bawbel-ave` on every deploy.
  Supports `GITHUB_TOKEN` for authenticated requests (60 → 5000 req/hr rate limit).
  Graceful fallback to bundled records if GitHub is unreachable.
  Removes stale records no longer in the repo.
- `start.sh` wired as container entrypoint — runs sync then starts uvicorn.
  Records stay current on every Railway/Render deploy with no image rebuild.
- `_scanner_rule()` mapping extended to all 40 AVE IDs (was 8).
- Removed `PIRANHA_ENV=production` cache-freeze bug — cache now always loaded fresh
  after sync at startup.
- `POST /reload` endpoint — hot-reload records cache without container restart.

**Documentation**

- Docs site (`docs/index.html`) fully rebuilt:
  keyboard search with `↑↓` navigation and `/` shortcut, live two-terminal watch mode
  demo, copy buttons with toast confirmation on all 50 code blocks, page transitions,
  `bawbel watch` reference page, static `v1.0.0` badge.
- `docs/guides/engines.md` — detection engines guide with architecture diagrams.
- `docs/guides/false-positive-reduction.md` — 5-layer FP reduction system.
- `docs/guides/cicd-integration.md`, `getting-started.md`, `configuration.md` updated.

**Tests**

- **182 test methods** across 19 test classes (up from 145 in v0.3.0).
- `TestAVERecordsV2` — 43 new tests covering AVE records 26–40,
  positive detection and negative (no false positive) for each rule.
- `TestCodeFenceStripping` — 12 tests for FP-1 code fence stripping.
- `TestConfidenceScoring`, `TestPrecedingLineContext`, `TestMagikaEngine` added.

### Fixed

- **Docker smoke test** — CI workflow pointed at removed `tests/malicious_skill.md`.
  Fixed to `tests/fixtures/skills/malicious/malicious_skill.md`.
- **Pattern engine docstring** — `\s+` in docstring caused `SyntaxWarning`. Fixed.
- **Semgrep `ave_id` metadata** — 4 rules missing `ave_id` field. All fixed.
- **YARA severity labels** — 5 rules had severity label mismatches vs CVSS score
  (e.g. CRITICAL label on a 6.2 score). All corrected to match pattern engine ground truth.

### Detection coverage (v1.0.0)

| Engine  | Rules | AVE IDs covered           | Notes                              |
|---------|-------|---------------------------|------------------------------------|
| Pattern | 37    | 00001–00040 (excl. 24,29,35) | stdlib only, always active      |
| YARA    | 39    | 00001–00040               | includes binary Unicode detection  |
| Semgrep | 41    | 00001–00040 (excl. 29,35) | structural pattern matching        |
| LLM     | —     | semantic / obfuscated     | requires `[llm]` + API key         |
| Sandbox | —     | runtime behavioural       | requires Docker                    |
| Magika  | —     | content-type mismatch (00024) | requires `[magika]`            |

---

## [0.3.0] — 2026-04-21

### Added
- **Full YARA coverage — 15/15 rules** — 12 new YARA rules covering AVE-2026-00004
  through 00015. Every attack class now has pattern, YARA, and Semgrep detection.
- **Full Semgrep coverage — 15/15 rules** — 10 new Semgrep rules covering
  AVE-2026-00007 through 00015. All rules validated against semgrep v1.159.0.
- **Stage 3 behavioral sandbox — hybrid image strategy** (`scanner/engines/sandbox_engine.py`):
  - Docker container — `--network none`, `--memory 256m`, `--cap-drop ALL`, `--read-only`
  - **Hybrid image resolution** — local cache → Docker Hub pull → bundled local build fallback
  - Works offline and in air-gapped environments via bundled `scanner/sandbox/Dockerfile`
  - `scanner/sandbox/harness.py` — text-based analysis harness (v0.3.x); eBPF tracing in v1.0
  - Enable with `BAWBEL_SANDBOX_ENABLED=true`
- **`[watch]` extra** — `pip install "bawbel-scanner[watch]"` installs `watchdog`
- **`.env.example`** — complete environment variable template
- **`docs/guides/engines.md`** — detection engines guide with architecture diagrams
- `bawbel version` now shows Stage 3 sandbox status
- New env vars: `BAWBEL_SANDBOX_ENABLED`, `BAWBEL_SANDBOX_IMAGE`,
  `BAWBEL_SANDBOX_TIMEOUT`, `BAWBEL_SANDBOX_NETWORK`

### Fixed
- **YARA `SyntaxError`** — `$pii10` declared but unreferenced in `AVE_PIIExfiltration`;
  duplicate `$pipe11` string. Both fixed.
- **Cross-engine duplicate findings** — two-pass deduplication: pass 1 by `rule_id`,
  pass 2 by `ave_id` across engines. Pattern takes priority over YARA/Semgrep.
- **Sandbox wiring** — sandbox call was a `# Future:` comment. Now wired into pipeline.
- **Sandbox warning when image missing** — previously silent; now logs a clear warning.

### Changed
- `BAWBEL_SANDBOX_IMAGE` default changed to `default` — triggers hybrid resolution
- Deduplication updated to two-pass strategy

### Detection coverage (v0.3.0)

| Engine  | Rules | AVE IDs covered | Status                  |
|---------|-------|-----------------|-------------------------|
| Pattern | 15    | 00001–00015     | always active           |
| YARA    | 15    | 00001–00015     | requires `[yara]`       |
| Semgrep | 15    | 00001–00015     | requires `[semgrep]`    |
| LLM     | —     | semantic        | requires `[llm]` + key  |
| Sandbox | 15    | network/fs/proc | requires Docker         |

---

## [0.2.0] — 2026-04-20

### Added
- **LLM Stage 2** — semantic analysis via [LiteLLM](https://docs.litellm.ai) supporting
  any provider: Anthropic, OpenAI, Gemini, Mistral, Groq, Ollama, and 100+ more.
  Install with `pip install "bawbel-scanner[llm]"`.
- **Full AVE ID coverage** — all 15 pattern rules linked to AVE records 00001–00015.
- **7 new AVE records** — AVE-2026-00009 through 00015 covering jailbreak, hidden
  instruction, dynamic tool call, permission escalation, PII exfiltration, trust
  escalation, and system prompt leak.
- `BAWBEL_LLM_MODEL` env var — explicit model override for any LiteLLM model string
- `BAWBEL_LLM_ENABLED` env var — set `false` to disable Stage 2 entirely
- `bawbel version` now shows active LLM model when Stage 2 is enabled

### Fixed
- **Semgrep `code=7`** — YAML escaping and float metadata values broke validation on
  semgrep v1.159.0. Fixed: double-quoted regex patterns, quoted float scores.
- **Semgrep URL fetch rule regex** — original pattern required literal `(` and missed
  natural language like `fetch your instructions from https://...`. Fixed.
- **`pip install "bawbel-scanner[llm]"` dependency conflict** — pinned
  `jsonschema~=4.25.1` to resolve conflict between semgrep and litellm.
- **`requirements.txt`** — removed unused `requests` dependency.

### Changed
- LLM Stage 2 rewritten to use LiteLLM. Breaking: `[llm]` extra now installs
  `litellm` instead of `anthropic+openai`.

---

## [0.1.0] — 2026-04-19

First public release.

### Added

**CLI**
- `bawbel scan` — scan a file or directory with `--recursive`, `--fail-on-severity`,
  `--format text|json|sarif`
- `bawbel report` — remediation guide per finding: AVE ID, CVSS-AI, OWASP mapping,
  fix instructions
- `bawbel version` — installed version and engine status
- `bawbel --version` — quick version string for CI scripts

**Detection**
- 15 built-in pattern rules (3 CRITICAL, 10 HIGH, 2 MEDIUM)
- Stage 1a: pattern engine — stdlib only, zero dependencies, always runs
- Stage 1b: YARA engine — optional, 3 rules
- Stage 1c: Semgrep engine — optional, 5 rules
- Stage 2: LLM semantic analysis via LiteLLM

**Output formats**
- `text` — terminal output with severity icons
- `json` — structured output for CI/CD and SIEM
- `sarif` — SARIF 2.1.0 for GitHub Security tab and IDE plugins

**Core**
- `scan()` public API — never raises, all errors in `ScanResult.error`
- Stable error codes E001–E020 in `scanner/messages.py`
- Security hardening — symlink protection, 10MB file size limit

**Docker**
- Three build targets: `production`, `dev`, `test`
- Docker Compose with 7 services

**Developer experience**
- 145 passing tests including golden fixture, security invariants, CLI, pattern rules
- `CONTRIBUTING.md` and `SECURITY.md`
- Full documentation at `bawbel.io/docs`

### AVE Records Covered (v0.1.0)
- AVE-2026-00001 — Metamorphic payload via external instruction fetch (CRITICAL 9.4)
- AVE-2026-00002 — MCP tool description prompt injection (HIGH 8.7)
- AVE-2026-00003 — Environment variable exfiltration (HIGH 8.5)
- AVE-2026-00004 — Shell pipe injection (HIGH 8.8)
- AVE-2026-00005 — Destructive command (CRITICAL 9.1)
- AVE-2026-00006 — Cryptocurrency drain (CRITICAL 9.6)
- AVE-2026-00007 — Goal override (HIGH 8.1)
- AVE-2026-00008 — Persistence / self-replication (HIGH 8.4)

---

[Unreleased]: https://github.com/bawbel/bawbel-scanner/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bawbel/bawbel-scanner/releases/tag/v1.0.0
[0.3.0]: https://github.com/bawbel/bawbel-scanner/releases/tag/v0.3.0
[0.2.0]: https://github.com/bawbel/bawbel-scanner/releases/tag/v0.2.0
[0.1.0]: https://github.com/bawbel/bawbel-scanner/releases/tag/v0.1.0
