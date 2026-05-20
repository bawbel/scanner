# Changelog

All notable changes to bawbel-scanner are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

---

## [1.2.2] - 2026-05-20

### Fixed

- **B1: `unknown` file profile over-suppression** - `_PROFILE_THRESHOLDS["unknown"]`
  was `0.80`, causing findings in files outside recognized paths (`docs/`, `examples/`,
  etc.) to be suppressed when confidence scored above the `skill` threshold (0.60) but
  below `unknown` (0.80). Changed to `0.60`. Files with unrecognized paths are now
  treated the same as skill files rather than penalized.

- **B1: `threshold` logic inconsistency** - FP-3 confidence scoring used a hardcoded
  branch `_CONFIDENCE_THRESHOLD if file_profile == "skill" else profile_threshold`,
  making `_PROFILE_THRESHOLDS["skill"]` unreachable. Simplified to always use
  `profile_threshold` which is already looked up from `_PROFILE_THRESHOLDS`.

- **B2: `--no-ignore` did not bypass FP-2 or FP-3** - The flag correctly bypassed
  inline suppression (Step 9) and justified suppression (Step 10) but had no effect
  on negation-context suppression (FP-2) or confidence scoring (FP-3). Added an
  early-continue at the top of the per-finding loop that sets `f.confidence = 1.0`
  and moves the finding directly to `active_findings` when `no_ignore` is set.

- **B3: `risk_score` ignored toxic flows** - `ScanResult.risk_score` only aggregated
  `aivss_score` across `findings`. A file with 0 active findings but 2 CRITICAL toxic
  flows reported `risk_score: 0.0` and label `CLEAN`. Fixed to include
  `tf.aivss_score` for all entries in `toxic_flows`. `is_clean` updated to also
  require `len(toxic_flows) == 0`.

- **LiteLLM botocore startup warnings** - `litellm` emitted two `WARNING` lines on
  every invocation attempting to pre-load AWS Bedrock and SageMaker response shapes
  when `botocore` is not installed. Suppressed by setting
  `logging.getLogger("LiteLLM").setLevel(logging.ERROR)` immediately after import in
  `llm_engine.py`.


---

## [1.2.0] - 2026-05-16

### Added

**Justified suppression and false positive feedback (Part 14)**

Two new suppression keywords on top of the existing `bawbel-ignore` system:

- `bawbel-ignore` with metadata fields (`reason`, `reviewer`, `reviewed`) declares a
  false positive permanently. The reason is recorded in the audit trail.
- `bawbel-accept` with an `expires` field declares an accepted risk. When the expiry
  date passes, the finding resurfaces automatically as an active finding on the next scan.

`bawbel accept` CLI command inserts justified suppression comments directly into source
files. `bawbel accept --list` shows all accepted findings. `bawbel accept --expiring-soon`
shows findings expiring within a configurable window and exits 1 for CI use.

Anonymous FP signals can be sent to PiranhaDB via `--report`. Only AVE ID, engine,
confidence score, and a hash of the match context are sent. No file content.

`ScanResult.accepted_findings` is a new field in JSON output containing full metadata
for each justified suppression.

**New detection rules**

Three new AVE records and pattern rules:

- `bawbel-hook-hijack` (AVE-2026-00046): MCP tool hook hijacking. CRITICAL, AIVSS 9.1.
  Detects skill files that register hooks to intercept or redirect tool execution calls.
- `bawbel-hardcoded-credential` (AVE-2026-00047): Hardcoded credentials. HIGH, AIVSS 7.8.
  Detects API keys, tokens, passwords, private keys, and URL-embedded credentials.
- `bawbel-unsafe-delegation` (AVE-2026-00048): Unsafe agent delegation chain. HIGH, AIVSS 8.2.
  Detects sub-agent spawning with inherited permissions and no trust boundary.

Pattern engine: 37 rules -> 40 rules.

**New commands**

- `bawbel creds <path>`: credential-focused scan, filters to AVE-2026-00047 and related
  rules. Same output format as `bawbel scan`. Supports `--recursive`, `--no-ignore`,
  `--fail-on-any`, `--format json`.
- `bawbel chain <path>`: delegation chain scanner, filters to AVE-2026-00048 and related
  rules. Same flags as `bawbel creds`.

**`bawbel report` improvements**

- Added `--recursive` / `-r` flag. `bawbel report ./skills/ --recursive` generates
  a full remediation report for every file in the directory.
- Added `--no-ignore` flag matching `bawbel scan`.

### Changed

- `scanner.py` Step 10 added: justified suppression runs after Step 9 (inline suppression).
  Expired accepted risks are re-surfaced as active findings at this stage.
- Pattern engine rule count: 37 -> 40.

### Fixed

- `pr-review.yml` regression-check job: missing `pip install -e .` caused scan import
  failures on clean repos.
- `ci.yml` test job: missing `pip install -e .` caused import failures.
- `ci.yml` Docker verify step: `python3 -c "..."` with f-strings caused shell brace
  expansion to mangle the script before Python saw it. Replaced with single-line
  assertion using no f-strings.
- `ci.yml` Docker verify step: wrong `aivss` field name (should be `aivss_score`),
  wrong threshold (9.0 should be 7.0 to match actual fixture score).

---

## [1.1.1] - 2026-05-07

### Fixed

- Added `<!-- mcp-name: io.github.bawbel/scanner -->` marker to README.md
  so the MCP official registry validator can verify PyPI package ownership.
  No functional changes. This is a registry submission requirement only.

---

## [1.1.0] - 2026-05-04

### Added

**`bawbel scan-server-card` and `bawbel ssc` (alias)**

New command that fetches `.well-known/mcp.json` (SEP-1649) from a server base URL
and scans all tool descriptions, parameter descriptions, and config schemas using
the full detection pipeline. The server-card attack surface exists at the discovery
layer before any tool call is made. This is the first dedicated scanner for it.

**Toxic flow detection**

`scanner/toxic_flows/` is a new 4-file modular package. After deduplication, the
scanner maps each finding to a capability tag and checks all capability pairs against
12 built-in flow definitions. When a toxic pair is found, a `ToxicFlow` object is
added to `ScanResult.toxic_flows` with a combined AIVSS score, attack chain
description, OWASP MCP mapping, and remediation steps.

The risk score in `ScanResult.risk_score` now considers toxic flows and is always
greater than or equal to the highest individual finding score.

Built-in chains: Credential Exfiltration (9.8), Remote Code Execution (9.7),
Supply Chain RCE (9.6), Goal Override + Execution (9.5), Lateral Movement + Execution
(9.4), Tool Poisoning + Exfiltration (9.3), Identity Spoof + Escalation (9.2),
Persistence + Exfiltration (9.1), Context Inject + Memory Write (8.9),
Goal Override + Exfiltration (8.8), Scope Expansion + Exfiltration (8.7),
Covert Channel + Persistence (8.6).

Adding a new flow requires one entry in `scanner/toxic_flows/flows.py`. No other
files need to change.

**`bawbel scan-conformance`, `bawbel conform` (alias)**

New command that scores an MCP server manifest against the MCP specification.
Accepts a local JSON file, a server base URL (fetches server-card), or a registry
name with `--registry`. Returns a score from 0 to 100, a grade from A+ to F, and
per-check results.

18 checks across 3 tiers:
- REQUIRED (weight 3): has-name, has-description, has-version, has-remotes,
  uses-https, tools-have-descriptions, tools-have-input-schema, tool-names-valid,
  tool-names-unique
- RECOMMENDED (weight 2): has-schema-ref, uses-streamable-http,
  tools-params-have-descriptions, tools-declare-required-params,
  no-deprecated-sse-transport
- BEST PRACTICE (weight 1): no-sensitive-params-in-headers, has-repository,
  description-not-too-long, tool-descriptions-not-too-long

A server is conformant when all applicable REQUIRED checks pass. SKIP results are
excluded from the score denominator so servers with no tools are not penalised for
tool-related checks.

**`bawbel pin`, `bawbel check-pins`, `bawbel cp` (alias)**

`scanner/pinner.py` is a new pinning engine. `bawbel pin <path>` hashes all
scannable files under a path and saves SHA-256 hashes to `.bawbel-pins.json`.
`bawbel check-pins <path>` compares current hashes against saved pins and reports
any files that have drifted.

Pins are stored in `.bawbel-pins.json` at the project root with `pinned_by` resolved
from `git config user.name`. The file should be committed to git so the whole team
shares the same pins and changes show up in code review.

`--fail-on-drift` exits with code 2 if any file has drifted, suitable for CI.

**OWASP MCP Top 10 mapping**

`scanner/owasp_mcp_map.py` maps all 45 AVE IDs to OWASP MCP Top 10 categories
(MCP01 through MCP10). Every finding in text output now shows an `OWASP MCP` line
alongside the existing `OWASP` line. Every finding in JSON output includes an
`owasp_mcp` field. The full mapping table is at `scanner/OWASP_MCP_MAPPING.md`.

**AVE records 41-45**

Five new records covering the MCP 2026 attack surface:
- AVE-2026-00041: MCP Server-Card Injection (CRITICAL 9.3)
- AVE-2026-00042: REPL Code Mode Payload Injection (CRITICAL 9.1)
- AVE-2026-00043: MCP App UI Payload Injection (HIGH 8.4)
- AVE-2026-00044: Async Task Result Poisoning (HIGH 8.6)
- AVE-2026-00045: Cross-App-Access Escalation (CRITICAL 9.0)

AVE-2026-00045 covers the MCP 2026 Cross-App-Access feature where a low-trust
server can pivot to a high-trust server via a shared agent session.

**CLI modular refactor**

`scanner/cli.py` (~890 lines) was refactored into a package at `scanner/cli/`.
Each command is in its own file. Shared rendering, constants, and formatters live
in `scanner/cli/shared/`. Adding a new command requires one new file and 3 lines
in `scanner/cli/__init__.py`.

**Command shortcuts**

`bawbel ssc` is an alias for `bawbel scan-server-card`.
`bawbel conform` is an alias for `bawbel scan-conformance`.
`bawbel cp` is an alias for `bawbel check-pins`.

**PiranhaDB v1.1**

`api.piranha.bawbel.io` expanded from 4 endpoints to 14. New endpoints cover
registry scan results, GitHub skill repo scans, ecosystem stats, and an on-demand
`POST /scan` endpoint. The store layer is abstracted so PostgreSQL and Redis can be
enabled by setting `DATABASE_URL` and `REDIS_URL` environment variables with no
code changes. OWASP MCP mapping is computed at response time from a built-in map
in `store/owasp_mcp_map.py`.

### Fixed

- YARA `AVE_A2AInjection` false positive: the condition used `("inject" or ...)` as
  a string literal in a boolean context which evaluates to `true` always. The rule
  now requires explicit attack phrases or a combination of an agent-type string and
  an attack-verb string. This fixes the false positive on `agenttrust/mcp-server`.
- Added `scanner/cli/__main__.py` so `python -m scanner.cli` works after the CLI
  refactor. Previously caused `No module named scanner.cli.__main__` in Docker smoke
  tests.
- Removed unused `B607` nosec tag from `scanner/pinner.py` which caused bandit to
  exit non-zero in strict mode.

### Breaking changes

None. All existing commands, JSON output fields, and Python API are unchanged.
`toxic_flows` is a new additive field on `ScanResult` that defaults to `[]`.
`owasp_mcp` is a new additive field on finding JSON output.

---

## [1.0.1] - 2026-04-28

### Fixed

- Pattern engine only reported the first matching line per rule per file. Fixed in
  `scanner/engines/pattern.py` by removing the `break` after first match and tracking
  matched lines with `rule_matched_lines: set[int]`.
- Deduplication in `scanner/scanner.py` changed from single-pass `{rule_id: Finding}`
  to two-pass `{(rule_id, line): Finding}` then `{(ave_id, line): Finding}` for
  cross-engine dedup. Previously only the first finding per rule was kept regardless
  of line number.

---

## [1.0.0] - 2026-04-25

### Added

**Detection: Pattern Engine (37 rules, AVE-2026-00001 to 00040)**

- AVE records 16-25: 10 new agentic-native attack classes including RAG injection
  (00016), MCP server impersonation (00017), tool result manipulation (00018),
  agent memory poisoning (00019), A2A cross-agent injection (00020), autonomous
  action without confirmation (00021), scope creep (00022), context window flooding
  (00023), content-type mismatch via Magika (00024), and conversation history
  injection (00025).
- AVE records 26-40: 15 new advanced attack classes including tool output
  exfiltration (00026), multi-turn instruction persistence (00027), file prompt
  injection (00028), homoglyph and Unicode obfuscation via YARA (00029), false role
  claim privilege escalation (00030), feedback loop and RLHF poisoning (00031),
  internal network reconnaissance (00032), unsafe deserialization and eval (00033),
  dynamic third-party skill import (00034), sensor and telemetry falsification via
  YARA (00035), lateral movement (00036), vision prompt injection (00037), excessive
  agency (00038), steganographic covert channel (00039), and insecure output
  handling (00040).

**Detection: YARA Engine (39 rules)**

- 24 new YARA rules covering AVE-2026-00016 through 00040.
- `AVE_HomoglyphAttack` (00029): binary-level detection of zero-width characters
  (U+200B, U+200C, U+200D, U+2060, U+FEFF) and bidirectional override codes
  (U+202E, U+202D).
- `AVE_EnvManipulation` (00035): sensor and telemetry falsification patterns.

**Detection: Semgrep Engine (41 rules)**

- 26 new Semgrep rules covering AVE-2026-00002 through 00005 (previously missing)
  and AVE-2026-00016 through 00040.
- Fixed 4 original rules missing `ave_id` metadata.
- Fixed `ave-base64-encoded-payload` severity from `WARNING` to `ERROR` (HIGH 7.9).

**Detection: Stage 0 Magika Engine**

- `scanner/engines/magika_engine.py`: ML-based file type verification that runs
  before all text analysis. Catches ELF binaries, Windows PE32, Python pickles, PHP
  scripts, and shell scripts disguised as `.md`, `.yaml`, `.json`, or `.txt` files.
  Mapped to AVE-2026-00024. Install with `pip install "bawbel-scanner[magika]"`.

**Detection: Meta-Analyzer (FP-4)**

- `scanner/engines/meta_analyzer.py`: LLM-based false positive filter. One call per
  file covers all medium-confidence findings (0.35 to 0.80). Verdicts are `real`
  (+0.15 confidence), `false_positive` (suppressed), and `needs_review` (-0.05).
  Skips silently if no LLM is configured.

**False Positive Reduction (5-layer system)**

- FP-1: Code fence stripping replaces content inside ` ``` ` and `~~~` blocks with
  blank lines before analysis. Line numbers remain accurate. About 60% FP reduction
  on documentation files.
- FP-2: Negation context analysis suppresses findings where the trigger phrase is
  clearly an example or warning.
- FP-3: Per-finding confidence scores (0.0 to 1.0) with context-aware penalties and
  boosts.
- FP-4: LLM secondary review of medium-confidence findings.
- FP-5: File-type scan profiles with different confidence thresholds per type
  (skill=0.60, mcp_manifest=0.55, documentation=0.85, unknown=0.80).

Validation result: 21 documentation files produce 0 active findings.

**Suppression system**

- Inline suppression with `<!-- bawbel-ignore -->`, `<!-- bawbel-ignore: rule_id -->`,
  and `<!-- bawbel-ignore: AVE-2026-00001 -->`. Also supports `#` and `//` styles.
- Block suppression with `<!-- bawbel-ignore-start -->` and `<!-- bawbel-ignore-end -->`.
- `.bawbelignore` file with gitignore-style path patterns.
- `--no-ignore` flag and `BAWBEL_NO_IGNORE=true` env var for audit mode.
- Suppressed findings move to `ScanResult.suppressed_findings` and always appear in
  JSON and SARIF output.

**CLI: new commands**

- `bawbel init`: scaffolds `.bawbelignore`, `bawbel.yml`, and CI workflow in the
  project root.
- `bawbel scan --watch`: re-scans on every file change using `watchdog`.
- `bawbel report`: full remediation guide with AVE ID, AIVSS score, OWASP mapping,
  and fix instructions per finding.

**Integrations**

- GitHub Action `uses: bawbel/integrations@v1` for one-line CI/CD integration.
- VS Code Extension on the Marketplace. Zero setup, auto-installs CLI, inline
  diagnostics, auto-scan on save.

**PiranhaDB API**

- `api.piranha.bawbel.io` updated to serve all 40 AVE records.
- `sync_records.py` syncs records from `bawbel/ave` on every deploy.
- `POST /reload` endpoint for hot-reloading records without a container restart.

### Fixed

- Docker smoke test pointed at a removed fixture file. Fixed path to
  `tests/fixtures/skills/malicious/malicious_skill.md`.
- Pattern engine docstring contained `\s+` which caused `SyntaxWarning`.
- Semgrep `ave_id` metadata missing from 4 rules.
- YARA severity label mismatches on 5 rules corrected to match CVSS scores.

---

## [0.3.0] - 2026-04-21

### Added

- Full YARA coverage: 15 rules (was 3, now 15) covering AVE-2026-00001 through 00015.
- Full Semgrep coverage: 15 rules (was 5, now 15) covering AVE-2026-00001 through
  00015.
- Stage 3 behavioral sandbox in `scanner/engines/sandbox_engine.py`. Docker container
  runs with `--network none`, `--memory 256m`, `--cap-drop ALL`, and `--read-only`.
  Hybrid image resolution: local cache then Docker Hub then bundled local build. Works
  offline and in air-gapped environments. Enable with `BAWBEL_SANDBOX_ENABLED=true`.
- `[watch]` extra: `pip install "bawbel-scanner[watch]"` for watch mode.
- `.env.example` with all environment variable documentation.

### Fixed

- YARA `SyntaxError`: `$pii10` declared but unreferenced in `AVE_PIIExfiltration`,
  and duplicate `$pipe11` string. Both fixed.
- Cross-engine duplicate findings: added two-pass deduplication (pass 1 by `rule_id`,
  pass 2 by `ave_id` across engines).
- Sandbox was a commented-out stub. Now wired into the pipeline.

---

## [0.2.0] - 2026-04-20

### Added

- Stage 2 LLM semantic analysis via LiteLLM supporting Anthropic, OpenAI, Gemini,
  Mistral, Groq, Ollama, and 100+ other providers. Install with
  `pip install "bawbel-scanner[llm]"`.
- Full AVE ID coverage: all 15 pattern rules linked to AVE records 00001 through 00015.
- 7 new AVE records: AVE-2026-00009 through 00015 covering jailbreak, hidden
  instruction, dynamic tool call, permission escalation, PII exfiltration, trust
  escalation, and system prompt leak.
- `BAWBEL_LLM_MODEL` and `BAWBEL_LLM_ENABLED` env vars.

### Fixed

- Semgrep `code=7`: YAML escaping and float metadata values broke validation on
  semgrep v1.159.0. Fixed with double-quoted regex patterns and quoted float scores.
- Semgrep URL fetch rule regex missed natural language patterns like "fetch your
  instructions from https://...". Fixed.
- `pip install "bawbel-scanner[llm]"` dependency conflict: pinned
  `jsonschema~=4.25.1` to resolve conflict between semgrep and litellm.

---

## [0.1.0] - 2026-04-19

First public release.

### Added

- `bawbel scan`: scan a file or directory with `--recursive`, `--fail-on-severity`,
  and `--format text|json|sarif`.
- `bawbel report`: remediation guide per finding with AVE ID, AIVSS, OWASP
  mapping, and fix instructions.
- `bawbel version`: installed version and engine status.
- 15 built-in pattern rules (3 CRITICAL, 10 HIGH, 2 MEDIUM) covering
  AVE-2026-00001 through 00008.
- Stage 1a pattern engine (stdlib only, always active), Stage 1b YARA engine
  (3 rules), Stage 1c Semgrep engine (5 rules), and Stage 2 LLM via LiteLLM.
- JSON, SARIF 2.1.0, and text output formats.
- `scan()` public API that never raises.
- 145 passing tests including golden fixture, security invariants, CLI, and rule tests.
- Docker with three build targets: production, dev, and test.

---

[Unreleased]: https://github.com/bawbel/scanner/compare/v1.2.2...HEAD
[1.2.2]: https://github.com/bawbel/scanner/releases/tag/v1.2.2
[1.2.1]: https://github.com/bawbel/scanner/releases/tag/v1.2.1
[1.2.0]: https://github.com/bawbel/scanner/releases/tag/v1.2.0
[1.1.1]: https://github.com/bawbel/scanner/releases/tag/v1.1.1
[1.1.0]: https://github.com/bawbel/scanner/releases/tag/v1.1.0
[1.0.1]: https://github.com/bawbel/scanner/releases/tag/v1.0.1
[1.0.0]: https://github.com/bawbel/scanner/releases/tag/v1.0.0
[0.3.0]: https://github.com/bawbel/scanner/releases/tag/v0.3.0
[0.2.0]: https://github.com/bawbel/scanner/releases/tag/v0.2.0
[0.1.0]: https://github.com/bawbel/scanner/releases/tag/v0.1.0
