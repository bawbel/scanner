# Project Structure Guide

Complete reference for every file and directory in `bawbel-scanner`.
Read this before contributing or editing anything.

Files marked `(target)` do not exist yet — they are where code will move
during the refactoring described in `docs/guides/refactoring-guide.md`.
Files marked `(current)` exist today.

---

## Full directory map

```
bawbel-scanner/
│
├── ── Root governance ──────────────────────────────────────────────────────
├── CLAUDE.md                    AI governance — read first every session
├── LANGUAGE.md                  Domain vocabulary — use these exact names
├── ARCHITECTURE.md              Layer model, module map, migration status
├── CONTRIBUTING.md              Contributor guide
├── PRODUCT.md                   Vision, roadmap, brand, standards alignment
├── PROJECT_STRUCTURE.md         This file
├── HOW-TO-USE.md                Sequence guide for all governance files
├── README.md                    Public-facing docs — PyPI and GitHub landing
├── SECURITY.md                  Vulnerability disclosure policy
├── LICENSE                      Apache 2.0
├── CHANGELOG.md                 Version history
│
├── ── Build and packaging ──────────────────────────────────────────────────
├── pyproject.toml               Build system, dependencies, extras, entry points
│                                [project.scripts] bawbel = "scanner.cli:cli"
│                                [project.optional-dependencies]
│                                yara, semgrep, llm, magika, sandbox, dev, all
│
├── ── Scanner config ───────────────────────────────────────────────────────
├── bawbel.yml                   Project scanner config (read by GitHub Action)
│                                scan.recursive, fail_on_severity, format
├── .bawbelignore                Paths suppressed during self-scan
│                                docs/**, tests/fixtures/skills/clean/**, examples/**
├── .pre-commit-hooks.yaml       Pre-commit hook definitions
│                                id: bawbel-scan (pattern only, ~15ms)
│                                id: bawbel-scan-all (all engines)
│
├── ── Git and secrets ──────────────────────────────────────────────────────
├── .gitignore                   Standard Python + bawbel-specific ignores
│                                docs/agents/handoffs/, .env, .venv/, dist/
├── .gitleaks.toml               Gitleaks secrets scanning config
│                                Suppress false positives on test fixtures
│                                that contain intentional credential patterns
│
├── ── Environment ──────────────────────────────────────────────────────────
├── .env.example                 Template for all environment variables
│                                BAWBEL_SANDBOX_ENABLED=false
│                                BAWBEL_MAGIKA_ENABLED=false
│                                ANTHROPIC_API_KEY=
│                                OPENAI_API_KEY=
│                                PIRANHA_API_URL=https://api.piranha.bawbel.io
│                                BAWBEL_NO_IGNORE=false
├── .env                         GITIGNORED — local overrides, never committed
│
├── ── Docker ───────────────────────────────────────────────────────────────
├── Dockerfile                   Scanner image for CI and sandbox engine
│                                Multi-stage: builder (pip install) → runtime
│                                Used by: bawbel/integrations GitHub Action
│                                         Stage 3 behavioral sandbox
├── docker-compose.yml           Local development stack
│                                services: scanner (CLI), piranha (API), sandbox
│                                Mounts: ./scanner, ./tests, ./rules
├── .dockerignore                Files excluded from Docker build context
│                                .venv/, __pycache__, tests/, docs/, .env
│
├── ── MCP Registry ─────────────────────────────────────────────────────────
├── server.json                  MCP Registry manifest for io.github.bawbel/scanner
│                                version must match PyPI release
│                                <!-- mcp-name: io.github.bawbel/scanner -->
│                                in README.md verifies PyPI ownership
│
├── ── CI/CD ────────────────────────────────────────────────────────────────
├── action.yml                   GitHub Action definition (in bawbel/integrations)
│                                For bawbel/scanner: lives in bawbel/integrations repo
│                                This file: .github/workflows/ are in scanner repo
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml               Run tests on push and PR
│   │   ├── publish.yml          PyPI publish on release tag
│   │   └── bawbel-scan.yml      Self-scan using bawbel/integrations@v2
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── PULL_REQUEST_TEMPLATE.md
│
├── ── Claude Code skills ────────────────────────────────────────────────────
├── .claude/
│   └── skills/
│       ├── setup-bawbel-skills/SKILL.md   Bootstrap
│       ├── tdd/                           Red-green-refactor
│       │   ├── SKILL.md
│       │   ├── deep-modules.md
│       │   ├── interface-design.md
│       │   ├── mocking.md
│       │   ├── refactoring.md
│       │   └── tests.md
│       ├── grill-with-docs/SKILL.md       Design interrogation
│       ├── design-an-interface/SKILL.md   3 parallel designs
│       ├── to-prd/SKILL.md                Conversation → PRD
│       ├── to-issues/SKILL.md             PRD → GitHub issues
│       ├── improve-codebase-architecture/SKILL.md
│       ├── diagnose/SKILL.md              Reproduce-Minimize-Fix
│       ├── zoom-out/SKILL.md              Read before editing
│       ├── handoff/SKILL.md               Session notes
│       └── git-guardrails/SKILL.md        Block dangerous commands
│
├── ── Constants ────────────────────────────────────────────────────────────
├── config/
│   └── default.py               Project-wide constants
│                                MAX_MATCH_LENGTH = 80
│                                MAX_FILE_SIZE_BYTES = 100 * 1024
│                                DEFAULT_FAIL_SEVERITY = "high"
│                                BAWBEL_SANDBOX_ENABLED (reads env)
│                                BAWBEL_MAGIKA_ENABLED (reads env)
│
├── ── Scanner package ──────────────────────────────────────────────────────
├── scanner/
│   ├── __init__.py              Package init — exports __version__
│   │
│   ├── scanner.py               Orchestrator — scan() public entry point
│   │                            scan(), _make_finding(), _error_result()
│   │                            Delegates to core/, engines/, suppression/
│   │                            See ARCHITECTURE.md migration status table
│   │
│   ├── messages.py              Logs class — Rich-formatted CLI output
│   │                            Scan summaries, finding display, tables
│   │                            Used by: engines/, cli/, scanner.py
│   │
│   ├── utils.py                 Shared utilities
│   │                            get_logger(name) → logging.Logger
│   │                            truncate_match(match, max_len=80) → str
│   │
│   ├── owasp_mcp_map.py         AVE ID → OWASP MCP Top 10 mapping
│   │                            Maps findings to MCP01-MCP10 categories
│   │                            Used by: Finding serialization, SARIF output
│   │
│   ├── pinner.py                SHA-256 pin management
│   │                            bawbel pin ./skills/ → .bawbel-pins.json
│   │                            bawbel check-pins → diff against stored pins
│   │
│   ├── fetcher.py               Remote content fetcher (IMPURE — network I/O)
│   │                            Fetches MCP server-cards from .well-known/
│   │                            Extracts attack surface into flat text for scan
│   │                            Used by: cli/cmd_ssc.py
│   │
│   ├── bawbel_pre_commit.py     Pre-commit entry point
│   │                            Invoked by .pre-commit-hooks.yaml
│   │                            Wraps scan() for pre-commit file list format
│   │                            Exits 0 (clean) or 1 (findings >= threshold)
│   │
│   ├── pre_commit_init.py       Pre-commit initialisation helper
│   │                            First-run setup when bawbel-scan is invoked
│   │                            via pre-commit for the first time
│   │
│   ├── core/                    PURE — no I/O of any kind
│   │   │                        No subprocess, requests, open, print
│   │   │                        Path used only for string introspection
│   │   │                        Tests run in milliseconds.
│   │   ├── preprocessor.py      FP-1: strip_code_fences(content) → str
│   │   ├── dedup.py             deduplicate(findings) → list[Finding]
│   │   ├── fp_pipeline.py       FP-2/3/5: classify_file, score_confidence,
│   │   │                        has_negation_context, run_fp_pipeline
│   │   ├── scoring.py           Re-exports calc_aivss, severity_from_aivss
│   │   │                        from scanner.models.severity
│   │   └── toxic_flows/
│   │       ├── detector.py      Chain detection logic
│   │       ├── flows.py         12 chain definitions
│   │       ├── models.py        ToxicFlow dataclass
│   │       └── capabilities.py  AVE ID → capability tag mapping
│   │                            Vocabulary for toxic flow detection
│   │
│   ├── models/                  DATA — no logic, no I/O
│   │   │                        Dataclasses only. No methods with logic.
│   │   ├── __init__.py          Re-exports Finding, ScanResult, Severity, SEVERITY_SCORES
│   │   ├── finding.py           Finding dataclass
│   │   │                        Evidence fields pending: confidence, evidence_stage,
│   │   │                        evidence_kind, evidence_basis, confidence_reason,
│   │   │                        derived — see Issue #69
│   │   ├── result.py            ScanResult dataclass
│   │   ├── severity.py          Severity enum, SEVERITY_SCORES, calc_aivss,
│   │   │                        severity_from_aivss, DEFAULT_AARF
│   │   ├── acceptance.py        AcceptedFinding, parse_expiry
│   │   │                        Justified suppression records
│   │   └── evidence.py          (pending Issue #69) evidence_stage enum,
│   │                            confidence_band enum
│   │
│   ├── engines/                 IMPURE — I/O allowed
│   │   │                        Subprocess, network, file reads.
│   │   │                        Calls core/ for pure logic.
│   │   ├── __init__.py          Re-exports: run_llm_scan etc.
│   │   ├── pattern_engine.py    Stage 1a: regex pattern rules
│   │   │                        run_pattern_scan(content) → list[Finding]
│   │   ├── yara_engine.py       Stage 1b: YARA binary/behavioral rules
│   │   ├── semgrep_engine.py    Stage 1c: Semgrep structural rules
│   │   ├── llm_engine.py        Stage 2: LLM semantic analysis
│   │   │                        run_llm_scan(), _parse_findings()
│   │   ├── sandbox_engine.py    Stage 3: Docker behavioral sandbox
│   │   │                        Activate: BAWBEL_SANDBOX_ENABLED=true
│   │   ├── magika_engine.py     Stage 0: ML file-type verification
│   │   │                        Activate: BAWBEL_MAGIKA_ENABLED=true
│   │   └── meta_analyzer.py     FP-4: LLM review of medium-confidence
│   │
│   ├── suppression/             Suppression mechanisms
│   │   ├── __init__.py          Empty package init
│   │   ├── inline.py            InlineSuppression + BlockSuppression
│   │   │                        apply_suppressions() → SuppressionResult
│   │   │                        NO_IGNORE env var toggle
│   │   ├── justified.py         JustifiedSuppression — bawbel-accept/ignore
│   │   │                        parse_accepted_findings, apply_justified_suppressions
│   │   │                        check_expiring_soon, send_fp_signal (opt-in)
│   │   └── bawbelignore.py      check_bawbelignore(path) → bool
│   │                            .bawbelignore glob pattern matching
│   │
│   ├── cli/                     BOUNDARY — user I/O only
│   │   │                        No business logic. Calls scanner.py.
│   │   ├── __init__.py          Click group definition + command registration
│   │   ├── __main__.py          python -m scanner.cli entry point
│   │   ├── cmd_scan.py          bawbel scan
│   │   ├── cmd_report.py        bawbel report
│   │   ├── cmd_accept.py        bawbel accept
│   │   ├── cmd_conform.py       bawbel conform / scan-conformance
│   │   ├── cmd_pin.py           bawbel pin / check-pins / cp
│   │   ├── cmd_ssc.py           bawbel ssc / scan-server-card
│   │   ├── cmd_creds.py         bawbel creds
│   │   ├── cmd_chain.py         bawbel chain
│   │   ├── cmd_init.py          bawbel init
│   │   ├── cmd_version.py       bawbel version
│   │   └── shared/              CLI-internal helpers (not a public interface)
│   │       ├── constants.py     Output format constants
│   │       ├── display.py       Rich console output helpers
│   │       ├── formatters.py    ScanResult → Rich table / JSON / SARIF
│   │       └── utils.py         CLI utility functions
│   │
│   ├── conformance/             MCP spec conformance scoring (PURE — no I/O)
│   │   │                        Independent subsystem, called by cmd_conform.py
│   │   ├── checks.py            CheckCategory enum + CONFORMANCE_CHECKS list
│   │   └── scorer.py            score_conformance(manifest) → ConformanceReport
│   │                            Pure function — safe to call concurrently
│   │
│   ├── rules/                   Pattern rule definitions (Python)
│   │   └── *.py                 One file per rule category
│   │
│   ├── yara_rules/              YARA rule files — included in PyPI wheel
│   │   └── *.yar
│   │
│   └── semgrep_rules/           Semgrep rule files — included in PyPI wheel
│       └── *.yaml
│
├── ── Operational scripts ───────────────────────────────────────────────────
├── scripts/
│   ├── sync_records.py          Syncs AVE records from github.com/bawbel/ave
│   │                            into PiranhaDB records/ directory.
│   │                            True home: piranha-api repo — kept here for
│   │                            deploy convenience. Not part of the scanner package.
│   │                            Run: python scripts/sync_records.py
│   └── ...                      Other operational and testing scripts
│
├── ── Tests ─────────────────────────────────────────────────────────────────
├── tests/
│   ├── test_scanner.py          (current) All 19 test classes, 1664 lines
│   │                            ← being migrated to unit/ integration/ e2e/
│   ├── unit/                    (target) < 100ms/file — pure core only
│   │   ├── test_dedup.py
│   │   ├── test_preprocessor.py
│   │   ├── test_fp_pipeline.py
│   │   ├── test_scoring.py
│   │   ├── test_toxic_flows.py
│   │   ├── test_finding_model.py
│   │   ├── test_finding_evidence_metadata.py  ← Issue #69
│   │   └── test_output_contracts.py           ← Issue #70
│   ├── integration/             (target) < 10s/file — calls scan()
│   │   └── test_scanner.py
│   ├── e2e/                     (target) CLI invocations
│   │   └── test_cli.py
│   └── fixtures/
│       ├── golden/              Locked JSON output contracts ← Issue #70
│       ├── lifecycle/           Evidence lifecycle test files ← Issue #71
│       ├── input/               Input files for fixture generation
│       ├── skills/
│       │   ├── malicious/       GOLDEN FIXTURE — NEVER modify
│       │   └── clean/           FP regression fixtures
│       └── mcp/                 MCP server card fixtures
│
├── ── Documentation ─────────────────────────────────────────────────────────
└── docs/
    ├── adr/
    │   ├── 0001-three-layer-architecture.md
    │   └── 0002-evidence-fields-first-class-output.md
    ├── agents/
    │   ├── prds/
    │   │   ├── prd-02-evidence-confidence-metadata.md
    │   │   └── prd-02-tasks.md
    │   ├── handoffs/            GITIGNORED
    │   └── README.md
    └── guides/
        ├── evidence-lifecycle.md
        ├── refactoring-guide.md
        └── adding-a-rule.md
```

---

## Root files explained

### `pyproject.toml`

Build config, deps, entry points. Key sections:

```toml
[project.scripts]
bawbel = "scanner.cli:cli"

[project.optional-dependencies]
yara    = ["yara-python"]
semgrep = ["semgrep"]
llm     = ["litellm"]
magika  = ["magika"]
sandbox = []          # requires Docker at runtime
dev     = ["pytest", "ruff", "mypy", "pre-commit"]
all     = [all of the above]
```

### `Dockerfile`

Multi-stage build. Builder stage installs dependencies. Runtime stage is lean.
Used by the GitHub Action and by the Stage 3 behavioral sandbox.

```dockerfile
FROM python:3.12-slim AS builder
RUN pip install "bawbel-scanner[all]"

FROM python:3.12-slim
COPY --from=builder /usr/local/lib/python3.12/site-packages .
ENTRYPOINT ["bawbel"]
```

### `docker-compose.yml`

Local dev stack. Three services:
- `scanner` — CLI for local scanning
- `piranha` — PiranhaDB API (points to api.piranha.bawbel.io or local)
- `sandbox` — isolated sandbox for Stage 3 behavioral analysis

### `server.json`

MCP Registry manifest. Both `version` fields must match the PyPI release.
The `<!-- mcp-name: io.github.bawbel/scanner -->` comment in `README.md`
verifies PyPI package ownership for the registry.

### `.gitleaks.toml`

Suppresses false positives from intentional credential patterns in test fixtures.
The test suite contains strings like API keys and tokens as scan targets — without
`.gitleaks.toml`, Gitleaks will flag these as real secrets in CI.

```toml
[[rules]]
id = "test-fixture-credentials"
path = "tests/fixtures/**"
# intentional patterns used as scan targets
```

### `.env.example`

Committed. Template showing all env vars the scanner reads.
Copy to `.env` for local development.

### `.env`

Gitignored. Real API keys, local overrides. Never committed.

### `SECURITY.md`

Vulnerability disclosure policy. GitHub's private vulnerability reporting
is enabled. 90-day responsible disclosure window.

---

## Layer model

Every file in the scanner package belongs to exactly one layer.
Layers can only depend downward — never upward.

```
┌─────────────────────────────────────────────────────────────────┐
│  CLI  scanner/cli.py  (target: scanner/cli/)                    │
│  User input/output only. No business logic.                     │
│  Calls: scanner.py, messages.py                                 │
├─────────────────────────────────────────────────────────────────┤
│  Orchestrator  scanner/scanner.py  (legacy — being hollowed out)│
│  Coordinates engines, suppression, FP pipeline.                 │
│  Calls: engines/, suppression/, core/, models.py, messages.py  │
├─────────────────────────────────────────────────────────────────┤
│  Engines  scanner/engines/                                       │
│  Subprocess, network, file I/O allowed.                         │
│  Calls core/ for pure logic. Reads models.py.                   │
│  Uses: utils.py, messages.py, owasp_mcp_map.py                 │
├─────────────────────────────────────────────────────────────────┤
│  Core  scanner/core/                                             │
│  PURE. No I/O. No subprocess. No network. No print.             │
│  Takes primitives. Returns primitives.                           │
│  Tests run in milliseconds.                                      │
│  Calls: models.py only                                          │
├─────────────────────────────────────────────────────────────────┤
│  Suppression  scanner/suppression/                               │
│  Suppression mechanisms. Reads models.py.                       │
│  No detection logic. No I/O except file reads (.bawbelignore).  │
├─────────────────────────────────────────────────────────────────┤
│  Models  scanner/models.py  (target: scanner/models/)           │
│  Dataclasses only. No logic. No I/O.                            │
│  Finding, ScanResult, Severity, SEVERITY_SCORES                 │
├─────────────────────────────────────────────────────────────────┤
│  Support  (no layer dependencies — used by all layers)          │
│  scanner/messages.py        Rich-formatted output (printing)    │
│  scanner/utils.py           get_logger(), truncate_match()      │
│  scanner/owasp_mcp_map.py   AVE → OWASP MCP mapping (pure)     │
│  scanner/pinner.py          SHA-256 pin management (file I/O)   │
│  config/default.py          Constants (no scanner/ imports)     │
│                                                                  │
│  Operational / entry-point files (outside the call graph)       │
│  scanner/sync_records.py    Deploy-time AVE sync script         │
│  scanner/bawbel_pre_commit.py  Pre-commit runner entry point    │
│  scanner/pre_commit_init.py    Pre-commit first-run init        │
└─────────────────────────────────────────────────────────────────┘
```

**Dependency direction:**
```
cli → scanner.py → engines/ → core/ → models.py
                 → suppression/ → models.py
                 → messages.py
                 → utils.py
                 → owasp_mcp_map.py
      pinner.py  → models.py  (standalone, called by cli)
```

Arrows point toward dependencies. `core/` has NO arrows pointing out
toward `cli/`, `engines/`, `scanner.py`, or `suppression/`.
Any violation of this direction is an architecture bug.

## Layer assignment for new code

Ask these questions in order:

| Question | Layer | File |
|---|---|---|
| Pure logic, no I/O of any kind? | Core | `scanner/core/` |
| Runs subprocess / network / file I/O? | Engines | `scanner/engines/` |
| User input/output only (CLI command)? | CLI | `scanner/cli.py` |
| Domain dataclass, no methods or logic? | Models | `scanner/models.py` |
| Suppresses findings (inline, justified, glob)? | Suppression | `scanner/suppression/` |
| Formats Rich output for the terminal? | Support | `scanner/messages.py` |
| Shared utility with no domain logic? | Support | `scanner/utils.py` |
| Maps AVE IDs to OWASP categories? | Support | `scanner/owasp_mcp_map.py` |
| Manages SHA-256 pins for rug-pull detection? | Support | `scanner/pinner.py` |
| Project-wide constant or env var toggle? | Config | `config/default.py` |
| Syncs external data at deploy time (not scan time)? | Operational | `scanner/sync_records.py` |
| Entry point for pre-commit runner? | Entry point | `scanner/bawbel_pre_commit.py` |

**The key test for `scanner/core/`:**
If your function contains `Path`, `subprocess`, `requests`, `open()`,
or `print()`, it does not belong in `scanner/core/`. Move it to `engines/`
or extract the I/O into a parameter so the core stays pure.

---

## PyPI wheel

Must include: `scanner/` Python files, `scanner/yara_rules/*.yar`,
`scanner/semgrep_rules/*.yaml`, `config/default.py`

Must NOT include: `tests/`, `docs/`, `.claude/`, `.venv/`, `.env`,
`Dockerfile`, `docker-compose.yml`, `examples/`

Verify before every release:
```bash
python -m build && unzip -l dist/bawbel_scanner-*.whl
```
