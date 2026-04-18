# Local Development Workflow — Claude Code Context

This file is for Claude Code sessions only.
Full developer documentation is in `docs/guides/getting-started.md`.

---

## Quick orientation for a new session

```bash
source .venv/bin/activate                                       # always first
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md  # golden check
# Expected: 2 findings, CRITICAL 9.4 — if this fails, stop and investigate
python -m pytest tests/ -q                                      # must be 145/145
```

---

## Where things live

| Task | File |
|---|---|
| First-time setup | `scripts/setup.sh --dev` |
| Configuration options | `docs/guides/configuration.md` |
| Docker usage | `docs/guides/docker.md` |
| CI/CD integration | `docs/guides/cicd-integration.md` |
| Adding a rule | `docs/guides/writing-rules.md` |
| Adding an engine | `docs/guides/adding-engine.md` |
| Python API | `docs/api/scan.md` |
| CLI reference | `docs/api/scan.md` |
| Utils classes | `docs/api/utils.md` |
| All dev commands | `.claude/commands.md` |

---

## Setup

```bash
# First time — full dev setup
./scripts/setup.sh --dev

# First time — minimal (core deps only)
./scripts/setup.sh --minimal

# Verify existing setup without reinstalling
./scripts/setup.sh --verify

# Every session
source .venv/bin/activate
```

---

## Scanning

```bash
# Scan a single file (text output)
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md

# Scan a directory recursively
bawbel scan ./skills/ --recursive

# Full remediation report
bawbel report tests/fixtures/skills/malicious/malicious_skill.md

# JSON output
bawbel scan ./skills/ --format json | jq '.[].max_severity'

# SARIF output
bawbel scan ./skills/ --format sarif > results.sarif

# Fail on severity (exit code 2 if findings at threshold)
bawbel scan ./skills/ --fail-on-severity high

# Check installed engines
bawbel version

# Debug mode — full internal logs
BAWBEL_LOG_LEVEL=DEBUG bawbel scan ./skill.md
```

---

## Testing

```bash
# All tests (must be 145/145)
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=scanner --cov-report=term-missing

# Fast — unit tests only
python -m pytest tests/unit/ -v

# One test class
python -m pytest tests/test_scanner.py::TestGoldenFixture -v
python -m pytest tests/test_scanner.py::TestNewPatternRules -v
python -m pytest tests/test_scanner.py::TestSecurity -v
python -m pytest tests/test_scanner.py::TestCLINewCommands -v

# One specific test
python -m pytest tests/test_scanner.py::TestNewPatternRules::test_detects_jailbreak_dan_mode -v

# Golden fixture (quick check)
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
# Expected: 2 findings, CRITICAL 9.4, AVE-2026-00001
```

---

## Code quality

```bash
# Lint
flake8 scanner/ --max-line-length 100

# Format check
black --check --line-length 100 scanner/

# Format (apply)
black --line-length 100 scanner/

# Security scan (must be 0 issues)
bandit -r scanner/ -f screen

# Dependency CVE scan (must be 0 CVEs)
pip-audit -r requirements.txt
```

---

## Docker

```bash
# Production image
docker build --target production -t bawbel/scanner:0.1.0 .
docker run --rm -v $(pwd)/tests/fixtures/skills:/scan:ro bawbel/scanner:0.1.0 scan /scan

# Development shell (hot-reload — source mounted)
docker build --target dev -t bawbel/scanner:dev .
docker run --rm -it -v $(pwd):/app bawbel/scanner:dev

# Test runner
docker build --target test -t bawbel/scanner:test .
docker run --rm bawbel/scanner:test

# Compose: scan ./scan/ directory
mkdir -p scan && cp tests/fixtures/skills/malicious/malicious_skill.md scan/
docker compose run --rm scan                     # text output
docker compose run --rm scan-json                # JSON output
docker compose run --rm scan-sarif > out.sarif   # SARIF output
docker compose run --rm report                   # remediation report
docker compose run --rm audit                    # security audit

# Compose: development shell
docker compose run --rm dev
```

---

## Pre-commit hooks

```bash
# Install (once after cloning)
pre-commit install
pre-commit install --hook-type commit-msg

# Run manually on all files
pre-commit run --all-files

# Run one hook
pre-commit run pytest-check --all-files
pre-commit run bandit --all-files

# Skip hooks for a specific commit (rare — document why)
git commit --no-verify -m "message"
```

Hooks that run on every `git commit`:
- `trailing-whitespace`, `end-of-file-fixer`, `check-yaml`, `check-json`
- `detect-private-key`, `no-commit-to-main`
- `black` — formatting
- `flake8` — linting
- `bandit` — security
- `gitleaks` — secret scanning
- `bawbel-self-scan` — scanner scans its own `.md` files
- `pytest-check` — full test suite (145 tests)

---

## Progress log

```bash
# Stamp timestamp only
python scripts/update_log.py --log /path/to/BAWBEL_PROGRESS_LOG.md

# Stamp with activity note
python scripts/update_log.py --log /path/to/BAWBEL_PROGRESS_LOG.md \
  -m "Added 5 new pattern rules"
```

---

## Common tasks

| Task | Command |
|---|---|
| Add a pattern rule | Edit `scanner/engines/pattern.py` → `PATTERN_RULES` |
| Add remediation text | Edit `scanner/cli.py` → `REMEDIATION_GUIDE` |
| Add YARA rule | Edit `scanner/rules/yara/ave_rules.yar` |
| Add Semgrep rule | Edit `scanner/rules/semgrep/ave_rules.yaml` |
| Add a new engine | See `.claude/skills/add-engine.md` |
| Do a security review | See `.claude/skills/security-review.md` |
| Write a test | See `.claude/skills/write-test.md` |
| Bump version | `scanner/__init__.py` + `pyproject.toml` + `Dockerfile` label |
