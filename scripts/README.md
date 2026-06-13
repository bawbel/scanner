# Bawbel Scanner - Scripts

Everything you need to set up, test, and run registry sweeps locally.

```
scripts/
  README.md               this file
  setup.sh                local dev setup (venv, deps, pre-commit)
  test_all.sh             automated full test suite
  diagnose.sh             crash diagnostics — paste output when filing a bug
  scan_smithery.py        sweep Smithery registry for AVE vulnerabilities
  scan_mcp_registry.py    sweep official MCP registry for AVE vulnerabilities
  sync_records.py         sync AVE records from github.com/bawbel/ave → PiranhaDB
  update_log.py           update CHANGELOG.md from git log
```

Manual testing guides have moved to `docs/guides/`:
- `docs/guides/manual-testing.md`
- `docs/guides/manual-testing-creds-chain.md`
- `docs/guides/manual-testing-suppress.md`

---

## Quick start

```bash
# 1. Clone and enter the repo
git clone https://github.com/bawbel/scanner
cd scanner

# 2. Set up local dev environment
bash scripts/setup.sh --dev

# 3. Activate the venv (every new terminal session)
source .venv/bin/activate

# 4. Run the full test suite
bash scripts/test_all.sh
```

---

## scripts/setup.sh

Sets up the local development environment from scratch.

```bash
# Full setup: venv + deps + dev tools + pre-commit hooks
bash scripts/setup.sh

# Dev setup: everything above + YARA, Semgrep, watchdog
bash scripts/setup.sh --dev

# Minimal: core deps only, no dev tools, no pre-commit
bash scripts/setup.sh --minimal

# Verify: check current state without installing anything
bash scripts/setup.sh --verify

# Help
bash scripts/setup.sh --help
```

What `--dev` installs on top of `--full`:
- `yara-python` - behavioral YARA rules engine
- `semgrep` - structural Semgrep rules engine
- `watchdog` - required for `bawbel scan --watch` mode

After running setup, always activate the venv:

```bash
source .venv/bin/activate   # macOS / Linux
.venv\Scripts\activate      # Windows
```

---

## scripts/test_all.sh

Runs every CLI command, output format, flag, alias, engine, and integration
point automatically. Skips optional sections cleanly when dependencies are
absent (Docker, network, LLM API keys, optional engines).

```bash
# Run all tests
bash scripts/test_all.sh

# With LLM engine tests
ANTHROPIC_API_KEY=your_key bash scripts/test_all.sh

# With both LLM providers
ANTHROPIC_API_KEY=sk-... OPENAI_API_KEY=sk-... bash scripts/test_all.sh
```

### What it covers

| Section | What is tested |
|---------|---------------|
| 1  | Installation, entry points, `python -m scanner` |
| 2  | `bawbel version` - engine list, rule count |
| 3  | `bawbel scan` - basic, recursive, text output |
| 3b | `bawbel scan --watch` - watch mode smoke test |
| 4  | Output formats: text, JSON, SARIF |
| 5  | AIVSS v0.8 fields: `aivss_score`, `aivss` block, `owasp_mcp`, `piranha_url` |
| 6  | `--fail-on-severity` exit codes |
| 7  | FP suppression: `bawbel-ignore`, negation context, `--no-ignore` |
| 8  | Toxic flow chain detection |
| 9  | `bawbel report` - text and JSON, AIVSS display |
| 10 | `bawbel conform` / `scan-conformance` - grade, score, flags |
| 11 | `bawbel pin` / `check-pins` / `cp` - drift detection |
| 12 | `bawbel init` - idempotent project initialisation |
| 13 | Public Python API: `scan()`, `ScanResult`, `Finding` |
| 14 | Conformance scorer Python API |
| 15 | Optional engines: YARA, Semgrep, Magika, LLM |
| 16 | Docker: build, scan, compose services |
| 17 | Network: `bawbel ssc`, `bawbel conform --registry` |
| 18 | Pre-commit hook |

### Exit codes

- `0` - all mandatory tests passed
- `1` - one or more mandatory tests failed

Skipped tests do not affect the exit code.

---

## Docker testing

### Using the Dockerfile directly

The Dockerfile has three useful targets: `dev`, `test`, and `production`.

#### Run the test suite inside Docker

```bash
# Build the test image (runs pytest as part of the build)
docker build --target test -t bawbel/scanner:test .

# Run tests and see results
docker run --rm bawbel/scanner:test

# Run a specific test file
docker run --rm bawbel/scanner:test \
  -m pytest tests/test_scanner.py -v --tb=short
```

#### Build and run production image

```bash
# Standard production build
docker build --target production -t bawbel/scanner:1.2.3 .

# With LLM engine
docker build --target production \
  --build-arg WITH_LLM=true \
  -t bawbel/scanner:1.2.3-llm .

# With sandbox engine
docker build --target production \
  --build-arg WITH_SANDBOX=true \
  -t bawbel/scanner:1.2.3-sandbox .

# With everything
docker build --target production \
  --build-arg WITH_ALL=true \
  -t bawbel/scanner:1.2.3-full .
```

#### Scan a local directory

```bash
# Text output (default)
docker run --rm \
  -v /path/to/skills:/scan:ro \
  bawbel/scanner:1.2.3 scan /scan --recursive

# JSON output
docker run --rm \
  -v /path/to/skills:/scan:ro \
  bawbel/scanner:1.2.3 scan /scan --recursive --format json

# SARIF output
docker run --rm \
  -v /path/to/skills:/scan:ro \
  -v /path/to/reports:/reports \
  bawbel/scanner:1.2.3 scan /scan --recursive \
    --format sarif --output /reports/bawbel.sarif

# Fail on high severity (for CI)
docker run --rm \
  -v /path/to/skills:/scan:ro \
  bawbel/scanner:1.2.3 scan /scan --recursive \
    --fail-on-severity high
echo "Exit: $?"   # 0 = clean, 2 = findings at threshold
```

#### Other commands

```bash
# Version and engine status
docker run --rm bawbel/scanner:1.2.3 version

# Conformance check of a live server
docker run --rm bawbel/scanner:1.2.3 \
  conform https://api.example.com

# Scan a server card
docker run --rm bawbel/scanner:1.2.3 \
  ssc https://api.example.com

# Report
docker run --rm \
  -v /path/to/skills:/scan:ro \
  bawbel/scanner:1.2.3 report /scan/my_skill.md
```

#### Dev shell inside Docker

```bash
# Build dev image
docker build --target dev -t bawbel/scanner:dev .

# Drop into an interactive bash shell with source mounted
docker run --rm -it \
  -v "$(pwd)":/app \
  bawbel/scanner:dev

# Inside the container:
bawbel version
bawbel scan tests/fixtures/ --recursive
python -m pytest tests/ -v
```

---

### Using docker compose

All compose commands use `SCAN_DIR` to point at the directory to scan.
Set it as an env var or inline.

```bash
export SCAN_DIR=/path/to/your/skills
```

#### Development shell

```bash
# Interactive dev shell with live source mount
docker compose --profile dev up dev

# Or with run (exits when you exit the shell)
docker compose --profile dev run --rm dev
```

#### Test suite

```bash
# Run pytest and exit
docker compose --profile test run --rm test
```

#### Scan commands

```bash
# Scan - text output (no profile needed, runs by default)
SCAN_DIR=./skills docker compose run --rm scan

# Scan - JSON output
SCAN_DIR=./skills docker compose --profile json run --rm scan-json

# Scan - SARIF output (saved to REPORT_DIR)
SCAN_DIR=./skills REPORT_DIR=./reports \
  docker compose --profile sarif run --rm scan-sarif

# Full remediation report
SCAN_DIR=./skills docker compose --profile report run --rm report
```

#### Server / MCP commands

```bash
# Scan a server card (fetches .well-known/mcp-server-card/server.json)
MCP_URL=https://api.example.com docker compose run --rm ssc

# Conformance check
MCP_URL=https://api.example.com docker compose run --rm conform

# AIBOM (AI Bill of Materials, saved to REPORT_DIR)
SCAN_DIR=./skills REPORT_DIR=./reports \
  docker compose --profile aibom run --rm aibom
```

#### Pinning

```bash
# Pin skill files (writes .bawbel-pins.json into SCAN_DIR)
SCAN_DIR=./skills docker compose --profile pin run --rm pin

# Check for drift
SCAN_DIR=./skills docker compose --profile pins run --rm check-pins
```

#### Local PiranhaDB (offline mode)

Start a local copy of the PiranhaDB threat intelligence API so the scanner
never calls out to `api.piranha.bawbel.io`:

```bash
# Start PiranhaDB locally
docker compose --profile offline up piranha

# Then run scans with the local API
BAWBEL_PIRANHA_URL=http://localhost:8000 \
  SCAN_DIR=./skills docker compose run --rm scan
```

#### Security audit of the scanner itself

```bash
# Runs bandit + pip-audit against the scanner codebase
docker compose --profile audit run --rm audit
```

#### LLM engine

```bash
# Pass API key to enable LLM semantic analysis
ANTHROPIC_API_KEY=your_key \
  BAWBEL_LLM_ENABLED=true \
  SCAN_DIR=./skills docker compose run --rm scan
```

#### Log level

```bash
# Default: WARNING
# Set to DEBUG for full diagnostic output
BAWBEL_LOG_LEVEL=DEBUG \
  SCAN_DIR=./skills docker compose run --rm scan
```

---

## Registry sweep scripts

These sweep external MCP registries for AVE vulnerabilities and feed
findings into PiranhaDB.

### Smithery registry

```bash
# Requirements
pip install requests
export SMITHERY_API_KEY=your_key

# Scan top 500 servers
python3 scripts/scan_smithery.py

# Custom limit and output file
python3 scripts/scan_smithery.py --limit 100 --output sweep.json

# Resume after interruption
python3 scripts/scan_smithery.py --limit 1000 --resume

# With LLM engine for deeper analysis
ANTHROPIC_API_KEY=your_key \
  python3 scripts/scan_smithery.py --limit 500

# Upload results to PiranhaDB
SMITHERY_API_KEY=your_key \
  PIRANHA_INGEST_TOKEN=your_token \
  python3 scripts/scan_smithery.py
```

### Official MCP registry

No API key required. The official registry is public.

```bash
# Scan latest 50 servers
python3 scripts/scan_mcp_registry.py

# Scan 200 servers, save to file
python3 scripts/scan_mcp_registry.py --limit 200 --output results.json

# Scan all versions (not just latest)
python3 scripts/scan_mcp_registry.py --limit 100 --all-versions

# Verbose - prints scan content for each server
python3 scripts/scan_mcp_registry.py --limit 20 --verbose
```

---

## CI/CD integration

### GitHub Actions (using the action)

```yaml
# .github/workflows/security.yml
name: Bawbel Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Bawbel scan
        uses: bawbel/scanner@v1
        with:
          path: ./skills/
          fail-on-severity: high
          format: sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bawbel-results.sarif
```

### GitHub Actions (using Docker)

```yaml
      - name: Bawbel scan
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/skills:/scan:ro \
            bawbel/scanner:1.2.3 scan /scan --recursive \
              --format sarif > bawbel.sarif
          echo "exit=$?" >> $GITHUB_OUTPUT
```

### Pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/bawbel/scanner
    rev: v1.2.3
    hooks:
      - id: bawbel-scan
```

```bash
pre-commit install
pre-commit run bawbel-scan --all-files
```

---

## Troubleshooting

**`bawbel: command not found`**
```bash
source .venv/bin/activate
# or
pip install bawbel-scanner
```

**`No module named scanner`**
```bash
pip install -e .
```

**YARA rules not loading**
```bash
# Check path
python3 -c "
from scanner.engines.yara_engine import RULES_PATH
print(RULES_PATH, RULES_PATH.exists())
"
# Should print: scanner/rules/yara/ave_rules.yar  True
```

**Semgrep not running**
```bash
semgrep --version
# If not found:
pip install semgrep
```

**Docker build fails**
```bash
# Check Docker is running
docker info

# Clean rebuild
docker build --no-cache --target production -t bawbel/scanner:1.2.3 .
```

**Watch mode not working**
```bash
pip install "bawbel-scanner[watch]"
# or
pip install watchdog
```

**LLM engine not triggering**
```bash
# Check a provider key is set
echo $ANTHROPIC_API_KEY
# Check LLM is enabled
BAWBEL_LLM_ENABLED=true bawbel scan ./skill.md
# Check which model is selected
bawbel version
```
