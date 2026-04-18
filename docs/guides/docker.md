# Docker — Bawbel Scanner

Run the scanner without any local Python installation.
Three build targets cover every use case.

---

## Build Targets

| Target | Use case | Size |
|---|---|---|
| `production` | Scan files in CI/CD or on any machine | Minimal |
| `dev` | Interactive development shell, hot-reload | Full toolchain |
| `test` | Run the test suite in a clean container | Full toolchain |

---

## Quick Start (Production)

```bash
# Build the production image
docker build --target production -t bawbel/scanner:0.1.0 .

# Scan a directory
docker run --rm \
  -v /path/to/your/skills:/scan:ro \
  bawbel/scanner:0.1.0 \
  scan /scan --recursive

# Scan a single file
docker run --rm \
  -v $(pwd)/my-skill.md:/scan/my-skill.md:ro \
  bawbel/scanner:0.1.0 \
  scan /scan/my-skill.md

# Full remediation report
docker run --rm \
  -v /path/to/your/skills:/scan:ro \
  bawbel/scanner:0.1.0 \
  report /scan/my-skill.md

# JSON output
docker run --rm \
  -v /path/to/your/skills:/scan:ro \
  bawbel/scanner:0.1.0 \
  scan /scan --recursive --format json

# SARIF output (redirect to file)
docker run --rm \
  -v /path/to/your/skills:/scan:ro \
  bawbel/scanner:0.1.0 \
  scan /scan --recursive --format sarif > results.sarif

# Check version and engines
docker run --rm bawbel/scanner:0.1.0 version
```

---

## Docker Compose

### Setup

```bash
# Create the scan directory and add files to scan
mkdir -p scan
cp path/to/your/skill.md scan/
```

### Scan (text output — default)

```bash
docker compose run --rm scan
```

### Report (full remediation guide)

```bash
docker compose run --rm report
```

### JSON output

```bash
docker compose run --rm scan-json
```

### SARIF output

```bash
docker compose run --rm scan-sarif > results.sarif
```

### Security audit

```bash
docker compose run --rm audit
```

### Custom scan directory

```bash
SCAN_DIR=/path/to/your/skills docker compose run --rm scan
```

---

## Development Shell

The `dev` target mounts your source code so changes reflect immediately
without rebuilding.

```bash
# Build the dev image
docker build --target dev -t bawbel/scanner:dev .

# Start an interactive shell
docker run --rm -it \
  -v $(pwd):/app \
  bawbel/scanner:dev

# Inside the container:
bawbel version
python -m pytest tests/ -v
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
```

Or with Compose:

```bash
docker compose run --rm dev
```

The dev shell has: `bawbel` CLI, `pytest`, `black`, `flake8`, `bandit`, `pre-commit`, `pip-audit`, `build`, `twine`.

---

## Test Runner

Run the full test suite in a clean container — useful for verifying the build
before a release:

```bash
# Build and run tests (build fails if tests fail)
docker build --target test -t bawbel/scanner:test .

# Run tests in the already-built image
docker run --rm bawbel/scanner:test
# Expected: 145 passed
```

Or with Compose:

```bash
docker compose run --rm test
```

---

## Environment Variables

Pass environment variables to enable optional features:

```bash
# Enable Stage 2 LLM semantic analysis
docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v /path/to/skills:/scan:ro \
  bawbel/scanner:0.1.0 \
  scan /scan --recursive

# Set log level
docker run --rm \
  -e BAWBEL_LOG_LEVEL=DEBUG \
  -v /path/to/skills:/scan:ro \
  bawbel/scanner:0.1.0 \
  scan /scan

# Use a .env file
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
docker run --rm --env-file .env \
  -v /path/to/skills:/scan:ro \
  bawbel/scanner:0.1.0 \
  scan /scan
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Bawbel Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build scanner
        run: docker build --target production -t bawbel/scanner:ci .

      - name: Scan and upload SARIF
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/scan:ro \
            bawbel/scanner:ci \
            scan /scan --recursive --format sarif > bawbel-results.sarif

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bawbel-results.sarif

      - name: Fail on critical findings
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/scan:ro \
            bawbel/scanner:ci \
            scan /scan --recursive --fail-on-severity critical
```

---

## Security Properties

The production image is hardened:

| Property | Value |
|---|---|
| Base image | `python:3.12-slim` |
| Run as | Non-root user `bawbel` (UID 1000) |
| Scan volume | Read-only (`:ro`) |
| Filesystem | Read-only (`read_only: true` in Compose) |
| Privileges | `no-new-privileges:true` |
| Build tools | Not included in production image |
| Tests | Not included in production image |

Never run the production image as root. Never mount the scan volume as writable.

---

## Troubleshooting

**`permission denied` on the scan volume:**
```bash
# The container runs as UID 1000 — make sure the files are readable
chmod -R a+r /path/to/your/skills
```

**`bawbel: command not found` inside dev container:**
```bash
# Reinstall the editable package
pip install -e . --quiet
```

**`ModuleNotFoundError: No module named 'scanner'`:**
```bash
# Always run from the repo root, not a subdirectory
cd /app   # inside container
bawbel scan ...
```

**Docker build fails at test stage:**
```bash
# Tests failed — run them locally to see what broke
python -m pytest tests/ -v
```
