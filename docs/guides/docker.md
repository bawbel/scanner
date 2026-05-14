# Docker

---

## Production image

```bash
# Build
docker build --target production -t bawbel/scanner:1.2.0 .

# With LLM engine
docker build --target production \
  --build-arg WITH_LLM=true \
  -t bawbel/scanner:1.2.0-llm .

# With everything
docker build --target production \
  --build-arg WITH_ALL=true \
  -t bawbel/scanner:1.2.0-full .
```

### Build args

| Arg | Default | Description |
|---|---|---|
| `PYTHON_VERSION` | `3.12` | Python version |
| `WITH_LLM` | `false` | Include LLM engine (`litellm`) |
| `WITH_SANDBOX` | `false` | Include sandbox engine deps |
| `WITH_ALL` | `false` | Include all optional engines |

---

## Scanning with Docker

```bash
# Scan a local directory - text output
docker run --rm \
  -v /path/to/skills:/scan:ro \
  bawbel/scanner:1.2.0 scan /scan --recursive

# JSON output
docker run --rm \
  -v /path/to/skills:/scan:ro \
  bawbel/scanner:1.2.0 scan /scan --recursive --format json

# SARIF output
docker run --rm \
  -v /path/to/skills:/scan:ro \
  -v /path/to/reports:/reports \
  bawbel/scanner:1.2.0 scan /scan --recursive \
    --format sarif > /reports/bawbel.sarif

# Fail on high severity (for CI)
docker run --rm \
  -v /path/to/skills:/scan:ro \
  bawbel/scanner:1.2.0 scan /scan --recursive \
    --fail-on-severity high
echo "Exit: $?"

# Other commands
docker run --rm bawbel/scanner:1.2.0 version
docker run --rm bawbel/scanner:1.2.0 conform https://api.example.com
docker run --rm bawbel/scanner:1.2.0 ssc https://api.example.com
```

---

## Docker Compose

All services use `SCAN_DIR` to point at the directory to scan.

```bash
export SCAN_DIR=/path/to/your/skills
```

### Common services

```bash
# Default scan - text output
SCAN_DIR=./skills docker compose run --rm scan

# JSON output
SCAN_DIR=./skills docker compose --profile json run --rm scan-json

# SARIF output (saved to REPORT_DIR)
SCAN_DIR=./skills REPORT_DIR=./reports \
  docker compose --profile sarif run --rm scan-sarif

# Remediation report
SCAN_DIR=./skills docker compose --profile report run --rm report

# MCP server card scan
MCP_URL=https://api.example.com docker compose run --rm ssc

# Conformance check
MCP_URL=https://api.example.com docker compose run --rm conform

# Pin skill files
SCAN_DIR=./skills docker compose --profile pin run --rm pin

# Check for drift
SCAN_DIR=./skills docker compose --profile pins run --rm check-pins
```

### Development shell

```bash
# Interactive shell with live source mount
docker compose --profile dev up dev

# Or with run
docker compose --profile dev run --rm dev
```

### Test suite

```bash
docker compose --profile test run --rm test
```

### Local PiranhaDB (offline mode)

```bash
# Start local PiranhaDB
docker compose --profile offline up piranha

# Scan using local API
BAWBEL_PIRANHA_URL=http://localhost:8000 \
  SCAN_DIR=./skills docker compose run --rm scan
```

### Security audit

```bash
# Run bandit + pip-audit against the scanner codebase
docker compose --profile audit run --rm audit
```

---

## Dockerfile targets

| Target | Purpose |
|---|---|
| `base` | Minimal Python + system deps |
| `builder` | Installs Python deps |
| `dev` | Full dev environment, source mounted |
| `test` | Runs pytest on build |
| `production` | Final minimal image, entrypoint set |

```bash
# Dev image
docker build --target dev -t bawbel/scanner:dev .

docker run --rm -it \
  -v "$(pwd)":/app \
  bawbel/scanner:dev
# Inside: bawbel version, bawbel scan tests/fixtures/...
```
