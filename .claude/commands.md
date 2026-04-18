# Commands — Bawbel Scanner

Quick reference for every command you will need during development.

---

## Setup

```bash
# First time setup — creates venv, installs all deps
./scripts/setup.sh

# Activate venv (do this every session)
source .venv/bin/activate

# Deactivate
deactivate

# Install a new dep and add to requirements.txt
pip install package-name && pip freeze > requirements.txt
```

---

## Scanning

```bash
# Scan a single file (text output)
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md

# Scan a single file (JSON output)
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md --format json

# Scan a directory recursively
bawbel scan ./skills/ --recursive

# Scan and fail CI on HIGH or above
bawbel scan ./skills/ --recursive --fail-on-severity high

# Generate report
bawbel report tests/fixtures/skills/malicious/malicious_skill.md

# Show help
bawbel --help
bawbel scan --help
```

---

## Testing

```bash
# Install test deps (first time)
pip install pytest pytest-cov

# Run all tests
python -m pytest tests/ -v

# Run with coverage report
python -m pytest tests/ --cov=scanner --cov-report=term-missing

# Run a single test file
python -m pytest tests/test_scanner.py -v

# Run a single test
python -m pytest tests/test_scanner.py::test_ave_00001_metamorphic_payload -v

# Run golden fixture check (must always show 2 findings, CRITICAL 9.4)
bawbel scan tests/fixtures/skills/malicious/malicious_skill.md
```

---

## Code Quality

```bash
# Lint (must pass before every PR)
flake8 scanner/ --max-line-length 100

# Format with black (optional but recommended)
pip install black
black scanner/

# Type check with mypy (optional)
pip install mypy
mypy scanner/ cli.py --ignore-missing-imports

# Security audit of dependencies
pip install pip-audit
pip-audit -r requirements.txt
```

---

## Docker

```bash
# Build image
docker build -t bawbel/scanner:0.1.0 .
docker build -t bawbel/scanner:latest .

# Run scan via Docker
docker run --rm -v $(pwd)/tests:/scan:ro bawbel/scanner scan /scan

# Run with JSON output
docker run --rm -v $(pwd)/tests:/scan:ro bawbel/scanner scan /scan --format json

# Run Docker Compose (text output)
mkdir -p scan && cp tests/fixtures/skills/malicious/malicious_skill.md scan/
docker-compose up

# Run Docker Compose (JSON output)
docker-compose --profile json up scanner-json

# Shell into container for debugging
docker run --rm -it --entrypoint /bin/bash bawbel/scanner

# Check image size
docker images bawbel/scanner

# Remove image
docker rmi bawbel/scanner:0.1.0
```

---

## Git

```bash
# Start a new feature
git checkout develop
git pull origin develop
git checkout -b feat/my-feature

# Start a new rule
git checkout -b rule/ave-00003-description

# Stage and commit
git add -p                                    # review changes before staging
git commit -m "rule(yara): add AVE-2026-00003 env exfiltration"

# Push and open PR to develop
git push -u origin feat/my-feature

# Update branch with latest develop
git fetch origin
git rebase origin/develop

# Squash commits before PR (clean history)
git rebase -i origin/develop
```

---

## YARA Rules

```bash
# Install yara-python
pip install yara-python

# Test YARA rules manually
python3 -c "
import yara
rules = yara.compile('scanner/rules/yara/ave_rules.yar')
matches = rules.match('tests/fixtures/skills/malicious/malicious_skill.md')
for m in matches:
    print(m.rule, m.meta)
"

# Validate YARA syntax (requires yara CLI)
yara scanner/rules/yara/ave_rules.yar tests/fixtures/skills/malicious/malicious_skill.md
```

---

## Semgrep Rules

```bash
# Install semgrep
pip install semgrep

# Test Semgrep rules manually
semgrep --config scanner/rules/semgrep/ave_rules.yaml tests/fixtures/skills/malicious/malicious_skill.md

# Test with JSON output
semgrep --config scanner/rules/semgrep/ave_rules.yaml --json tests/fixtures/skills/malicious/malicious_skill.md | jq .

# Validate rule syntax
semgrep --validate --config scanner/rules/semgrep/ave_rules.yaml

# Test a single rule
semgrep --config scanner/rules/semgrep/ave_rules.yaml \
        --include "*.md" tests/ --json | jq '.results[].check_id'
```

---

## Progress Log

```bash
# Stamp current date/time only
python scripts/update_log.py

# Stamp + add an activity note
python scripts/update_log.py -m "Pushed bawbel-scanner v0.1.0 to GitHub"
python scripts/update_log.py -m "Fixed false positive in bawbel-env-exfiltration rule"

# Use a custom log path
python scripts/update_log.py --log /path/to/BAWBEL_PROGRESS_LOG.md -m "note"
```

Run this at the **end of every working session** — it keeps the log current
with a UTC timestamp and an optional one-line activity note.


---

## Debugging

```bash
# Run scanner with Python debugger
python -m pdb cli.py scan tests/fixtures/skills/malicious/malicious_skill.md

# Add a temporary debug print in scan()
import pprint; pprint.pprint(result.__dict__)

# Check which engines are available
python3 -c "
try:
    import yara; print('yara-python: ✓')
except ImportError:
    print('yara-python: ✗ (install: pip install yara-python)')

import subprocess
r = subprocess.run(['semgrep', '--version'], capture_output=True)
if r.returncode == 0:
    print(f'semgrep: ✓ ({r.stdout.decode().strip()})')
else:
    print('semgrep: ✗ (install: pip install semgrep)')
"

# Profile scan performance
python3 -c "
import cProfile
from scanner.scanner import scan
cProfile.run('scan(\"tests/fixtures/skills/malicious/malicious_skill.md\")', sort='cumulative')
"
```
