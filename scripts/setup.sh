#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Bawbel Scanner — Local Development Setup
#
# Usage:
#   ./scripts/setup.sh              Full setup (venv + deps + pre-commit)
#   ./scripts/setup.sh --dev        Full setup + dev tools (pytest, bandit, etc.)
#   ./scripts/setup.sh --minimal    Core deps only (no dev tools, no pre-commit)
#   ./scripts/setup.sh --verify     Check setup without installing anything
#
# What this does:
#   1. Checks Python 3.10+
#   2. Creates a virtual environment at .venv/
#   3. Installs core dependencies
#   4. Installs the bawbel CLI in editable mode
#   5. Installs dev tools (--dev flag)
#   6. Installs pre-commit hooks (unless --minimal)
#   7. Runs the golden fixture to verify everything works
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

tick()  { echo -e "${GREEN}✓${NC}  $*"; }
arrow() { echo -e "${CYAN}→${NC}  $*"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $*"; }
fail()  { echo -e "${RED}✗${NC}  $*"; exit 1; }
dim()   { echo -e "${DIM}$*${NC}"; }

# ── Parse flags ───────────────────────────────────────────────────────────────
MODE="full"
for arg in "$@"; do
    case "$arg" in
        --dev)     MODE="dev"     ;;
        --minimal) MODE="minimal" ;;
        --verify)  MODE="verify"  ;;
        --help|-h)
            echo "Usage: ./scripts/setup.sh [--dev|--minimal|--verify]"
            exit 0 ;;
        *) warn "Unknown flag: $arg"; ;;
    esac
done

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}Bawbel Scanner${NC} — Local Development Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Check we are in the repo root ────────────────────────────────────────────
if [ ! -f "pyproject.toml" ]; then
    fail "Run this script from the repo root: ./scripts/setup.sh"
fi

# ── Verify mode — check without installing ───────────────────────────────────
if [ "$MODE" = "verify" ]; then
    echo "Checking current setup..."
    echo ""

    # Python
    PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo "")
    [ -z "$PYTHON" ] && fail "Python not found" || tick "Python: $($PYTHON --version)"

    # venv
    [ -d ".venv" ] && tick ".venv exists" || warn ".venv not found — run setup.sh"

    # bawbel CLI
    if [ -f ".venv/bin/bawbel" ] || [ -f ".venv/Scripts/bawbel.exe" ]; then
        tick "bawbel CLI installed"
    else
        warn "bawbel CLI not found — run setup.sh"
    fi

    # Golden fixture
    FIXTURE="tests/fixtures/skills/malicious/malicious_skill.md"
    if [ -f "$FIXTURE" ]; then
        tick "Golden fixture present"
    else
        fail "Golden fixture missing: $FIXTURE"
    fi

    echo ""
    echo "Run './scripts/setup.sh --dev' to install everything."
    exit 0
fi

# ── 1. Check Python version ───────────────────────────────────────────────────
arrow "Checking Python..."

PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo "")
if [ -z "$PYTHON" ]; then
    fail "Python 3.10+ is required but not found. Install from python.org"
fi

PY_VERSION=$($PYTHON --version 2>&1 | awk '{print $2}')
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    fail "Python 3.10+ required, found $PY_VERSION"
fi

tick "Python $PY_VERSION"

# ── 2. Create virtual environment ────────────────────────────────────────────
if [ -d ".venv" ]; then
    tick ".venv already exists — skipping creation"
else
    arrow "Creating virtual environment (.venv)..."
    $PYTHON -m venv .venv
    tick "Virtual environment created"
fi

# Activate (cross-platform)
if [ -f ".venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
elif [ -f ".venv/Scripts/activate" ]; then
    # shellcheck disable=SC1091
    source .venv/Scripts/activate
else
    fail "Could not activate virtual environment"
fi

tick "Virtual environment activated"

# ── 3. Upgrade pip ───────────────────────────────────────────────────────────
arrow "Upgrading pip..."
pip install --upgrade pip --quiet
tick "pip upgraded"

# ── 4. Install core dependencies ─────────────────────────────────────────────
arrow "Installing core dependencies..."
pip install -r requirements.txt --quiet
tick "Core dependencies installed"

# ── 5. Install bawbel CLI in editable mode ───────────────────────────────────
arrow "Installing bawbel CLI (editable)..."
pip install -e . --quiet
tick "bawbel CLI installed (editable — code changes reflect immediately)"

# ── 6. Install dev tools (--dev or --full) ───────────────────────────────────
if [ "$MODE" = "dev" ] || [ "$MODE" = "full" ]; then
    arrow "Installing dev tools..."
    pip install --quiet \
        pytest \
        pytest-cov \
        pytest-mock \
        black \
        flake8 \
        flake8-bugbear \
        bandit \
        pre-commit \
        pip-audit \
        "tomli~=2.0.1" \
        build \
        twine
    tick "Dev tools installed (pytest, black, flake8, bandit, pre-commit, pip-audit)"
fi

# ── 7. Install optional engines ──────────────────────────────────────────────
if [ "$MODE" = "dev" ]; then
    echo ""
    arrow "Optional engines (YARA, Semgrep)..."
    dim "  These extend detection beyond the 15 built-in pattern rules."
    dim "  Skipping if install fails — scanner works without them."

    pip install yara-python --quiet 2>/dev/null && tick "yara-python installed" \
        || warn "yara-python skipped (may need system libs: apt install libyara-dev)"

    pip install semgrep --quiet 2>/dev/null && tick "semgrep installed" \
        || warn "semgrep skipped (large package — install manually if needed)"
fi

# ── 8. Install pre-commit hooks ──────────────────────────────────────────────
if [ "$MODE" != "minimal" ]; then
    arrow "Installing pre-commit hooks..."
    if command -v pre-commit &>/dev/null; then
        pre-commit install
        pre-commit install --hook-type commit-msg
        tick "Pre-commit hooks installed"
        dim "  Hooks run automatically on every git commit:"
        dim "  black, flake8, bandit, gitleaks, bawbel self-scan, pytest"
    else
        warn "pre-commit not found — skipping hook installation"
        dim "  Install with: pip install pre-commit"
    fi
fi

# ── 9. Verify installation ────────────────────────────────────────────────────
echo ""
arrow "Verifying installation..."

# Version check
VERSION=$(bawbel --version 2>&1)
tick "$VERSION"

# Golden fixture
FIXTURE="tests/fixtures/skills/malicious/malicious_skill.md"
if [ -f "$FIXTURE" ]; then
    RESULT=$(bawbel scan "$FIXTURE" 2>&1)
    if echo "$RESULT" | grep -q "CRITICAL"; then
        tick "Golden fixture: 2 findings, CRITICAL 9.4"
    else
        warn "Golden fixture produced unexpected output — check manually"
        echo "$RESULT"
    fi
else
    warn "Golden fixture not found: $FIXTURE"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
tick "Setup complete"
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo ""
echo "  source .venv/bin/activate          # activate venv (every session)"
echo "  bawbel version                     # check engines"
echo "  bawbel scan ./path/to/skill.md     # scan a file"
echo "  bawbel report ./path/to/skill.md   # full remediation report"
echo ""
echo -e "${DIM}Run tests:${NC}"
echo "  python -m pytest tests/ -v"
echo ""
echo -e "${DIM}Full docs: docs/guides/getting-started.md${NC}"
echo ""
