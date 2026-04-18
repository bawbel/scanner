#!/bin/bash
# Bawbel Scanner — local setup script
# Creates a virtual environment and installs all dependencies
#
# Usage: ./setup.sh

set -e

echo ""
echo "Bawbel Scanner — Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check Python version
PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then
    echo "❌  Python 3.10+ is required but not found."
    exit 1
fi

PY_VERSION=$($PYTHON --version 2>&1 | awk '{print $2}')
echo "✓  Python $PY_VERSION found"

# Create virtual environment
echo "→  Creating virtual environment (.venv)..."
$PYTHON -m venv .venv

# Activate
source .venv/bin/activate

# Upgrade pip
echo "→  Upgrading pip..."
pip install --upgrade pip --quiet

# Install dependencies
echo "→  Installing dependencies..."
pip install -r requirements.txt --quiet

echo ""
echo "✓  Setup complete"
echo ""
echo "Activate the environment:"
echo "  source .venv/bin/activate"
echo ""
echo "Then scan a file:"
echo "  python cli.py scan ./path/to/skill.md"
echo ""
echo "Or scan a directory:"
echo "  python cli.py scan ./skills/ --recursive"
echo ""
