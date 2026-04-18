"""
Bawbel Scanner — Default configuration.

All tuneable values live here. Never hardcode these in scanner.py,
engine files, or cli.py. Import from this module.

To override at runtime: set environment variables.
To change defaults for a deployment: edit this file only.
"""

import os
from pathlib import Path


# ── Paths ─────────────────────────────────────────────────────────────────────

PACKAGE_ROOT  = Path(__file__).parent.parent
RULES_DIR     = PACKAGE_ROOT / "scanner" / "rules"
YARA_RULES    = RULES_DIR / "yara"    / "ave_rules.yar"
SEMGREP_RULES = RULES_DIR / "semgrep" / "ave_rules.yaml"


# ── Security limits ───────────────────────────────────────────────────────────
# Do not lower these without a security review.

MAX_FILE_SIZE_BYTES  = int(os.environ.get("BAWBEL_MAX_FILE_SIZE_MB", "10")) * 1024 * 1024
MAX_MATCH_LENGTH     = 80    # chars — prevents CI log leakage
MAX_SCAN_TIMEOUT_SEC = int(os.environ.get("BAWBEL_SCAN_TIMEOUT_SEC", "30"))


# ── Component type detection ──────────────────────────────────────────────────

COMPONENT_EXTENSIONS: dict[str, str] = {
    ".md":   "skill",
    ".json": "mcp",
    ".yaml": "prompt",
    ".yml":  "prompt",
    ".txt":  "prompt",
}


# ── Logging ───────────────────────────────────────────────────────────────────

LOG_LEVEL = os.environ.get("BAWBEL_LOG_LEVEL", "WARNING").upper()


# ── Severity scoring ──────────────────────────────────────────────────────────

SEVERITY_SCORES: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}


# ── Stage 2: LLM semantic analysis ───────────────────────────────────────────

LLM_ENABLED    = bool(
    os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")
)
LLM_MODEL      = os.environ.get("BAWBEL_LLM_MODEL", "claude-sonnet-4-20250514")
LLM_MAX_TOKENS = int(os.environ.get("BAWBEL_LLM_MAX_TOKENS", "1000"))
LLM_TIMEOUT    = int(os.environ.get("BAWBEL_LLM_TIMEOUT_SEC", "60"))


# ── Stage 3: Behavioral sandbox (future) ─────────────────────────────────────

SANDBOX_ENABLED = os.environ.get("BAWBEL_SANDBOX_ENABLED", "false").lower() == "true"
SANDBOX_TIMEOUT = int(os.environ.get("BAWBEL_SANDBOX_TIMEOUT_SEC", "120"))


# ── CI/CD ─────────────────────────────────────────────────────────────────────

# Exit code when findings at or above threshold
EXIT_CODE_FINDINGS = 2
EXIT_CODE_CLEAN    = 0
EXIT_CODE_WARNING  = 1
