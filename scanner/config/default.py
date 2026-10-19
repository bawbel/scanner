"""
Bawbel Scanner - Default configuration.

All tuneable values live here. Never hardcode these in scanner.py,
engine files, or cli.py. Import from this module.

To override at runtime: set environment variables.
To change defaults for a deployment: edit this file only.
"""

import logging
import os
from pathlib import Path
from typing import Optional

from scanner.messages import Logs

# ── Paths ──────────────────────────────────────────────────────────────────────

PACKAGE_ROOT = Path(__file__).parent.parent.parent
RULES_DIR = PACKAGE_ROOT / "scanner" / "rules"
YARA_RULES = RULES_DIR / "yara" / "ave_rules.yar"
SEMGREP_RULES = RULES_DIR / "semgrep" / "ave_rules.yaml"


# ── Security limits ────────────────────────────────────────────────────────────
# Do not lower these without a security review.

MAX_FILE_SIZE_BYTES = int(os.environ.get("BAWBEL_MAX_FILE_SIZE_MB", "10")) * 1024 * 1024
MAX_MATCH_LENGTH = 80  # chars - prevents CI log leakage
MAX_SCAN_TIMEOUT_SEC = int(os.environ.get("BAWBEL_SCAN_TIMEOUT_SEC", "30"))


# ── Component type detection ───────────────────────────────────────────────────

COMPONENT_EXTENSIONS: dict[str, str] = {
    ".md": "skill",
    ".json": "mcp",
    ".yaml": "prompt",
    ".yml": "prompt",
    ".txt": "prompt",
}


# ── Logging ────────────────────────────────────────────────────────────────────

LOG_LEVEL = os.environ.get("BAWBEL_LOG_LEVEL", "WARNING").upper()


# ── External endpoints ─────────────────────────────────────────────────────────
# The one place that sets them. Each is overridable from the environment, and a value
# that is not an http(s) URL is ignored with a warning, never used.

AVE_API_URL_DEFAULT = "https://api.aveproject.org"


def env_http_url(var: str) -> Optional[str]:
    """Return the http(s) URL in environment variable var, without a trailing slash.

    None when var is unset or empty, or when its value is not an http(s) URL; the last
    case logs a warning so a misconfiguration is visible.
    """
    raw = (os.environ.get(var) or "").strip()
    if not raw:
        return None
    if raw.lower().startswith(("https://", "http://")):
        return raw.rstrip("/")
    logging.getLogger(__name__).warning(Logs.CONFIG_URL_IGNORED, var)
    return None


# AVE records. Findings link to {AVE_API_URL}/records/{ave_id} as ave_url and
# piranha_url (same value until 2.0).
AVE_API_URL = env_http_url("BAWBEL_AVE_API_URL") or AVE_API_URL_DEFAULT
AVE_RECORD_URL_TEMPLATE = AVE_API_URL + "/records/{ave_id}"

# Opt-in false-positive signal (suppression/justified.py). No default: the hosted
# PiranhaDB API is offline, so nothing is sent unless BAWBEL_PIRANHA_URL is set.
FP_SIGNAL_URL = env_http_url("BAWBEL_PIRANHA_URL")


# ── Stage 2: LLM semantic analysis ────────────────────────────────────────────

LLM_ENABLED = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY"))
LLM_MODEL = os.environ.get("BAWBEL_LLM_MODEL", "claude-sonnet-4-20250514")
LLM_MAX_TOKENS = int(os.environ.get("BAWBEL_LLM_MAX_TOKENS", "1000"))
LLM_TIMEOUT = int(os.environ.get("BAWBEL_LLM_TIMEOUT_SEC", "60"))


# ── Stage 3: Behavioral sandbox (future) ──────────────────────────────────────

SANDBOX_ENABLED = os.environ.get("BAWBEL_SANDBOX_ENABLED", "false").lower() == "true"
SANDBOX_TIMEOUT = int(os.environ.get("BAWBEL_SANDBOX_TIMEOUT_SEC", "120"))


# ── CI/CD ──────────────────────────────────────────────────────────────────────

# Exit code when findings at or above threshold
EXIT_CODE_FINDINGS = 2
EXIT_CODE_CLEAN = 0
EXIT_CODE_WARNING = 1
