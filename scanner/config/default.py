"""
Bawbel Scanner - Default configuration.

All tuneable values live here. Never hardcode these in scanner.py,
engine files, or cli.py. Import from this module.

To override at runtime: set environment variables.
To change defaults for a deployment: edit this file only.
"""

import logging
import os
import re
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlsplit

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


# host or host:port, letters, digits, dots, and hyphens only: no credentials, no spaces,
# no quotes.
_HOST_PORT = re.compile(r"^[A-Za-z0-9.-]+(:[0-9]{1,5})?$")


def env_http_url(var: str) -> Optional[str]:
    """Return the http(s) URL in environment variable var, normalised, or None.

    The value must parse as http(s) with a plain host[:port]. The result is rebuilt from
    scheme, host, and percent-encoded path, without query, fragment, or trailing slash.
    None when var is unset or empty, or when the value does not qualify; the last case
    logs a warning so a misconfiguration is visible.
    """
    raw = (os.environ.get(var) or "").strip()
    if not raw:
        return None
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme in ("http", "https") and _HOST_PORT.match(parts.netloc):
        path = quote(parts.path, safe="/%")
        return f"{scheme}://{parts.netloc}{path}".rstrip("/")
    logging.getLogger(__name__).warning(Logs.CONFIG_URL_IGNORED, var)
    return None


def env_int(var: str, default: int, minimum: int = 1) -> int:
    """Return the integer in environment variable var, or default.

    default when var is unset or empty, or when its value is not an integer of at least
    minimum; the last case logs a warning.
    """
    raw = (os.environ.get(var) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = minimum - 1
    if value < minimum:
        logging.getLogger(__name__).warning(Logs.CONFIG_INT_IGNORED, var, default)
        return default
    return value


# Outbound HTTP: one timeout for server-card fetches and MCP registry lookups.
HTTP_TIMEOUT_SEC = env_int("BAWBEL_HTTP_TIMEOUT_SEC", 10)

# AVE records. Findings link to {AVE_API_URL}/records/{ave_id} as ave_url and
# piranha_url (same value until 2.0).
AVE_API_URL = env_http_url("BAWBEL_AVE_API_URL") or AVE_API_URL_DEFAULT
AVE_RECORD_URL_TEMPLATE = AVE_API_URL + "/records/{ave_id}"

# Opt-in false-positive signal (suppression/justified.py). No default: the hosted
# PiranhaDB API is offline, so nothing is sent unless BAWBEL_PIRANHA_URL is set.
FP_SIGNAL_URL = env_http_url("BAWBEL_PIRANHA_URL")
FP_SIGNAL_TIMEOUT_SEC = 5  # the signal is best-effort; never hold up the caller

# Bawbel Scanner's homepage, reported as the SARIF tool informationUri.
PROJECT_HOMEPAGE_URL = "https://bawbel.io"

# The AVE project, linked from SARIF rules that have no AVE record.
AVE_PROJECT_URL = "https://github.com/aveproject/ave"

# Official MCP registry, used by `bawbel conform` to look up a server by name.
MCP_REGISTRY_URL_DEFAULT = "https://registry.modelcontextprotocol.io"
MCP_REGISTRY_URL = env_http_url("BAWBEL_MCP_REGISTRY_URL") or MCP_REGISTRY_URL_DEFAULT


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
