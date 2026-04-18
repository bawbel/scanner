"""
Bawbel Scanner — Configuration package.

Import config values from here, not from config.default directly.
This ensures a stable public interface even if the config internals change.

Usage:
    from config import MAX_FILE_SIZE_BYTES, COMPONENT_EXTENSIONS, LOG_LEVEL
"""

from config.default import (
    # Paths
    PACKAGE_ROOT,
    RULES_DIR,
    YARA_RULES,
    SEMGREP_RULES,

    # Security limits
    MAX_FILE_SIZE_BYTES,
    MAX_MATCH_LENGTH,
    MAX_SCAN_TIMEOUT_SEC,

    # Component detection
    COMPONENT_EXTENSIONS,

    # Logging
    LOG_LEVEL,

    # Severity
    SEVERITY_SCORES,

    # Stage 2 LLM
    LLM_ENABLED,
    LLM_MODEL,
    LLM_MAX_TOKENS,
    LLM_TIMEOUT,

    # Stage 3 Sandbox
    SANDBOX_ENABLED,
    SANDBOX_TIMEOUT,

    # CI/CD exit codes
    EXIT_CODE_FINDINGS,
    EXIT_CODE_CLEAN,
    EXIT_CODE_WARNING,
)

__all__ = [
    "PACKAGE_ROOT", "RULES_DIR", "YARA_RULES", "SEMGREP_RULES",
    "MAX_FILE_SIZE_BYTES", "MAX_MATCH_LENGTH", "MAX_SCAN_TIMEOUT_SEC",
    "COMPONENT_EXTENSIONS", "LOG_LEVEL", "SEVERITY_SCORES",
    "LLM_ENABLED", "LLM_MODEL", "LLM_MAX_TOKENS", "LLM_TIMEOUT",
    "SANDBOX_ENABLED", "SANDBOX_TIMEOUT",
    "EXIT_CODE_FINDINGS", "EXIT_CODE_CLEAN", "EXIT_CODE_WARNING",
]
