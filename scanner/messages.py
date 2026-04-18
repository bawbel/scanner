"""
Bawbel Scanner — Centralised message definitions.

All user-facing error messages, log messages, and status strings live here.
Never inline message strings in scanner.py, cli.py, or utils.py.
Import from this module and reuse.

Usage:
    from scanner.messages import Errors, Logs, Info
    return ScanResult(error=Errors.FILE_NOT_FOUND.format(path=file_path))
"""


class Errors:
    """
    User-facing error messages returned in ScanResult.error.

    Security rules:
    - NEVER include internal exception details (e, str(e)) — leaks stack info
    - NEVER include absolute internal paths (RULES_DIR, __file__)
    - NEVER include Python version, library versions, or system info
    - File paths in messages use basename only, never absolute paths
    - Error codes are stable — do not rename without updating docs
    """

    # Path / file validation — no internal detail exposed
    INVALID_PATH = "E001: Invalid file path provided."
    PATH_RESOLVE_FAILED = "E002: Could not resolve the provided path."
    FILE_NOT_FOUND = "E003: File not found: {name}"  # basename only
    NOT_A_FILE = "E004: Path is not a regular file: {name}"
    SYMLINK_REJECTED = (
        "E005: Symlinks are not scanned for security reasons. "
        "Resolve the symlink and scan the target file directly."
    )
    FILE_TOO_LARGE = (
        "E006: File too large ({size_kb}KB) — "
        "maximum is {max_mb}MB. "
        "Agentic components should not exceed this size."
    )
    CANNOT_STAT_FILE = "E007: Could not read file metadata."
    CANNOT_READ_FILE = "E008: Could not read file content."

    # Engine errors — no internal paths or exception strings
    YARA_COMPILE_FAILED = "E010: YARA rule compilation failed. Check rule syntax."
    YARA_SCAN_FAILED = "E011: YARA scan failed."
    SEMGREP_PARSE_FAILED = "E012: Could not parse scanner output."
    SEMGREP_TIMEOUT = "E013: Scan timed out after {timeout}s."

    # Rules
    RULES_FILE_MISSING = "E020: Required rules file is missing. Re-install the scanner."


class Logs:
    """Structured log messages — used with the logger."""

    # Scan lifecycle
    SCAN_START = "Scan started: path=%s component_type=%s size_kb=%d"
    SCAN_COMPLETE = "Scan complete: path=%s findings=%d risk=%.1f time_ms=%d"
    SCAN_ERROR = "Scan error: path=%s error=%s"
    SCAN_SKIPPED = "Scan skipped: path=%s reason=%s"

    # Path validation
    SYMLINK_REJECTED = "Symlink rejected: path=%s"
    FILE_TOO_LARGE = "File too large, skipping: path=%s size_kb=%d max_kb=%d"
    COMPONENT_TYPE = "Component type detected: path=%s type=%s ext=%s"

    # Engine lifecycle
    ENGINE_UNAVAILABLE = "Engine unavailable (not installed): engine=%s"
    ENGINE_START = "Engine started: engine=%s path=%s"
    ENGINE_COMPLETE = "Engine complete: engine=%s findings=%d time_ms=%d"
    ENGINE_ERROR = "Engine error: engine=%s path=%s error=%s"
    ENGINE_TIMEOUT = "Engine timeout: engine=%s path=%s timeout_sec=%d"

    # Rules
    RULES_LOADED = "Rules loaded: engine=%s path=%s rule_count=%d"
    RULES_MISSING = "Rules file missing: engine=%s path=%s"

    # Deduplication
    DEDUP_COMPLETE = "Deduplication complete: before=%d after=%d"
    FINDING_DEDUPED = "Finding deduplicated: rule_id=%s kept_severity=%s"

    # Finding
    FINDING_DETECTED = "Finding detected: rule_id=%s severity=%s engine=%s line=%s"

    # CLI
    CLI_SCAN_REQUEST = "CLI scan request: path=%s format=%s recursive=%s"
    CLI_SCAN_FILES = "Files to scan: count=%d"
    CLI_COMPLETE = "CLI scan complete: files=%d total_findings=%d"


class Info:
    """Informational strings shown in the UI (not errors, not logs)."""

    CLEAN_COMPONENT = "No vulnerabilities found"
    CLEAN_DESCRIPTION = "This component passed all AVE checks."
    REPORT_COMING_SOON = "Full A-BOM report generation coming in v0.2.0"
    NO_FILES_FOUND = "No scannable files found in: {path}"
    ENGINE_SKIPPED_MISSING = "Engine skipped — not installed: {engine}"
