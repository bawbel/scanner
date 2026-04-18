"""
Bawbel Scanner — Utilities and helpers.

All shared infrastructure lives here as focused classes.
Import functions (not classes) via the module-level aliases at the bottom.

Classes:
    Logger          — structured logging factory
    PathValidator   — safe path resolution and validation
    FileReader      — safe file reading with encoding fallback
    SubprocessRunner — safe external tool execution
    JsonParser      — safe JSON parsing
    TextSanitiser   — string validation and truncation
    Timer           — elapsed time context manager

Usage (preferred — use module-level functions):
    from scanner.utils import get_logger, resolve_path, is_safe_path, ...

Usage (direct class):
    from scanner.utils import PathValidator
    path, err = PathValidator.resolve("/some/path")
"""

import json
import logging
import os
import subprocess  # nosec B404  # noqa: S404
import time
from pathlib import Path
from typing import Optional

from scanner.messages import Errors, Logs

# ── Logger ────────────────────────────────────────────────────────────────────


class Logger:
    """
    Logging factory for all scanner modules.

    Log level controlled by BAWBEL_LOG_LEVEL env var (default: WARNING).
    All loggers share the same format and are namespaced under "bawbel.".

    Security note:
        NEVER log file content, match strings, or exception messages at
        WARNING or above. Use DEBUG level for full diagnostic details.
        Always use type(e).__name__ in warning/error messages, not str(e).

    Usage:
        log = Logger.get(__name__)
        log.debug("detail: value=%s", value)       # DEBUG only — full detail
        log.warning("skipped: reason=%s", code)    # WARNING — code only
        log.error("failed: type=%s", type(e).__name__)  # ERROR — type only
    """

    FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    DATE_FMT = "%Y-%m-%dT%H:%M:%S"
    _LEVEL = os.environ.get("BAWBEL_LOG_LEVEL", "WARNING").upper()

    @classmethod
    def get(cls, name: str) -> logging.Logger:
        """
        Return a named logger under the bawbel namespace.

        Args:
            name: Module name — use __name__ from the calling module

        Returns:
            Configured logging.Logger instance
        """
        logger = logging.getLogger(f"bawbel.{name}")

        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(cls.FORMAT, datefmt=cls.DATE_FMT))
            logger.addHandler(handler)

        try:
            logger.setLevel(getattr(logging, cls._LEVEL, logging.WARNING))
        except (AttributeError, TypeError):
            logger.setLevel(logging.WARNING)

        return logger


# ── PathValidator ─────────────────────────────────────────────────────────────


class PathValidator:
    """
    Safe path resolution and validation.

    All path operations follow this security contract:
    1. Check symlink on the RAW path (before resolve)
    2. Resolve to absolute path
    3. Check file existence, type, and size

    This order matters — Path.resolve() follows symlinks, so the symlink
    check MUST happen before resolve() to prevent symlink attacks.
    """

    _log = Logger.get("utils.path")

    @classmethod
    def resolve(cls, file_path: str) -> tuple[Optional[Path], Optional[str]]:
        """
        Safely construct and resolve a Path from a string.

        Checks: valid path string, not a symlink.

        Args:
            file_path: Raw path string from user input

        Returns:
            (resolved Path, None) on success
            (None, error code string) on failure
        """
        try:
            raw = Path(file_path)
        except Exception as e:
            cls._log.warning("invalid path input: error_type=%s", type(e).__name__)
            return None, Errors.INVALID_PATH

        # Symlink check BEFORE resolve()
        if raw.is_symlink():
            cls._log.warning(Logs.SYMLINK_REJECTED, file_path)
            return None, Errors.SYMLINK_REJECTED

        try:
            resolved = raw.resolve()
        except Exception as e:
            cls._log.warning("path resolve failed: error_type=%s", type(e).__name__)
            return None, Errors.PATH_RESOLVE_FAILED

        return resolved, None

    @classmethod
    def validate(cls, path: Path) -> tuple[bool, Optional[str]]:
        """
        Validate a resolved path is safe and scannable.

        Checks: not a symlink, exists, is a file, within size limit.

        Args:
            path: A Path object (should already be resolved)

        Returns:
            (True, None) if valid
            (False, error code string) if invalid
        """
        from config.default import MAX_FILE_SIZE_BYTES

        if path.is_symlink():
            return False, Errors.SYMLINK_REJECTED

        if not path.exists():
            return False, Errors.FILE_NOT_FOUND.format(name=path.name)

        if not path.is_file():
            return False, Errors.NOT_A_FILE.format(name=path.name)

        try:
            size = path.stat().st_size
        except OSError as e:
            cls._log.warning("stat failed: error_type=%s", type(e).__name__)
            return False, Errors.CANNOT_STAT_FILE

        if size > MAX_FILE_SIZE_BYTES:
            return False, Errors.FILE_TOO_LARGE.format(
                size_kb=size // 1024,
                max_mb=MAX_FILE_SIZE_BYTES // 1024 // 1024,
            )

        return True, None


# ── FileReader ────────────────────────────────────────────────────────────────


class FileReader:
    """
    Safe file reading with encoding fallback.

    Security note:
        Always uses errors="ignore" — malicious files may contain invalid
        UTF-8 sequences designed to cause UnicodeDecodeError and expose
        stack traces. Dropping invalid bytes is safe for text analysis.
    """

    _log = Logger.get("utils.file")

    @classmethod
    def read_text(cls, path: Path) -> tuple[Optional[str], Optional[str]]:
        """
        Read a text file safely.

        Args:
            path: Resolved, validated Path object

        Returns:
            (content string, None) on success
            (None, error code string) on failure
        """
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            return content, None
        except PermissionError as e:
            cls._log.warning("permission denied: error_type=%s", type(e).__name__)
            return None, Errors.CANNOT_READ_FILE
        except OSError as e:
            cls._log.warning("file read failed: error_type=%s", type(e).__name__)
            return None, Errors.CANNOT_READ_FILE
        except Exception as e:  # nosec B110
            cls._log.error("unexpected read error: error_type=%s", type(e).__name__)
            return None, Errors.CANNOT_READ_FILE


# ── SubprocessRunner ──────────────────────────────────────────────────────────


class SubprocessRunner:
    """
    Safe external tool execution via subprocess.

    Security contract (never violate):
    - Args are ALWAYS a list — never a string, never shell=True
    - User input is NEVER interpolated into command strings
    - Timeout is ALWAYS enforced
    - stderr is NEVER returned to the user (logged at DEBUG only)
    - Tool-not-found returns (None, None) — caller skips silently
    """

    _log = Logger.get("utils.subprocess")

    @classmethod
    def run(
        cls,
        args: list[str],
        timeout: int,
        label: str,
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Run an external command safely.

        Args:
            args:    Command + arguments as a list (security: never a string)
            timeout: Maximum seconds before TimeoutExpired
            label:   Human-readable identifier for logging

        Returns:
            (stdout string, None) on success
            (None, None) if tool not installed — caller should skip silently
            (None, error code) on failure
        """
        start = time.time()

        try:
            result = subprocess.run(  # nosec B603 B607  # noqa: S603
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            elapsed = int((time.time() - start) * 1000)

            cls._log.debug(
                "complete: label=%s exit_code=%d time_ms=%d",
                label,
                result.returncode,
                elapsed,
            )

            if result.returncode not in (0, 1):
                cls._log.warning(
                    "non-zero exit: label=%s code=%d",
                    label,
                    result.returncode,
                )
                if result.stderr:
                    # Stderr may contain internal paths — DEBUG only
                    cls._log.debug(
                        "stderr: label=%s content=%s",
                        label,
                        result.stderr[:100],
                    )

            return result.stdout or "", None

        except subprocess.TimeoutExpired:
            cls._log.error("timeout: label=%s timeout_sec=%d", label, timeout)
            return None, Errors.SEMGREP_TIMEOUT.format(timeout=timeout)

        except FileNotFoundError:
            cls._log.info("tool not found: label=%s cmd=%s", label, args[0] if args else "")
            return None, None  # not installed — skip silently

        except Exception as e:  # nosec B110
            cls._log.error("error: label=%s error_type=%s", label, type(e).__name__)
            return None, Errors.YARA_SCAN_FAILED


# ── JsonParser ────────────────────────────────────────────────────────────────


class JsonParser:
    """
    Safe JSON parsing with structured error returns.

    Never raises. Always returns (result, error) tuple.
    """

    _log = Logger.get("utils.json")

    @classmethod
    def parse(
        cls,
        raw: str,
        label: str = "json",
    ) -> tuple[Optional[dict | list], Optional[str]]:
        """
        Parse a JSON string safely.

        Args:
            raw:   Raw JSON string (may be empty or malformed)
            label: Identifier for log messages

        Returns:
            (parsed object, None) on success
            (None, error code) on failure
        """
        if not raw or not raw.strip():
            return None, None  # empty output is not an error

        try:
            return json.loads(raw), None
        except json.JSONDecodeError as e:
            cls._log.warning("parse failed: label=%s error_type=%s", label, type(e).__name__)
            return None, Errors.SEMGREP_PARSE_FAILED
        except Exception as e:  # nosec B110
            cls._log.error("unexpected error: label=%s error_type=%s", label, type(e).__name__)
            return None, Errors.SEMGREP_PARSE_FAILED


# ── TextSanitiser ─────────────────────────────────────────────────────────────


class TextSanitiser:
    """
    String validation and sanitisation.

    Security note:
        truncate_match enforces MAX_MATCH_LENGTH on all match strings
        before they are stored in findings. This prevents long content
        from leaking into CI logs, SIEM systems, or JSON reports.
    """

    @staticmethod
    def truncate(text: Optional[str], max_len: int) -> Optional[str]:
        """
        Truncate a string to max_len after stripping whitespace.

        Args:
            text:    Input string (may be None)
            max_len: Maximum character length

        Returns:
            Truncated string, or None if input is None
        """
        if text is None:
            return None
        cleaned = text.strip()
        return cleaned[:max_len] if len(cleaned) > max_len else cleaned

    @staticmethod
    def parse_severity(severity_str: str, fallback: str = "HIGH") -> str:
        """
        Validate and normalise a severity string.

        Args:
            severity_str: Raw severity from rule metadata
            fallback:     Returned if severity_str is unrecognised

        Returns:
            Valid severity string: CRITICAL | HIGH | MEDIUM | LOW | INFO
        """
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        normalised = severity_str.strip().upper() if severity_str else fallback
        if normalised not in valid:
            Logger.get("utils.severity").warning(
                "unknown severity: value=%s fallback=%s",
                severity_str,
                fallback,
            )
            return fallback
        return normalised

    @staticmethod
    def parse_cvss(raw: object, fallback: float = 5.0) -> float:
        """
        Parse and clamp a CVSS score to 0.0–10.0.

        Args:
            raw:      Raw value (str, float, int, or None)
            fallback: Returned if raw cannot be parsed

        Returns:
            Float clamped to [0.0, 10.0]
        """
        try:
            return max(0.0, min(10.0, float(raw)))
        except (TypeError, ValueError):
            Logger.get("utils.cvss").warning(
                "invalid CVSS score: value=%r fallback=%.1f", raw, fallback
            )
            return fallback


# ── Timer ─────────────────────────────────────────────────────────────────────


class Timer:
    """
    Elapsed-time context manager.

    Usage:
        with Timer() as t:
            do_work()
        log.debug("took %dms", t.elapsed_ms)
    """

    def __init__(self) -> None:
        self._start: float = 0.0
        self.elapsed_ms: int = 0

    def __enter__(self) -> "Timer":
        self._start = time.time()
        return self

    def __exit__(self, *_: object) -> None:
        self.elapsed_ms = int((time.time() - self._start) * 1000)


# ── Module-level aliases ──────────────────────────────────────────────────────
# These allow callers to import functions rather than classes,
# keeping call sites clean without losing the OOP structure.


def get_logger(name: str) -> logging.Logger:
    """Alias for Logger.get(name)."""
    return Logger.get(name)


def resolve_path(file_path: str) -> tuple[Optional[Path], Optional[str]]:
    """Alias for PathValidator.resolve(file_path)."""
    return PathValidator.resolve(file_path)


def is_safe_path(path: Path) -> tuple[bool, Optional[str]]:
    """Alias for PathValidator.validate(path)."""
    return PathValidator.validate(path)


def read_file_safe(path: Path) -> tuple[Optional[str], Optional[str]]:
    """Alias for FileReader.read_text(path)."""
    return FileReader.read_text(path)


def run_subprocess(
    args: list[str],
    timeout: int,
    label: str,
) -> tuple[Optional[str], Optional[str]]:
    """Alias for SubprocessRunner.run(args, timeout, label)."""
    return SubprocessRunner.run(args, timeout, label)


def parse_json_safe(
    raw: str,
    label: str = "json",
) -> tuple[Optional[dict | list], Optional[str]]:
    """Alias for JsonParser.parse(raw, label)."""
    return JsonParser.parse(raw, label)


def parse_severity(severity_str: str, fallback: str = "HIGH") -> str:
    """Alias for TextSanitiser.parse_severity(severity_str, fallback)."""
    return TextSanitiser.parse_severity(severity_str, fallback)


def parse_cvss(raw: object, fallback: float = 5.0) -> float:
    """Alias for TextSanitiser.parse_cvss(raw, fallback)."""
    return TextSanitiser.parse_cvss(raw, fallback)


def truncate_match(text: Optional[str], max_len: int) -> Optional[str]:
    """Alias for TextSanitiser.truncate(text, max_len)."""
    return TextSanitiser.truncate(text, max_len)
