"""
Bawbel Scanner — Core orchestrator.

This module is the public API entry point.
It orchestrates the scan pipeline — validation, engine dispatch, deduplication.

It does NOT contain engine logic or rules.
Each engine lives in scanner/engines/<name>.py.
Each model lives in scanner/models/<name>.py.
All config lives in config/default.py.
All strings live in scanner/messages.py.
All helpers live in scanner/utils.py.

Public API:
    from scanner.scanner import scan
    result = scan("/path/to/skill.md")
"""

from pathlib import Path
from typing import Optional

# Config
from config.default import (
    COMPONENT_EXTENSIONS,
    MAX_FILE_SIZE_BYTES,
    SEVERITY_SCORES,
)

# Models
from scanner.models import Finding, ScanResult, Severity

# Engines
from scanner.engines import run_pattern_scan, run_semgrep_scan, run_yara_scan

# Infrastructure
from scanner.messages import Errors, Logs  # noqa: F401
from scanner.utils import (
    Timer,
    get_logger,
    is_safe_path,
    parse_cvss,
    read_file_safe,
    resolve_path,
    truncate_match,
)

log = get_logger(__name__)

# Re-export for backwards compatibility and test imports
__all__ = [
    "scan",
    "Finding",
    "ScanResult",
    "Severity",
    "SEVERITY_SCORES",
    "MAX_FILE_SIZE_BYTES",
]


# ── Internal helpers ──────────────────────────────────────────────────────────


def _error_result(
    file_path: str,
    error: str,
    component_type: str = "unknown",
) -> ScanResult:
    """
    Build a ScanResult for a failed scan.
    Logs the error and returns a clean ScanResult with error set.
    """
    log.error(Logs.SCAN_ERROR, file_path, error)
    return ScanResult(
        file_path=file_path,
        component_type=component_type,
        error=error,
    )


def _make_finding(
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    cvss_ai: float,
    engine: str,
    ave_id: Optional[str] = None,
    line: Optional[int] = None,
    match: Optional[str] = None,
    owasp: Optional[list[str]] = None,
    max_match: int = 80,
) -> Finding:
    """
    Construct a sanitised Finding.
    Always use this — never instantiate Finding directly.
    Validates and clamps all fields.
    """
    return Finding(
        rule_id=rule_id,
        ave_id=ave_id,
        title=title[:max_match],
        description=description,
        severity=severity,
        cvss_ai=parse_cvss(cvss_ai),
        line=line,
        match=truncate_match(match, max_match),
        engine=engine,
        owasp=owasp or [],
    )


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Keep the highest-severity finding per rule_id.

    Stable contract: do not change without a minor version bump.
    Downstream CI/CD integrations may depend on finding counts.
    """
    seen: dict[str, Finding] = {}

    for f in findings:
        existing = seen.get(f.rule_id)
        if existing is None:
            seen[f.rule_id] = f
        elif SEVERITY_SCORES.get(f.severity.value, 0) > SEVERITY_SCORES.get(
            existing.severity.value, 0
        ):
            log.debug(Logs.FINDING_DEDUPED, f.rule_id, f.severity.value)
            seen[f.rule_id] = f

    result = list(seen.values())
    log.debug(Logs.DEDUP_COMPLETE, len(findings), len(result))
    return result


# ── Main public API ───────────────────────────────────────────────────────────


def scan(file_path: str) -> ScanResult:
    """
    Scan an agentic AI component for AVE vulnerabilities.

    This is the single public entry point. It:
      1. Validates and resolves the path
      2. Reads the file safely
      3. Dispatches to all enabled detection engines
      4. Deduplicates and sorts findings
      5. Returns a complete ScanResult

    Never raises — all errors are captured in ScanResult.error.

    Args:
        file_path: Path to the component file (any string — will be validated)

    Returns:
        ScanResult with findings, risk_score, max_severity, scan_time_ms
        ScanResult.is_clean == True only if no findings AND no error
    """
    with Timer() as t:

        # ── Step 1: Resolve path ──────────────────────────────────────────────
        path, path_err = resolve_path(file_path)
        if path_err:
            return _error_result(file_path, path_err)

        # ── Step 2: Validate file ─────────────────────────────────────────────
        safe, safe_err = is_safe_path(path)
        if not safe:
            _log_skip_reason(file_path, path, safe_err)
            return _error_result(str(path), safe_err)

        # ── Step 3: Detect component type ─────────────────────────────────────
        ext = path.suffix.lower()
        component_type = COMPONENT_EXTENSIONS.get(ext, "unknown")
        log.debug(Logs.COMPONENT_TYPE, path, component_type, ext)

        # ── Step 4: Read content ──────────────────────────────────────────────
        content, read_err = read_file_safe(path)
        if read_err:
            return _error_result(str(path), read_err, component_type)

        try:
            size_kb = path.stat().st_size // 1024
        except OSError:
            size_kb = 0

        log.info(Logs.SCAN_START, path, component_type, size_kb)

        # ── Step 5: Run detection engines ─────────────────────────────────────
        findings: list[Finding] = []
        findings.extend(run_pattern_scan(content))
        findings.extend(run_yara_scan(str(path)))
        findings.extend(run_semgrep_scan(str(path)))
        # Future: findings.extend(run_llm_scan(content))
        # Future: findings.extend(run_sandbox_scan(str(path)))

        # ── Step 6: Deduplicate and sort ──────────────────────────────────────
        findings = _deduplicate(findings)
        findings.sort(
            key=lambda f: SEVERITY_SCORES.get(f.severity.value, 0),
            reverse=True,
        )

    result = ScanResult(
        file_path=str(path),
        component_type=component_type,
        findings=findings,
        scan_time_ms=t.elapsed_ms,
    )

    log.info(
        Logs.SCAN_COMPLETE,
        path,
        len(findings),
        result.risk_score,
        t.elapsed_ms,
    )

    return result


def _log_skip_reason(
    original_path: str,
    resolved_path: Optional[Path],
    reason: Optional[str],
) -> None:
    """Log the appropriate warning for a skipped file."""
    if not reason:
        return
    if "ymlink" in reason:
        log.warning(Logs.SYMLINK_REJECTED, original_path)
    elif "too large" in reason.lower():
        try:
            size_kb = resolved_path.stat().st_size // 1024 if resolved_path else 0
        except OSError:
            size_kb = 0
        log.warning(Logs.FILE_TOO_LARGE, original_path, size_kb, MAX_FILE_SIZE_BYTES // 1024)
    else:
        log.warning(Logs.SCAN_SKIPPED, original_path, reason)
