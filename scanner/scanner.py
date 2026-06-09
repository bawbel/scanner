"""
Bawbel Scanner - Core orchestrator.

This module is the public API entry point.
It orchestrates the scan pipeline - validation, engine dispatch, deduplication.

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
from scanner.models.severity import calc_aivss, severity_from_aivss, DEFAULT_AARF

# Engines
from scanner.engines import run_pattern_scan, run_semgrep_scan, run_yara_scan, run_llm_scan
from scanner.engines.magika_engine import run_magika_scan
from scanner.engines.meta_analyzer import run_meta_analysis
from scanner.engines.sandbox_engine import (
    run_sandbox_scan,
    SANDBOX_ENABLED,
    is_docker_available,
)

# Core pure functions
from scanner.core.preprocessor import strip_code_fences
from scanner.core.dedup import deduplicate
from scanner.core.fp_pipeline import run_fp_pipeline

# Toxic flow analysis
from scanner.core.toxic_flows import detect_toxic_flows

# Infrastructure
from scanner.messages import Logs
from scanner.suppression.inline import apply_suppressions, NO_IGNORE
from scanner.suppression.justified import (
    apply_justified_suppressions,
    parse_accepted_findings,
)
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

# Per-process warning flags - emit each warning only once across all files
_warned_sandbox_no_image: bool = False
_warned_sandbox_no_docker: bool = False

# Re-export for backwards compatibility and test imports
__all__ = [
    "scan",
    "Finding",
    "ScanResult",
    "Severity",
    "SEVERITY_SCORES",
    "MAX_FILE_SIZE_BYTES",
]

# ── Internal helpers ─────────────────────────────────────────────────────────


def _error_result(
    file_path: str,
    error: str,
    component_type: str = "unknown",
) -> ScanResult:
    """Build a ScanResult for a failed scan."""
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
    aivss_score: float,
    engine: str,
    ave_id: Optional[str] = None,
    line: Optional[int] = None,
    match: Optional[str] = None,
    owasp: Optional[list[str]] = None,
    owasp_mcp: Optional[list[str]] = None,
    cvss_base: float = 0.0,
    aarf: Optional[dict] = None,
    thm: float = 0.75,
    mitigation_factor: float = 1.0,
    max_match: int = 80,
) -> Finding:
    """Construct a sanitised Finding with AIVSS scoring applied."""
    if cvss_base > 0.0 and aarf:
        computed = calc_aivss(cvss_base, aarf, thm, mitigation_factor)
        severity = severity_from_aivss(computed)
        score = computed
    else:
        score = parse_cvss(aivss_score)

    return Finding(
        rule_id=rule_id,
        ave_id=ave_id,
        title=title[:max_match],
        description=description,
        severity=severity,
        aivss_score=score,
        cvss_base=cvss_base,
        aarf=aarf or dict(DEFAULT_AARF),
        aars=round(sum((aarf or DEFAULT_AARF).values()), 1),
        thm=thm,
        mitigation_factor=mitigation_factor,
        line=line,
        match=truncate_match(match, max_match),
        engine=engine,
        owasp=owasp or [],
        owasp_mcp=owasp_mcp or [],
    )


# ── Main public API ───────────────────────────────────────────────────────────


def scan(file_path: str, no_ignore: bool = False) -> ScanResult:
    """
    Scan an agentic AI component for AVE vulnerabilities.

    This is the single public entry point. It:
      1. Validates and resolves the path
      2. Reads the file safely
      3. Dispatches to all enabled detection engines
      4. Deduplicates and sorts findings
      5. Applies the 5-layer FP reduction pipeline
      6. Applies inline suppressions
      7. Returns a complete ScanResult with OWASP AIVSS v0.8 scores

    Never raises - all errors are captured in ScanResult.error.

    Args:
        file_path: Path to the component file (any string - will be validated)
        no_ignore: If True, skip all suppressions - audit mode

    Returns:
        ScanResult with findings, suppressed_findings, risk_score,
        max_severity, scan_time_ms, and toxic_flows.
        ScanResult.is_clean == True only if no findings AND no error.
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

        # ── Step 5: FP-1 - Strip code fences ─────────────────────────────────
        # Content inside ``` blocks is replaced with blank lines.
        # Line numbers stay accurate. Original content preserved for sandbox.
        stripped = strip_code_fences(content)

        findings: list[Finding] = []

        # ── Stage 0: Magika content-type verification ─────────────────────────
        magika_findings = run_magika_scan(str(path))
        findings.extend(magika_findings)
        if magika_findings:
            dangerous = any(f.rule_id == "bawbel-content-type-dangerous" for f in magika_findings)
            if dangerous:
                log.warning(
                    "Magika: dangerous content type in %s - " "skipping text analysis engines",
                    path.name,
                )
            else:
                findings.extend(run_pattern_scan(stripped))
                findings.extend(run_yara_scan(str(path), stripped))
                findings.extend(run_semgrep_scan(str(path), stripped))
                findings.extend(run_llm_scan(content))
        else:
            findings.extend(run_pattern_scan(stripped))
            findings.extend(run_yara_scan(str(path), stripped))
            findings.extend(run_semgrep_scan(str(path), stripped))
            findings.extend(run_llm_scan(content))

        # ── Stage 3: Behavioral sandbox ───────────────────────────────────────
        if SANDBOX_ENABLED:
            if is_docker_available():
                sandbox_findings = run_sandbox_scan(str(path), stripped_content=stripped)
                findings.extend(sandbox_findings)
                if not sandbox_findings:
                    global _warned_sandbox_no_image
                    if not _warned_sandbox_no_image:
                        _warned_sandbox_no_image = True
                        log.warning(
                            "Sandbox engine: no findings returned - "
                            "ensure bawbel/sandbox:latest image is built "
                            "or set BAWBEL_SANDBOX_IMAGE=local to build locally. "
                            "See docs/guides/engines.md for setup."
                        )
            else:
                global _warned_sandbox_no_docker
                if not _warned_sandbox_no_docker:
                    _warned_sandbox_no_docker = True
                    log.warning("Sandbox engine: Docker not running - Stage 3 skipped")

        # ── Step 6: Deduplicate and sort ──────────────────────────────────────
        findings = deduplicate(findings)
        findings.sort(
            key=lambda f: SEVERITY_SCORES.get(f.severity.value, 0),
            reverse=True,
        )

        toxic_flows = detect_toxic_flows(findings)

        # ── Step 7: FP-2 + FP-3 + FP-5 ───────────────────────────────────────
        if no_ignore or NO_IGNORE:
            for f in findings:
                f.confidence = 1.0
            active_findings: list[Finding] = list(findings)
            low_confidence: list[Finding] = []
        else:
            active_findings = run_fp_pipeline(findings, path, content)
            low_confidence = [f for f in findings if f.suppressed]

        # ── Step 8: FP-4 - Meta-analyzer ──────────────────────────────────────
        # One LLM call per file reviews medium-confidence findings (0.35-0.80).
        # Returns real / false_positive / needs_review per finding.
        # Skips silently if LLM not configured.
        magika_label = next(
            (f.match.replace("detected: ", "") for f in findings if f.engine == "magika"),
            "unknown",
        )
        active_findings = run_meta_analysis(
            findings=active_findings,
            content=content,
            file_path=str(path),
            magika_label=magika_label,
        )
        meta_fp = [f for f in active_findings if f.suppressed]
        active_findings = [f for f in active_findings if not f.suppressed]
        low_confidence.extend(meta_fp)

        # ── Step 9: Apply inline suppressions ─────────────────────────────────
        sup = apply_suppressions(
            findings=active_findings,
            file_path=str(path),
            content=content,
            no_ignore=no_ignore or NO_IGNORE,
        )

        # ── Step 10: Apply justified suppressions (bawbel-accept / extended bawbel-ignore)
        # J1: parse reason/reviewer/reviewed/expires metadata from file
        # J5: expired accepted risks are NOT suppressed - they resurface as active
        if no_ignore or NO_IGNORE:
            just_active = sup.active
            just_suppressed = []
            accepted_list = []
        else:
            accepted_list = parse_accepted_findings(content, str(path))
            just_active, just_suppressed, accepted_list = apply_justified_suppressions(
                findings=sup.active,
                accepted_list=accepted_list,
                file_path=str(path),
            )

    result = ScanResult(
        file_path=str(path),
        component_type=component_type,
        findings=just_active,
        suppressed_findings=sup.suppressed + just_suppressed + low_confidence,
        scan_time_ms=t.elapsed_ms,
        toxic_flows=toxic_flows,
        accepted_findings=accepted_list,
    )

    log.info(
        Logs.SCAN_COMPLETE,
        path,
        len(sup.active),
        result.risk_score,
        t.elapsed_ms,
    )

    if sup.suppressed:
        log.info(
            "Suppression: %d finding(s) suppressed in %s - run with --no-ignore to see all",
            len(sup.suppressed),
            path.name,
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
