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
from scanner.models.finding import calc_aivss, severity_from_aivss, DEFAULT_AARF

# Engines
from scanner.engines import run_pattern_scan, run_semgrep_scan, run_yara_scan, run_llm_scan
from scanner.engines.magika_engine import run_magika_scan
from scanner.engines.meta_analyzer import run_meta_analysis
from scanner.engines.sandbox_engine import (
    run_sandbox_scan,
    SANDBOX_ENABLED,
    is_docker_available,
)

# Toxic flow analysis
from scanner.toxic_flows import detect_toxic_flows

# Infrastructure
from scanner.messages import Logs
from scanner.suppression import apply_suppressions, NO_IGNORE
from scanner.justified_suppression import (
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
import os as _os
import re as _re

# Matches fenced code blocks: ```...``` (any language tag, any content)
# Uses DOTALL so . matches newlines. Non-greedy to handle multiple fences.
_FENCE_RE = _re.compile(r"```[^\n]*\n(.*?)```", _re.DOTALL)
# Also match ~~~...~~~ fences (less common but valid Markdown)
_TILDE_RE = _re.compile(r"~~~[^\n]*\n(.*?)~~~", _re.DOTALL)


def _strip_code_fences(content: str) -> str:
    """
    Replace fenced code block content with blank lines, preserving line numbers.

    Replaces the *content* of each ``` or ~~~ block with an equal number of
    blank lines so that line N in the stripped content maps to the same line N
    in the original. This keeps Finding.line accurate.

    The fence markers themselves are kept - only the content between them is
    blanked. Content inside fences is not scanned by static analysis engines.

    Why preserve line numbers:
        If we deleted fenced lines instead of blanking them, every finding
        below a fence would have an off-by-N line number.

    Why sandbox gets the original content:
        The sandbox runs the full file. A malicious payload hidden inside a
        code fence is still caught behaviourally.

    Args:
        content: Raw file content string.

    Returns:
        Content string with fenced block interiors replaced by blank lines.
    """

    def _blank_interior(m: _re.Match) -> str:
        interior = m.group(1)
        blank_lines = "\n" * interior.count("\n")
        fence_open = m.group(0).split("\n")[0]
        return fence_open + "\n" + blank_lines + "```"

    def _blank_tilde(m: _re.Match) -> str:
        interior = m.group(1)
        blank_lines = "\n" * interior.count("\n")
        fence_open = m.group(0).split("\n")[0]
        return fence_open + "\n" + blank_lines + "~~~"

    result = _FENCE_RE.sub(_blank_interior, content)
    result = _TILDE_RE.sub(_blank_tilde, result)
    return result


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

# ── FP-2: Preceding-line negation context ────────────────────────────────────
# If the line immediately before a match contains any of these prefixes,
# the match is almost certainly a documentation example, not a real attack.

_NEGATION_PREFIXES: frozenset[str] = frozenset(
    {
        "bad:",
        "bad example",
        "avoid",
        "do not",
        "don't",
        "never",
        "example:",
        "e.g.",
        "for example",
        "watch out",
        "warning:",
        "incorrect:",
        "instead of",
        "such as",
        "like this:",
        "unsafe:",
        "dangerous:",
        "do not run",
        "do not use",
        "never do this",
        "antipattern",
        "anti-pattern",
        "\u274c",
        "\u2717",
        "wrong:",
        "# bad",
        "// bad",
        "<!-- bad",
    }
)


def _has_negation_context(lines: list[str], line_no: int) -> bool:
    """
    Return True if the line immediately preceding line_no (1-indexed)
    contains a negation / documentation prefix.
    """
    if line_no is None or line_no < 2:
        return False
    preceding = lines[line_no - 2].lower().strip()
    return any(prefix in preceding for prefix in _NEGATION_PREFIXES)


# ── FP-3: Confidence scoring ──────────────────────────────────────────────────
_CONFIDENCE_THRESHOLD: float = float(_os.environ.get("BAWBEL_CONFIDENCE_THRESHOLD", "0.80"))

_SKILL_NAMES: frozenset[str] = frozenset(
    {
        "skill.md",
        "skills.md",
        "system_prompt.md",
        "system_prompt.txt",
        "system_prompt.yaml",
        "system_prompt.yml",
        "agent.md",
        "assistant.md",
    }
)

_DOC_PATH_SEGMENTS: frozenset[str] = frozenset(
    {
        "docs",
        "doc",
        "documentation",
        "examples",
        "example",
        "guides",
        "guide",
        "samples",
        "sample",
        "demo",
    }
)


def _score_confidence(
    finding: Finding,
    lines: list[str],
    path: Path,
    all_findings: list[Finding],
) -> float:
    """
    Compute a confidence score (0.0-1.0) for a finding.

    Score represents the probability that this is a true positive.
    Starts at 1.0 and adjusts based on context signals.

    Penalties (reduce confidence - likely FP):
        -0.4  preceded by negation context
        -0.45 match is inside a markdown table (line starts with |)
        -0.55 match is in a heading (line starts with #)
        -0.35 file path contains a docs/examples/tests segment
        -0.2  match text is very short (< 6 chars)

    Boosts (increase confidence - likely TP):
        +0.15 match is in the first 30 lines
        +0.25 two or more engines agree on the same ave_id
        +0.15 file is named SKILL.md or system_prompt.*
        +0.05 AIVSS score >= 9.0
    """
    score = 1.0
    line_no = finding.line

    if line_no is not None:
        if _has_negation_context(lines, line_no):
            score -= 0.4
        if 1 <= line_no <= len(lines):
            current_line = lines[line_no - 1].lstrip()
            if current_line.startswith("|"):
                score -= 0.45
            if _re.match(r"#{1,6}\s+\w", current_line):
                score -= 0.55

    path_parts = {p.lower() for p in path.parts}
    in_docs_path = bool(path_parts & _DOC_PATH_SEGMENTS)
    if in_docs_path:
        score -= 0.35

    if finding.match and len(finding.match.strip()) < 6:
        score -= 0.2

    if line_no is not None and line_no <= 30 and not in_docs_path:
        score += 0.15

    if finding.ave_id:
        agreeing = sum(
            1 for f in all_findings if f.ave_id == finding.ave_id and f.engine != finding.engine
        )
        if agreeing >= 1:
            score += 0.25

    if path.name.lower() in _SKILL_NAMES:
        score += 0.15

    # Use aivss_score for the critical signal boost (was cvss_ai in v1.1)
    if finding.aivss_score >= 9.0:
        score += 0.05

    return max(0.0, min(1.0, score))


# ── FP-5: File-type scan profiles ────────────────────────────────────────────
_PROFILE_THRESHOLDS: dict[str, float] = {
    "skill": 0.60,
    "mcp_manifest": 0.55,
    "documentation": 0.85,
    "unknown": 0.80,
}


def _classify_file(path: Path) -> str:
    """
    Classify a file into a scan profile based on name and path.

    Returns one of: "skill" | "mcp_manifest" | "documentation" | "unknown"
    """
    name = path.name.lower()
    parts = {p.lower() for p in path.parts}

    if name in {
        "skill.md",
        "skills.md",
        "system_prompt.md",
        "system_prompt.txt",
        "system_prompt.yaml",
        "system_prompt.yml",
        "agent.md",
        "assistant.md",
        "prompt.md",
    }:
        return "skill"
    if name.endswith((".skill.md", ".skill.yaml", ".skill.yml")):
        return "skill"

    if any(name.startswith(prefix) for prefix in ("mcp_", "mcp-", "mcp.")) and name.endswith(
        (".json", ".yaml", ".yml")
    ):
        return "mcp_manifest"
    if name in {"mcp_manifest.json", "mcp_manifest.yaml", "server.json"}:
        return "mcp_manifest"

    doc_segments = {
        "docs",
        "doc",
        "documentation",
        "examples",
        "example",
        "guides",
        "guide",
        "samples",
        "sample",
        "demo",
    }
    if parts & doc_segments:
        return "documentation"

    if name in {
        "readme.md",
        "changelog.md",
        "contributing.md",
        "license.md",
        "authors.md",
        "history.md",
    }:
        return "documentation"

    return "unknown"


# ── Internal helpers ──────────────────────────────────────────────────────────


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
    aivss_score: float,  # renamed from cvss_ai - OWASP AIVSS v0.8
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
    """
    Construct a sanitised Finding.
    Always use this - never instantiate Finding directly.

    If cvss_base and aarf are provided, aivss_score is computed from
    the OWASP AIVSS v0.8 formula. Otherwise aivss_score is used directly.
    """
    # Compute AIVSS score from formula if AARF data is available
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


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Deduplicate findings across engines.

    Pass 1: Keep highest-severity finding per rule_id.
    Pass 2: Keep highest-severity finding per (ave_id, line) - removes
            cross-engine duplicates where pattern + YARA + Semgrep all
            detect the same AVE on the same line.
    """
    by_rule: dict[str, Finding] = {}
    for f in findings:
        existing = by_rule.get(f.rule_id)
        if existing is None:
            by_rule[f.rule_id] = f
        elif SEVERITY_SCORES.get(f.severity.value, 0) > SEVERITY_SCORES.get(
            existing.severity.value, 0
        ):
            log.debug(Logs.FINDING_DEDUPED, f.rule_id, f.severity.value)
            by_rule[f.rule_id] = f

    by_ave: dict[str, Finding] = {}
    no_ave: list[Finding] = []
    priority = {"pattern": 0, "yara": 1, "semgrep": 2, "llm": 3, "sandbox": 4}

    for f in by_rule.values():
        if not f.ave_id:
            no_ave.append(f)
            continue
        existing = by_ave.get(f.ave_id)
        if existing is None:
            by_ave[f.ave_id] = f
            continue

        f_has_line = f.line is not None
        ex_has_line = existing.line is not None

        if f_has_line and not ex_has_line:
            by_ave[f.ave_id] = f
        elif not f_has_line and ex_has_line:
            pass
        else:
            if priority.get(f.engine, 99) < priority.get(existing.engine, 99):
                by_ave[f.ave_id] = f
                log.debug(
                    "Cross-engine dedup: kept %s(%s) over %s for %s",
                    f.engine,
                    f.rule_id,
                    existing.engine,
                    f.ave_id,
                )

    result = list(by_ave.values()) + no_ave
    log.debug(Logs.DEDUP_COMPLETE, len(findings), len(result))
    return result


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
        stripped = _strip_code_fences(content)

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
        findings = _deduplicate(findings)
        findings.sort(
            key=lambda f: SEVERITY_SCORES.get(f.severity.value, 0),
            reverse=True,
        )

        toxic_flows = detect_toxic_flows(findings)

        # ── Step 7: FP-2 + FP-3 - Negation context + confidence scoring ───────
        lines = content.splitlines()
        active_findings: list[Finding] = []
        low_confidence: list[Finding] = []

        # FP-5: file-type profile determines confidence threshold
        file_profile = _classify_file(path)
        profile_threshold = _PROFILE_THRESHOLDS.get(file_profile, _CONFIDENCE_THRESHOLD)

        for f in findings:
            # FP-2: preceding-line negation context
            if f.line is not None and _has_negation_context(lines, f.line):
                f.suppressed = True
                f.suppression_reason = (
                    "negation_context - preceding line signals documentation example"
                )
                low_confidence.append(f)
                log.debug(
                    "FP-2: %s line %s suppressed by negation context",
                    f.rule_id,
                    f.line,
                )
                continue

            # FP-3: confidence scoring
            f.confidence = _score_confidence(f, lines, path, findings)
            threshold = _CONFIDENCE_THRESHOLD if file_profile == "skill" else profile_threshold
            if f.confidence < threshold:
                f.suppressed = True
                f.suppression_reason = (
                    f"low_confidence ({f.confidence:.2f} < {threshold:.2f}"
                    f" [{file_profile} profile])"
                )
                low_confidence.append(f)
                log.debug(
                    "FP-3: %s confidence %.2f below threshold %.2f",
                    f.rule_id,
                    f.confidence,
                    _CONFIDENCE_THRESHOLD,
                )
                continue

            active_findings.append(f)

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
