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
from scanner.engines import run_pattern_scan, run_semgrep_scan, run_yara_scan, run_llm_scan
from scanner.engines.magika_engine import run_magika_scan
from scanner.engines.meta_analyzer import run_meta_analysis
from scanner.engines.sandbox_engine import (
    run_sandbox_scan,
    SANDBOX_ENABLED,
    is_docker_available,
)

# Infrastructure
from scanner.messages import Logs
from scanner.suppression import apply_suppressions, NO_IGNORE
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
    in the original. This keeps Finding.line accurate — the line number a
    pattern engine reports is still correct relative to the original file.

    The fence markers themselves (``` and ```) are kept — only the content
    between them is blanked. This means a finding on the fence-open line is
    still possible (the marker line is not blanked), but content lines inside
    the fence are not scanned.

    Why preserve line numbers:
        If we deleted fenced lines instead of blanking them, every finding
        below a fence would have an off-by-N line number.

    Why sandbox gets the original content:
        The sandbox runs the full file. A malicious payload hidden inside a
        code fence is still caught behaviourally at Stage 3.

    Args:
        content: Raw file content string.

    Returns:
        Content string with fenced block interiors replaced by blank lines.
    """

    def _blank_interior(m: _re.Match) -> str:
        interior = m.group(1)
        # Count how many newlines are in the interior and replace with blanks
        blank_lines = "\n" * interior.count("\n")
        # Reconstruct: opening fence line + blank interior + closing fence
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

# Per-process warning flags — emit each warning only once across all files
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
# Case-insensitive, partial match (e.g. "bad:" matches "# Bad:").

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
        "❌",
        "✗",
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

    Args:
        lines:   All lines of the file (0-indexed list).
        line_no: 1-indexed line number of the finding.

    Returns:
        True if preceding line signals this is a documentation example.
    """
    if line_no is None or line_no < 2:
        return False
    preceding = lines[line_no - 2].lower().strip()
    return any(prefix in preceding for prefix in _NEGATION_PREFIXES)


# ── FP-3: Confidence scoring ──────────────────────────────────────────────────
# Default threshold — findings below this go to low_confidence_findings.
_CONFIDENCE_THRESHOLD: float = float(_os.environ.get("BAWBEL_CONFIDENCE_THRESHOLD", "0.80"))

# File patterns that indicate a skill / high-trust component
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

# Path segments that indicate documentation / low-trust context
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
    Compute a confidence score (0.0–1.0) for a finding.

    Score represents the probability that this is a true positive.
    Starts at 1.0 and adjusts based on context signals.

    Signals:
      Penalties (reduce confidence — likely FP):
        -0.4  preceded by negation context
        -0.3  match is inside a markdown table (line starts with |)
        -0.4  match is in a heading (line starts with # word)
        -0.3  file path contains a docs/examples/tests segment
        -0.2  match text is very short (< 6 chars — too little signal)

      Boosts (increase confidence — likely TP):
        +0.2  match is in the first 30 lines (instructions are usually at top)
        +0.3  two or more engines agree on the same ave_id
        +0.2  file is named SKILL.md or system_prompt.*
        +0.1  CVSS-AI >= 9.0 (critical patterns — trust the high-severity signal)

    Args:
        finding:      The finding to score.
        lines:        All lines of the file (0-indexed).
        path:         Resolved file path.
        all_findings: All findings (for multi-engine agreement check).

    Returns:
        Float in range [0.0, 1.0].
    """
    score = 1.0
    line_no = finding.line

    # ── Penalties ─────────────────────────────────────────────────────────────
    if line_no is not None:
        # Negation context — preceding line signals documentation example
        if _has_negation_context(lines, line_no):
            score -= 0.4

        # Markdown table — match is inside a table row (starts with |)
        if 1 <= line_no <= len(lines):
            current_line = lines[line_no - 1].lstrip()
            if current_line.startswith("|"):
                score -= 0.45
            # Heading — match is inside a # heading
            if _re.match(r"#{1,6}\s+\w", current_line):
                score -= 0.55

    # Documentation path segment — computed before boosts so boosts can be conditional
    path_parts = {p.lower() for p in path.parts}
    in_docs_path = bool(path_parts & _DOC_PATH_SEGMENTS)
    if in_docs_path:
        score -= 0.35

    # Very short match — too little context to be meaningful
    if finding.match and len(finding.match.strip()) < 6:
        score -= 0.2

    # ── Boosts ────────────────────────────────────────────────────────────────
    # Boosts do NOT apply when a structural FP indicator is present —
    # being in line 1 of a docs/ file does not make the finding more real.
    if line_no is not None and line_no <= 30 and not in_docs_path:
        score += 0.15

    # Multi-engine agreement — same ave_id detected by 2+ engines
    if finding.ave_id:
        agreeing = sum(
            1 for f in all_findings if f.ave_id == finding.ave_id and f.engine != finding.engine
        )
        if agreeing >= 1:
            score += 0.25

    # Skill file name — high-trust context
    if path.name.lower() in _SKILL_NAMES:
        score += 0.15

    # Critical severity — small signal boost (not enough to override structural FP)
    if finding.cvss_ai >= 9.0:
        score += 0.05

    return max(0.0, min(1.0, score))


# ── FP-5: File-type scan profiles ────────────────────────────────────────────
# Maps file classification → confidence threshold override.
# Documentation files require a higher bar to surface a finding.

_PROFILE_THRESHOLDS: dict[str, float] = {
    "skill": 0.60,  # skill files — scan hard
    "mcp_manifest": 0.55,  # MCP manifests — scan hardest (high-risk surface)
    "documentation": 0.85,  # docs — only surface very high-confidence findings
    "unknown": 0.80,  # default threshold
}


def _classify_file(path: Path) -> str:
    """
    Classify a file into a scan profile based on name and path.

    Returns one of: "skill" | "mcp_manifest" | "documentation" | "unknown"
    """
    name = path.name.lower()
    parts = {p.lower() for p in path.parts}

    # Explicit skill indicators
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

    # MCP manifest indicators
    if any(name.startswith(prefix) for prefix in ("mcp_", "mcp-", "mcp.")) and name.endswith(
        (".json", ".yaml", ".yml")
    ):
        return "mcp_manifest"
    if name in {"mcp_manifest.json", "mcp_manifest.yaml", "server.json"}:
        return "mcp_manifest"

    # Documentation indicators — path segments
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

    # Documentation indicators — filename
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
    Deduplicate findings across engines.

    Two passes:
    1. Keep the highest-severity finding per rule_id (same engine, same rule).
    2. Keep the highest-severity finding per (ave_id, line) — removes cross-engine
       duplicates where pattern + YARA + Semgrep all detect the same AVE ID on
       the same line. The finding with the richer match/description wins.

    Stable contract: do not change without a minor version bump.
    """
    # Pass 1 — deduplicate by rule_id
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

    # Pass 2 — deduplicate by ave_id across engines
    # Groups all findings with the same ave_id, keeps the best one:
    # - prefer the finding that has a line number (more specific)
    # - among those with lines, prefer pattern > yara > semgrep > llm > sandbox
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

        # Prefer the finding with a line number
        f_has_line = f.line is not None
        ex_has_line = existing.line is not None

        if f_has_line and not ex_has_line:
            by_ave[f.ave_id] = f  # f is more specific
        elif not f_has_line and ex_has_line:
            pass  # keep existing — it has a line
        else:
            # Both have (or both lack) line numbers — prefer by engine priority
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
      5. Applies suppression (inline, block, .bawbelignore)
      6. Returns a complete ScanResult

    Never raises — all errors are captured in ScanResult.error.

    Args:
        file_path: Path to the component file (any string — will be validated)
        no_ignore: If True, skip all suppressions — audit mode

    Returns:
        ScanResult with findings, suppressed_findings, risk_score, max_severity, scan_time_ms
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
        # Strip code fence content before static analysis (Priority 1 FP reduction).
        # Fenced content is replaced with blank lines — line numbers stay correct.
        # Original content is preserved for:
        #   - Sandbox (Stage 3) — must see full file for behavioural analysis
        #   - Suppression — inline bawbel-ignore comments may be inside fences
        stripped = _strip_code_fences(content)

        findings: list[Finding] = []

        # ── Stage 0: Magika file type verification ────────────────────────────
        # Runs before all other engines. Catches supply chain attacks where
        # a file's content type doesn't match its extension.
        # Skips silently if magika is not installed.
        magika_findings = run_magika_scan(str(path))
        findings.extend(magika_findings)
        if magika_findings:
            # If Magika flags a dangerous content type, skip text analysis —
            # the file is not what it claims to be and text patterns are
            # meaningless. Still run sandbox for behavioral analysis.
            dangerous = any(f.rule_id == "bawbel-content-type-dangerous" for f in magika_findings)
            if dangerous:
                log.warning(
                    "Magika: dangerous content type in %s — " "skipping text analysis engines",
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

        # ── Stage 3: Behavioral sandbox ──────────────────────────────────────
        if SANDBOX_ENABLED:
            if is_docker_available():
                sandbox_findings = run_sandbox_scan(str(path), stripped_content=stripped)
                findings.extend(sandbox_findings)
                if not sandbox_findings:
                    global _warned_sandbox_no_image
                    if not _warned_sandbox_no_image:
                        _warned_sandbox_no_image = True
                        log.warning(
                            "Sandbox engine: no findings returned — "
                            "ensure bawbel/sandbox:latest image is built "
                            "or set BAWBEL_SANDBOX_IMAGE=local to build locally. "
                            "See docs/guides/engines.md for setup."
                        )
            else:
                global _warned_sandbox_no_docker
                if not _warned_sandbox_no_docker:
                    _warned_sandbox_no_docker = True
                    log.warning("Sandbox engine: Docker not running — Stage 3 skipped")

        # ── Step 6: Deduplicate and sort ──────────────────────────────────────
        findings = _deduplicate(findings)
        findings.sort(
            key=lambda f: SEVERITY_SCORES.get(f.severity.value, 0),
            reverse=True,
        )

        # ── Step 7: FP-2 + FP-3 — negation context + confidence scoring ───────
        lines = content.splitlines()
        active_findings: list[Finding] = []
        low_confidence: list[Finding] = []

        # FP-5: file-type profile threshold override
        file_profile = _classify_file(path)
        profile_threshold = _PROFILE_THRESHOLDS.get(file_profile, _CONFIDENCE_THRESHOLD)

        for f in findings:
            # FP-2: preceding-line negation context
            if f.line is not None and _has_negation_context(lines, f.line):
                f.suppressed = True
                f.suppression_reason = (
                    "negation_context — preceding line signals documentation example"
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

        # ── Step 8: Meta-analysis FP filter ──────────────────────────────────
        # Runs on medium-confidence active findings — one LLM call per file.
        # Skips silently if LLM not configured.
        magika_label = next(
            (f.match.replace("detected: ", "") for f in findings if f.engine == "magika"), "unknown"
        )
        active_findings = run_meta_analysis(
            findings=active_findings,
            content=content,
            file_path=str(path),
            magika_label=magika_label,
        )
        # Move meta-analyzer FP verdicts to low_confidence
        meta_fp = [f for f in active_findings if f.suppressed]
        active_findings = [f for f in active_findings if not f.suppressed]
        low_confidence.extend(meta_fp)

        # ── Step 9: Apply suppressions ────────────────────────────────────────
        sup = apply_suppressions(
            findings=active_findings,
            file_path=str(path),
            content=content,
            no_ignore=no_ignore or NO_IGNORE,
        )

    result = ScanResult(
        file_path=str(path),
        component_type=component_type,
        findings=sup.active,
        suppressed_findings=sup.suppressed + low_confidence,
        scan_time_ms=t.elapsed_ms,
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
            "Suppression: %d finding(s) suppressed in %s — run with --no-ignore to see all",
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
