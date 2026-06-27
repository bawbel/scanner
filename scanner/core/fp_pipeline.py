"""
Bawbel Scanner - FP pipeline: file classification, negation context, confidence scoring.

FP-2: has_negation_context — suppress findings preceded by documentation signals.
FP-3: score_confidence     — score each finding 0.0-1.0, suppress below threshold.
FP-4: meta-analyzer        — see scanner/engines/meta_analyzer.py.
FP-5: classify_file        — derive scan profile from file name and path.

confidence_band() — maps a score to "high" | "medium" | "low" for human output.
"""

import os as _os
import re as _re
from pathlib import Path

from scanner.models import Finding

# ── FP-5: File classification ─────────────────────────────────────────────────

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
        "prompt.md",
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
    }
)

_PROFILE_THRESHOLDS: dict[str, float] = {
    "skill": 0.60,
    "mcp_manifest": 0.55,
    "documentation": 0.85,
    "unknown": 0.60,
}

_CONFIDENCE_THRESHOLD: float = float(_os.environ.get("BAWBEL_CONFIDENCE_THRESHOLD", "0.80"))


def classify_file(path: Path) -> str:
    """Classify a file into a scan profile: skill | mcp_manifest | documentation | unknown."""
    name = path.name.lower()
    parts = {p.lower() for p in path.parts}

    if name in _SKILL_NAMES:
        return "skill"
    if name.endswith((".skill.md", ".skill.yaml", ".skill.yml")):
        return "skill"

    if any(name.startswith(prefix) for prefix in ("mcp_", "mcp-", "mcp.")) and name.endswith(
        (".json", ".yaml", ".yml")
    ):
        return "mcp_manifest"
    if name in {"mcp_manifest.json", "mcp_manifest.yaml", "server.json"}:
        return "mcp_manifest"

    if parts & _DOC_PATH_SEGMENTS:
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


# ── FP-2: Negation context ────────────────────────────────────────────────────

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


def has_negation_context(lines: list[str], line_no: int) -> bool:
    """Return True if the line immediately preceding line_no contains a negation prefix."""
    if line_no is None or line_no < 2:
        return False
    preceding = lines[line_no - 2].lower().strip()
    return any(prefix in preceding for prefix in _NEGATION_PREFIXES)


# ── FP-3: Confidence scoring ──────────────────────────────────────────────────


def score_confidence(
    finding: Finding,
    lines: list[str],
    path: Path,
    all_findings: list[Finding],
) -> float:
    """Adjust a finding's confidence score based on file context.

    Seeds from finding.confidence (the AVE confidence_baseline) so that
    each rule's prior probability is respected before context adjustments
    are applied.
    """
    score = finding.confidence if finding.confidence > 0.0 else 1.0
    line_no = finding.line

    if line_no is not None:
        if has_negation_context(lines, line_no):
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

    if finding.aivss_score >= 9.0:
        score += 0.05

    return max(0.0, min(1.0, score))


# ── FP pipeline ───────────────────────────────────────────────────────────────


def confidence_band(confidence: float) -> str:
    """Map a confidence score to a human-readable band.

    Bands align with the meta-analyzer thresholds and the default profile thresholds:
      high   ≥ 0.80  trusted as-is, meta-analyzer skips
      medium  0.55–0.79  worth LLM review, visible in output
      low    < 0.55  typically suppressed by profile threshold
    """
    if confidence >= 0.80:
        return "high"
    if confidence >= 0.55:
        return "medium"
    return "low"


def run_fp_pipeline(
    findings: list[Finding],
    path: Path,
    content: str,
) -> list[Finding]:
    """
    Apply FP-2 (negation context) and FP-3 (confidence scoring) to findings.

    Returns active findings. Suppressed findings have suppressed=True set in place.
    """
    if not findings:
        return []

    lines = content.splitlines()
    file_profile = classify_file(path)
    threshold = _PROFILE_THRESHOLDS.get(file_profile, _CONFIDENCE_THRESHOLD)
    active: list[Finding] = []

    for f in findings:
        if f.line is not None and has_negation_context(lines, f.line):
            f.suppressed = True
            f.suppression_reason = "negation_context - preceding line signals documentation example"
            continue

        f.confidence = score_confidence(f, lines, path, findings)
        if f.confidence < threshold:
            f.suppressed = True
            f.suppression_reason = (
                f"low_confidence ({f.confidence:.2f} < {threshold:.2f}"
                f" [{file_profile} profile])"
            )
            continue

        active.append(f)

    return active