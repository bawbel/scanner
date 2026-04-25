"""
Bawbel Scanner — Stage 0: Magika file type verification engine.

Uses Google's Magika (~99% accuracy, ~5ms/file) to detect content-type
mismatches between a file's extension and its actual content.

Catches supply chain attacks that static text analysis cannot detect:
  - skill.md   that is actually PHP code      → CRITICAL
  - config.yaml that is actually a pickle      → CRITICAL
  - logo.png   that is actually an ELF binary  → CRITICAL
  - utils.py   that is actually a shell script → HIGH

Install:
    pip install "bawbel-scanner[magika]"

Runs BEFORE all other engines (Stage 0). Returns an empty list silently
if magika is not installed.

AVE-2026-00024: Supply chain — content type mismatch.
"""

from __future__ import annotations

import os
from pathlib import Path

from scanner.messages import Logs
from scanner.models import Finding, Severity
from scanner.utils import Timer, get_logger

log = get_logger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
MAGIKA_ENABLED = os.environ.get("BAWBEL_MAGIKA_ENABLED", "true").lower() != "false"

# Expected content types for common agentic skill file extensions
_EXPECTED_TYPES: dict[str, set[str]] = {
    ".md": {"markdown", "txt", "text"},
    ".yaml": {"yaml"},
    ".yml": {"yaml"},
    ".json": {"json"},
    ".toml": {"toml"},
    ".txt": {"txt", "text", "markdown"},
    ".py": {"python"},
    ".js": {"javascript"},
    ".ts": {"typescript"},
}

# Content types that are always dangerous inside a skill file
_DANGEROUS_TYPES: dict[str, tuple[str, str, float]] = {
    "elf": ("ELF binary disguised as skill file", "CRITICAL", 9.5),
    "pe32": ("Windows PE executable disguised as skill", "CRITICAL", 9.5),
    "pe64": ("Windows PE executable disguised as skill", "CRITICAL", 9.5),
    "python_pyc": ("Python bytecode disguised as skill file", "CRITICAL", 9.3),
    "php": ("PHP code disguised as skill file", "CRITICAL", 9.3),
    "jsp": ("JSP code disguised as skill file", "CRITICAL", 9.3),
    "shell": ("Shell script disguised as skill file", "HIGH", 8.8),
    "batch": ("Windows batch file disguised as skill", "HIGH", 8.8),
    "powershell": ("PowerShell script disguised as skill", "HIGH", 8.8),
    "pickle": ("Python pickle disguised as config file", "CRITICAL", 9.6),
}


def run_magika_scan(file_path: str) -> list[Finding]:
    """
    Stage 0 — file type verification via Google Magika.

    Checks for content-type mismatches (extension vs actual content)
    and known-dangerous content types in skill files.

    Args:
        file_path: Resolved absolute path to the component file.

    Returns:
        List of Findings — empty if no mismatch or magika not installed.
    """
    if not MAGIKA_ENABLED:
        return []

    try:
        from magika import Magika  # optional dependency  # noqa: PLC0415
    except ImportError:
        log.debug("Magika not installed — Stage 0 skipped (pip install magika)")
        return []

    findings: list[Finding] = []
    path = Path(file_path)

    log.debug(Logs.ENGINE_START, "magika", file_path)

    with Timer() as t:
        try:
            m = Magika()
            result = m.identify_path(path)
            content_type = result.output.label.lower()
            confidence = result.score

            log.debug(
                "Magika: %s → %s (confidence %.2f)",
                path.name,
                content_type,
                confidence,
            )

            # Only act on high-confidence results
            if confidence < 0.75:
                log.debug(
                    "Magika: confidence %.2f below 0.75 — skipping %s",
                    confidence,
                    path.name,
                )
                return []

            # Check 1: known-dangerous content type regardless of extension
            if content_type in _DANGEROUS_TYPES:
                desc, sev, cvss = _DANGEROUS_TYPES[content_type]
                findings.append(
                    Finding(
                        rule_id="bawbel-content-type-dangerous",
                        ave_id="AVE-2026-00024",
                        title=f"Supply chain: {desc}",
                        description=(
                            f"File {path.name!r} has extension {path.suffix!r} "
                            f"but Magika identifies its content as {content_type!r} "
                            f"(confidence {confidence:.0%}). "
                            f"This is a strong indicator of a supply chain attack."
                        ),
                        severity=Severity(sev),
                        cvss_ai=cvss,
                        line=None,
                        match=f"detected: {content_type}",
                        engine="magika",
                        owasp=["ASI07"],
                    )
                )
                log.debug(
                    "Magika: dangerous content type %s in %s",
                    content_type,
                    path.name,
                )
                return findings  # don't continue — file is dangerous

            # Check 2: extension-vs-content mismatch
            ext = path.suffix.lower()
            expected = _EXPECTED_TYPES.get(ext)
            if (
                expected
                and content_type not in expected
                and not _is_benign_mismatch(ext, content_type)
            ):
                findings.append(
                    Finding(
                        rule_id="bawbel-content-type-mismatch",
                        ave_id="AVE-2026-00024",
                        title=(
                            f"Supply chain: content type mismatch "
                            f"({path.suffix} file contains {content_type})"
                        ),
                        description=(
                            f"File {path.name!r} has extension {path.suffix!r} "
                            f"but Magika identifies its content as {content_type!r} "
                            f"(confidence {confidence:.0%}). "
                            f"Expected one of: {sorted(expected)}."
                        ),
                        severity=Severity("HIGH"),
                        cvss_ai=8.5,
                        line=None,
                        match=f"{path.suffix} → {content_type}",
                        engine="magika",
                        owasp=["ASI07"],
                    )
                )

        except Exception as e:  # nosec B110  # noqa: S110
            log.warning(
                "Magika engine error: file=%s error_type=%s",
                path.name,
                type(e).__name__,
            )

    log.debug(Logs.ENGINE_COMPLETE, "magika", len(findings), t.elapsed_ms)
    return findings


def _is_benign_mismatch(ext: str, content_type: str) -> bool:
    """
    Return True for mismatches that are not security-relevant.
    Avoids FPs on things like .md files identified as plain text.
    """
    # Markdown often identified as text/txt — not a mismatch worth flagging
    if ext in (".md", ".txt") and content_type in ("txt", "text", "markdown"):
        return True
    # Empty files
    if content_type in ("empty", "unknown"):
        return True
    # Generic text variants
    if content_type in ("txt", "text") and ext in (".md", ".yaml", ".yml", ".toml"):
        return True
    return False
