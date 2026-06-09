"""
Bawbel Scanner — InlineSuppression and BlockSuppression mechanisms.

Mechanisms:
  1. Inline — <!-- bawbel-ignore --> comment on the finding's line.
  2. Block  — <!-- bawbel-ignore-start/end --> wrapping a section.
  3. BawbelIgnore — .bawbelignore path glob (delegated to bawbelignore.py).

Suppressed findings are NOT removed — they move to ScanResult.suppressed_findings
so CI/CD can audit them.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from scanner.suppression.bawbelignore import check_bawbelignore
from scanner.utils import get_logger

log = get_logger(__name__)

NO_IGNORE: bool = os.environ.get("BAWBEL_NO_IGNORE", "false").lower() == "true"

_INLINE_PATTERN = re.compile(
    r"(?:<!--|#|//)\s*bawbel-ignore" r"(?:\s*:\s*(.*?)\s*)?" r"\s*(?:-->|$)",
    re.IGNORECASE,
)
_BLOCK_START_PATTERN = re.compile(
    r"(?:<!--|#|//)\s*bawbel-ignore-start\s*(?:-->)?",
    re.IGNORECASE,
)
_BLOCK_END_PATTERN = re.compile(
    r"(?:<!--|#|//)\s*bawbel-ignore-end\s*(?:-->)?",
    re.IGNORECASE,
)


class SuppressionResult:
    """Result of applying suppressions: active findings and suppressed findings."""

    __slots__ = ("active", "suppressed")

    def __init__(self, active: list, suppressed: list) -> None:
        self.active = active
        self.suppressed = suppressed


def apply_suppressions(
    findings: list,
    file_path: str,
    content: str,
    no_ignore: bool = False,
) -> SuppressionResult:
    """Apply inline, block, and bawbelignore suppression to findings."""
    if no_ignore or NO_IGNORE:
        if findings:
            log.info(
                "Suppression: --no-ignore active — all %d suppressions overridden",
                len(findings),
            )
        return SuppressionResult(active=list(findings), suppressed=[])

    path = Path(file_path)
    lines = content.splitlines()

    inline_suppressions = _parse_inline(lines)
    block_lines = _parse_blocks(lines)
    path_ignored = check_bawbelignore(path)

    active: list = []
    suppressed: list = []

    for finding in findings:
        reason = _is_suppressed(finding, path_ignored, inline_suppressions, block_lines)
        if reason:
            log.info(
                "Suppression: %s (line %s) suppressed — %s",
                finding.rule_id,
                finding.line or "?",
                reason,
            )
            finding.suppressed = True
            finding.suppression_reason = reason
            suppressed.append(finding)
        else:
            finding.suppressed = False
            finding.suppression_reason = None
            active.append(finding)

    if suppressed:
        log.info(
            "Suppression: %d finding(s) suppressed, %d active",
            len(suppressed),
            len(active),
        )

    return SuppressionResult(active=active, suppressed=suppressed)


def _parse_inline(lines: list[str]) -> dict[int, Optional[list[str]]]:
    """Parse inline bawbel-ignore comments, returning line→rule_ids mapping."""
    result: dict[int, Optional[list[str]]] = {}
    for i, line in enumerate(lines, start=1):
        m = _INLINE_PATTERN.search(line)
        if m:
            raw_ids = m.group(1)
            if raw_ids:
                ids = [s.strip() for s in re.split(r"[,\s]+", raw_ids) if s.strip()]
                result[i] = ids
            else:
                result[i] = None
    return result


def _parse_blocks(lines: list[str]) -> set[int]:
    """Parse bawbel-ignore-start/end blocks, returning suppressed line numbers."""
    suppressed_lines: set[int] = set()
    in_block = False
    block_start = 0

    for i, line in enumerate(lines, start=1):
        if _BLOCK_START_PATTERN.search(line):
            if in_block:
                log.warning("Suppression: nested bawbel-ignore-start at line %d ignored", i)
            else:
                in_block = True
                block_start = i
        elif _BLOCK_END_PATTERN.search(line):
            if in_block:
                in_block = False
            else:
                log.warning("Suppression: bawbel-ignore-end without matching start at line %d", i)
        elif in_block:
            suppressed_lines.add(i)

    if in_block:
        log.warning(
            "Suppression: unclosed bawbel-ignore-start at line %d — suppressing to end of file",
            block_start,
        )

    return suppressed_lines


def _is_suppressed(
    finding,
    path_ignored: bool,
    inline_suppressions: dict[int, Optional[list[str]]],
    block_lines: set[int],
) -> Optional[str]:
    """Return suppression reason string, or None if not suppressed."""
    if path_ignored:
        return ".bawbelignore — file path matched"

    line = finding.line

    if line is not None and line in block_lines:
        return "block suppression (bawbel-ignore-start/end)"

    if line is not None and line in inline_suppressions:
        ids = inline_suppressions[line]
        if ids is None:
            return "inline suppression (bawbel-ignore)"
        rule_lower = finding.rule_id.lower()
        ave_lower = (finding.ave_id or "").lower()
        for id_ in ids:
            if id_.lower() in (rule_lower, ave_lower):
                return f"inline suppression (bawbel-ignore: {id_})"

    return None


BAWBELIGNORE_TEMPLATE = """\
# .bawbelignore — Bawbel Scanner suppression file
#
# Suppress findings for specific files or path patterns.
# Syntax is similar to .gitignore.
#
# Examples:
#   tests/fixtures/**          # all files under tests/fixtures/
#   docs/examples/bad.md       # a specific known-bad example file
#   **/test_*.md               # any file starting with test_
#   examples/                  # all files in any examples/ directory
#
# Override all suppressions (audit mode):
#   bawbel scan ./skills/ --no-ignore

# Add your patterns below:
tests/fixtures/malicious/**
"""
