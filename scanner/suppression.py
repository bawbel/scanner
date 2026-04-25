"""
Bawbel Scanner — Suppression engine.

Three suppression mechanisms, applied in order after deduplication:

  1. Inline suppression — comment on the same line as the finding:
       fetch https://internal.company.com  <!-- bawbel-ignore -->
       fetch https://internal.company.com  <!-- bawbel-ignore: bawbel-external-fetch -->
       fetch https://internal.company.com  <!-- bawbel-ignore: AVE-2026-00001 -->
       # curl | bash  # bawbel-ignore: bawbel-shell-pipe
       IGNORE_ME = true  // bawbel-ignore

  2. Block suppression — suppress a section of lines:
       <!-- bawbel-ignore-start -->
       ... all findings in this block are suppressed ...
       <!-- bawbel-ignore-end -->
       Also supports: # bawbel-ignore-start / # bawbel-ignore-end

  3. .bawbelignore file — path patterns (gitignore syntax):
       tests/fixtures/**          # ignore all test fixtures
       docs/examples/bad.md       # known-bad example for documentation
       **/test_*.md               # all test skill files

Override all suppressions:
  BAWBEL_NO_IGNORE=true bawbel scan ./skill.md
  bawbel scan ./skill.md --no-ignore

Suppressed findings are NOT removed from ScanResult — they move to
ScanResult.suppressed_findings so CI/CD can audit them. This means
suppression cannot hide vulnerabilities from security audits.

Audit trail: every suppression is logged at INFO level.
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Optional

from scanner.utils import get_logger

log = get_logger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
NO_IGNORE = os.environ.get("BAWBEL_NO_IGNORE", "false").lower() == "true"

# Inline suppression patterns — matches comment-style markers
# Supports: <!-- bawbel-ignore -->, # bawbel-ignore, // bawbel-ignore
_INLINE_PATTERN = re.compile(
    r"(?:<!--|#|//)\s*bawbel-ignore"
    r"(?:\s*:\s*(.*?)\s*)?"  # optional: rule-id or AVE-ID list
    r"\s*(?:-->|$)",
    re.IGNORECASE,
)

# Block suppression markers
_BLOCK_START_PATTERN = re.compile(
    r"(?:<!--|#|//)\s*bawbel-ignore-start\s*(?:-->)?",
    re.IGNORECASE,
)
_BLOCK_END_PATTERN = re.compile(
    r"(?:<!--|#|//)\s*bawbel-ignore-end\s*(?:-->)?",
    re.IGNORECASE,
)

# .bawbelignore filename
_IGNORE_FILE = ".bawbelignore"


# ── Public dataclass for suppression result ───────────────────────────────────


class SuppressionResult:
    """
    Result of applying suppressions to a list of findings.

    active:     findings that are NOT suppressed — show in output
    suppressed: findings that ARE suppressed — hidden from output but kept for audit
    """

    __slots__ = ("active", "suppressed")

    def __init__(self, active, suppressed):
        self.active = active
        self.suppressed = suppressed


# ── Main entry point ──────────────────────────────────────────────────────────


def apply_suppressions(
    findings: list,
    file_path: str,
    content: str,
    no_ignore: bool = False,
) -> SuppressionResult:
    """
    Apply all three suppression mechanisms to a list of findings.

    Args:
        findings:  List of Finding objects from all engines.
        file_path: Resolved absolute path of the scanned file.
        content:   Raw file content string.
        no_ignore: If True, skip ALL suppressions (audit mode).

    Returns:
        SuppressionResult with .active and .suppressed lists.
    """
    if no_ignore or NO_IGNORE:
        if findings:
            log.info(
                "Suppression: --no-ignore active — all %d suppressions overridden",
                len(findings),
            )
        return SuppressionResult(active=list(findings), suppressed=[])

    path = Path(file_path)
    lines = content.splitlines()

    # Build suppression index from file content
    inline_suppressions = _parse_inline(lines)
    block_lines = _parse_blocks(lines)
    path_ignored = _check_bawbelignore(path)

    active: list = []
    suppressed: list = []

    for finding in findings:
        reason = _is_suppressed(
            finding,
            path_ignored,
            inline_suppressions,
            block_lines,
        )
        if reason:
            log.info(
                "Suppression: %s (line %s) suppressed — %s",
                finding.rule_id,
                finding.line or "?",
                reason,
            )
            # Mark the finding with suppression metadata
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


# ── Mechanism 1: Inline ───────────────────────────────────────────────────────


def _parse_inline(lines: list[str]) -> dict[int, Optional[list[str]]]:
    """
    Parse inline bawbel-ignore comments.

    Returns a dict mapping 1-indexed line number →
      None  = suppress all rules on this line
      list  = suppress only these rule_ids / ave_ids
    """
    result: dict[int, Optional[list[str]]] = {}

    for i, line in enumerate(lines, start=1):
        m = _INLINE_PATTERN.search(line)
        if m:
            raw_ids = m.group(1)
            if raw_ids:
                ids = [s.strip() for s in re.split(r"[,\s]+", raw_ids) if s.strip()]
                result[i] = ids
            else:
                result[i] = None  # suppress all

    return result


# ── Mechanism 2: Block ────────────────────────────────────────────────────────


def _parse_blocks(lines: list[str]) -> set[int]:
    """
    Parse bawbel-ignore-start / bawbel-ignore-end blocks.

    Returns a set of 1-indexed line numbers that are inside a suppression block.
    Unclosed blocks suppress to end of file (with a warning).
    """
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
            "Suppression: unclosed bawbel-ignore-start at line %d — " "suppressing to end of file",
            block_start,
        )

    return suppressed_lines


# ── Mechanism 3: .bawbelignore ────────────────────────────────────────────────


def _check_bawbelignore(path: Path) -> bool:
    """
    Check if the file matches any pattern in .bawbelignore.

    Searches for .bawbelignore starting from the file's directory up to
    the filesystem root (same as .gitignore discovery).

    Returns True if the file should be fully ignored.
    """
    # Search from file directory upward
    search_dir = path.parent
    ignore_file: Optional[Path] = None

    for _ in range(10):  # max 10 levels up
        candidate = search_dir / _IGNORE_FILE
        if candidate.exists():
            ignore_file = candidate
            break
        parent = search_dir.parent
        if parent == search_dir:
            break
        search_dir = parent

    if not ignore_file:
        return False

    try:
        patterns = _load_bawbelignore(ignore_file)
    except OSError as e:
        log.warning("Suppression: could not read %s — %s", ignore_file, e)
        return False

    # Make path relative to .bawbelignore location for matching
    try:
        rel_path = str(path.relative_to(ignore_file.parent))
    except ValueError:
        rel_path = str(path)

    # Normalise to forward slashes for consistent matching
    rel_path = rel_path.replace("\\", "/")

    for pattern in patterns:
        if _matches_pattern(rel_path, pattern):
            log.info(
                "Suppression: %s matches .bawbelignore pattern %r",
                rel_path,
                pattern,
            )
            return True

    return False


def _load_bawbelignore(path: Path) -> list[str]:
    """
    Load and parse a .bawbelignore file.

    Returns list of active patterns (strips comments and blank lines).
    """
    patterns: list[str] = []

    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()
            # Skip blank lines and comments
            if not stripped or stripped.startswith("#"):
                continue
            # Support inline comments
            if " #" in stripped:
                stripped = stripped[: stripped.index(" #")].strip()
            if stripped:
                patterns.append(stripped)

    return patterns


def _matches_pattern(file_path: str, pattern: str) -> bool:
    """
    Match a file path against a gitignore-style pattern.

    Supports:
      - Exact matches:        tests/fixtures/bad.md
      - Glob wildcards:       *.md, tests/**
      - Directory patterns:   tests/fixtures/
      - Negation:             !important.md  (TODO: future)
    """
    # Strip leading /
    if pattern.startswith("/"):
        pattern = pattern[1:]

    # Directory pattern (trailing /)
    if pattern.endswith("/"):
        return file_path.startswith(pattern) or ("/" + pattern) in file_path

    # Double star — match any path segment
    if "**" in pattern:
        # Convert ** to fnmatch-friendly form
        regex = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
        return bool(re.match(regex + "$", file_path))

    # Simple glob
    if fnmatch.fnmatch(file_path, pattern):
        return True

    # Match basename only (pattern with no slash)
    if "/" not in pattern:
        basename = file_path.split("/")[-1]
        if fnmatch.fnmatch(basename, pattern):
            return True

    # Prefix match (pattern is a directory prefix)
    if file_path.startswith(pattern + "/"):
        return True

    return False


# ── Decision logic ────────────────────────────────────────────────────────────


def _is_suppressed(
    finding,
    path_ignored: bool,
    inline_suppressions: dict[int, Optional[list[str]]],
    block_lines: set[int],
) -> Optional[str]:
    """
    Check if a finding should be suppressed.

    Returns the suppression reason string, or None if not suppressed.
    """
    # .bawbelignore — whole file suppressed
    if path_ignored:
        return ".bawbelignore — file path matched"

    line = finding.line

    # Block suppression — line is inside a bawbel-ignore-start/end block
    if line is not None and line in block_lines:
        return "block suppression (bawbel-ignore-start/end)"

    # Inline suppression — line has a bawbel-ignore comment
    if line is not None and line in inline_suppressions:
        ids = inline_suppressions[line]
        if ids is None:
            # Suppress all rules on this line
            return "inline suppression (bawbel-ignore)"
        # Check if this specific rule or AVE ID is listed
        rule_lower = finding.rule_id.lower()
        ave_lower = (finding.ave_id or "").lower()
        for id_ in ids:
            if id_.lower() in (rule_lower, ave_lower):
                return f"inline suppression (bawbel-ignore: {id_})"

    return None


# ── .bawbelignore template ────────────────────────────────────────────────────

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
# Inline suppression (in the file itself):
#   content here  <!-- bawbel-ignore -->
#   content here  <!-- bawbel-ignore: bawbel-external-fetch -->
#   content here  <!-- bawbel-ignore: AVE-2026-00001, AVE-2026-00007 -->
#
# Block suppression (in the file itself):
#   <!-- bawbel-ignore-start -->
#   ... suppressed section ...
#   <!-- bawbel-ignore-end -->
#
# Override all suppressions (audit mode):
#   bawbel scan ./skills/ --no-ignore

# Add your patterns below:
tests/fixtures/malicious/**
"""
