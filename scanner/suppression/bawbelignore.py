"""
Bawbel Scanner — BawbelIgnore suppression mechanism.

Glob-pattern file suppression via .bawbelignore, using gitignore-style syntax.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Optional

from scanner.utils import get_logger

log = get_logger(__name__)

_IGNORE_FILE = ".bawbelignore"


def check_bawbelignore(path: Path) -> bool:
    """Return True if path matches any pattern in the nearest .bawbelignore file."""
    search_dir = path.parent
    ignore_file: Optional[Path] = None

    for _ in range(10):
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

    try:
        rel_path = str(path.relative_to(ignore_file.parent))
    except ValueError:
        rel_path = str(path)

    rel_path = rel_path.replace("\\", "/")

    for pattern in patterns:
        if matches_pattern(rel_path, pattern):
            log.info(
                "Suppression: %s matches .bawbelignore pattern %r",
                rel_path,
                pattern,
            )
            return True

    return False


def _load_bawbelignore(path: Path) -> list[str]:
    """Load and parse a .bawbelignore file, stripping comments and blank lines."""
    patterns: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if " #" in stripped:
                stripped = stripped[: stripped.index(" #")].strip()
            if stripped:
                patterns.append(stripped)
    return patterns


def matches_pattern(file_path: str, pattern: str) -> bool:
    """Match a file path against a gitignore-style glob pattern."""
    if pattern.startswith("/"):
        pattern = pattern[1:]

    if pattern.endswith("/"):
        return file_path.startswith(pattern) or ("/" + pattern) in file_path

    if "**" in pattern:
        regex = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
        return bool(re.match(regex + "$", file_path))

    if fnmatch.fnmatch(file_path, pattern):
        return True

    if "/" not in pattern:
        basename = file_path.split("/")[-1]
        if fnmatch.fnmatch(basename, pattern):
            return True

    if file_path.startswith(pattern + "/"):
        return True

    return False
