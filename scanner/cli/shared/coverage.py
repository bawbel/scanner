"""
Bawbel Scanner - what a directory scan covered (issue 182).

A directory scan reads only the files `collect_files` lists. A result with no findings says
nothing about the rest, so this walks the tree once and says what was left out:

    scanned   the files `collect_files` returned, which scan() read
    skipped   a file nobody read, counted by extension (executable-type files are named)
    ignored   a file the user or the scanner excluded: matched by .bawbelignore, the scanner's
              own configuration at the root, or inside .git, node_modules or a virtual
              environment. Counted, never listed

Ignoring changes what is counted here, not what is scanned: a text file inside node_modules is
still scanned today. Paths are relative to the scanned directory and never absolute.

The walk also collects the .pyc files outside excluded directories, so the header check can run
on them. Their contents are not read.
"""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from scanner.config import (
    COVERAGE_EXCLUDED_DIRS,
    COVERAGE_MAX_EXTENSION_KEYS,
    COVERAGE_MAX_NAMED_FILES,
    EXECUTABLE_EXTENSIONS,
    PYC_EXTENSION,
    SCANNER_CONFIG_FILES,
    VENV_MARKER_FILE,
)
from scanner.engines.bytecode_engine import run_bytecode_scan
from scanner.models import ScanResult
from scanner.suppression.bawbelignore import (
    _IGNORE_FILE,
    _load_bawbelignore,  # the same parser the suppression mechanism uses
    check_bawbelignore,
    matches_pattern,
)

NO_EXTENSION = "(none)"
OTHER_EXTENSIONS = "(other)"

REASON_EXTENSION = "extension_not_scanned"
REASON_NOT_RECURSIVE = "not_recursive"
IGNORED_BAWBELIGNORE = "bawbelignore"
IGNORED_SCANNER_CONFIG = "scanner_config"
IGNORED_DIRECTORY = "excluded_directory"

_IGNORE_SEARCH_LEVELS = 10  # how far up check_bawbelignore looks for a .bawbelignore


@dataclass
class CoverageReport:
    """The coverage object for the output, and the .pyc files whose header should be checked."""

    summary: dict
    pyc_paths: list[Path] = field(default_factory=list)


def extension_key(name: str) -> str:
    """The lower-cased last suffix with its dot, or "(none)". `.env` has no suffix."""
    return Path(name).suffix.lower() or NO_EXTENSION


class _IgnoreIndex:
    """.bawbelignore matching for many files, reading each ignore file once."""

    def __init__(self) -> None:
        self._nearest: dict[str, Optional[Path]] = {}
        self._patterns: dict[Path, list[str]] = {}

    def _find(self, directory: Path) -> Optional[Path]:
        key = str(directory)
        if key not in self._nearest:
            found: Optional[Path] = None
            current = directory
            for _ in range(_IGNORE_SEARCH_LEVELS):
                candidate = current / _IGNORE_FILE
                if candidate.exists():
                    found = candidate
                    break
                if current.parent == current:
                    break
                current = current.parent
            self._nearest[key] = found
        return self._nearest[key]

    def matches(self, path: Path) -> bool:
        ignore_file = self._find(path.parent)
        if ignore_file is None:
            return False
        if ignore_file not in self._patterns:
            try:
                self._patterns[ignore_file] = _load_bawbelignore(ignore_file)
            except OSError:
                self._patterns[ignore_file] = []
        try:
            rel = str(path.relative_to(ignore_file.parent))
        except ValueError:
            rel = str(path)
        rel = rel.replace("\\", "/")
        return any(matches_pattern(rel, pattern) for pattern in self._patterns[ignore_file])


def _ordered(counter: Counter) -> dict[str, int]:
    """Largest count first, then by name, folding the tail into "(other)" past the key cap."""
    items = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    kept, rest = items[:COVERAGE_MAX_EXTENSION_KEYS], items[COVERAGE_MAX_EXTENSION_KEYS:]
    ordered = dict(kept)
    if rest:
        ordered[OTHER_EXTENSIONS] = sum(count for _, count in rest)
    return ordered


def build_coverage(
    root: Path,
    recursive: bool,
    collected: Iterable[Path],
    no_ignore: bool = False,
) -> CoverageReport:
    """
    Walk `root` once and classify every file as scanned, skipped or ignored.

    Args:
        root: the directory that was scanned.
        recursive: whether subdirectories were entered. Files below the top level are skipped
            with the reason "not_recursive" when they were not.
        collected: the files `collect_files` returned.
        no_ignore: audit mode. .bawbelignore is not honoured, so nothing is ignored by it.
    """
    scanned = {str(path) for path in collected}
    root_str = str(root)
    skipped_ext: Counter = Counter()
    skipped_reason: Counter = Counter()
    ignored_reason: Counter = Counter()
    executables: list[str] = []
    pyc_paths: list[Path] = []
    index = _IgnoreIndex()
    excluded: dict[str, bool] = {root_str: False}  # the root is never excluded: it was named

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here_excluded = excluded.get(dirpath, False)
        for name in dirnames:
            child = os.path.join(dirpath, name)
            excluded[child] = (
                here_excluded
                or name in COVERAGE_EXCLUDED_DIRS
                or os.path.isfile(os.path.join(child, VENV_MARKER_FILE))
            )
        at_top = dirpath == root_str

        for name in filenames:
            full = os.path.join(dirpath, name)
            if full in scanned:
                continue
            if here_excluded:
                ignored_reason[IGNORED_DIRECTORY] += 1
                continue
            if at_top and name in SCANNER_CONFIG_FILES:
                ignored_reason[IGNORED_SCANNER_CONFIG] += 1
                continue
            if not no_ignore and index.matches(Path(full)):
                ignored_reason[IGNORED_BAWBELIGNORE] += 1
                continue

            key = extension_key(name)
            entered = recursive or at_top
            skipped_ext[key] += 1
            skipped_reason[REASON_EXTENSION if entered else REASON_NOT_RECURSIVE] += 1
            if key in EXECUTABLE_EXTENSIONS:
                executables.append(Path(os.path.relpath(full, root)).as_posix())
            if key == PYC_EXTENSION and entered and not os.path.islink(full):
                pyc_paths.append(Path(full))

    executables.sort()
    named = executables[:COVERAGE_MAX_NAMED_FILES]
    summary = {
        "directory_scan": True,
        "files_scanned": len(scanned),
        "files_skipped": sum(skipped_ext.values()),
        "skipped_by_extension": _ordered(skipped_ext),
        "skipped_by_reason": dict(sorted(skipped_reason.items())),
        "executable_files": named,
        "executable_files_omitted": len(executables) - len(named),
        "files_ignored": sum(ignored_reason.values()),
        "ignored_by_reason": dict(sorted(ignored_reason.items())),
        "bytecode_headers_checked": len(pyc_paths),
    }
    return CoverageReport(summary=summary, pyc_paths=sorted(pyc_paths))


def bytecode_results(pyc_paths: Iterable[Path]) -> list[ScanResult]:
    """One result per .pyc file that has a finding. The header is checked, the contents are not."""
    results: list[ScanResult] = []
    for path in pyc_paths:
        findings = run_bytecode_scan(str(path))
        if findings:
            results.append(
                ScanResult(file_path=str(path), component_type="unknown", findings=findings)
            )
    return results


def add_bytecode_findings(result: ScanResult, path: Path, no_ignore: bool = False) -> None:
    """For a .pyc named on the command line: add the header findings to the scan() result.

    A file matched by .bawbelignore gets them as suppressed findings, as scan() does for its own.
    """
    if result.error is not None:
        return
    findings = run_bytecode_scan(str(path))
    if not findings:
        return
    if not no_ignore and check_bawbelignore(path):
        for finding in findings:
            finding.suppressed = True
            finding.suppression_reason = ".bawbelignore - file path matched"
        result.suppressed_findings.extend(findings)
    else:
        result.findings.extend(findings)
