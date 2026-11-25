"""
Bawbel Scanner — CLI utility functions.

Small helpers shared across multiple command modules.
"""

from pathlib import Path

from scanner.config import SCANNED_EXTENSIONS, SCANNER_CONFIG_FILES


def collect_files(path_obj: Path, recursive: bool) -> list[Path]:
    """Collect all scannable files from a path.

    A directory is read for the file types in SCANNED_EXTENSIONS, matched on the end of the
    name without regard to case. The scanner's own configuration (SCANNER_CONFIG_FILES) is
    skipped at the root of a directory scan. The same names deeper in the tree, or a file named
    on the command line, are scanned.
    """
    if path_obj.is_dir():
        walk = path_obj.rglob if recursive else path_obj.glob
        files = [f for f in walk("*") if f.name.lower().endswith(SCANNED_EXTENSIONS)]
        files = [f for f in files if not (f.parent == path_obj and f.name in SCANNER_CONFIG_FILES)]
        return sorted(files)
    return [path_obj]


def parse_required_engines(value: str) -> list[str]:
    """Parse a comma-separated engine list. Raises ValueError naming any unknown engine."""
    from scanner.models import ENGINES

    names = [n.strip().lower() for n in value.split(",") if n.strip()]
    unknown = [n for n in names if n not in ENGINES]
    if unknown:
        raise ValueError(f"unknown engine {', '.join(unknown)} (choose from {', '.join(ENGINES)})")
    return list(dict.fromkeys(names))


def missing_required_engines(results: list, required: list[str]) -> list[tuple[str, str]]:
    """(engine, reason) for each required engine that did not run on at least one file."""
    missing: dict[str, str] = {}
    for result in results:
        ran = set(result.engines_run)
        reasons = {d.engine: d.reason for d in result.engines_degraded}
        for engine in required:
            if engine not in ran and engine not in missing:
                missing[engine] = reasons.get(engine, "scan_failed" if result.error else "unknown")
    return [(engine, missing[engine]) for engine in required if engine in missing]
