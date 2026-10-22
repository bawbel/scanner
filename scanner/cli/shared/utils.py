"""
Bawbel Scanner — CLI utility functions.

Small helpers shared across multiple command modules.
"""

from pathlib import Path

from scanner.config import SCANNER_CONFIG_FILES


def collect_files(path_obj: Path, recursive: bool) -> list[Path]:
    """Collect all scannable files from a path.

    The scanner's own configuration (SCANNER_CONFIG_FILES) is skipped at the root of a
    directory scan. The same names deeper in the tree, or a file named on the command line,
    are scanned.
    """
    extensions = [".md", ".json", ".yaml", ".yml", ".txt"]
    if path_obj.is_dir():
        files: list[Path] = []
        for ext in extensions:
            glob = path_obj.rglob if recursive else path_obj.glob
            files.extend(glob(f"*{ext}"))
        files = [f for f in files if not (f.parent == path_obj and f.name in SCANNER_CONFIG_FILES)]
        return sorted(files)
    return [path_obj]
