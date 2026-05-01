"""
Bawbel Scanner — CLI utility functions.

Small helpers shared across multiple command modules.
"""

from pathlib import Path


def collect_files(path_obj: Path, recursive: bool) -> list[Path]:
    """Collect all scannable files from a path."""
    extensions = [".md", ".json", ".yaml", ".yml", ".txt"]
    if path_obj.is_dir():
        files: list[Path] = []
        for ext in extensions:
            glob = path_obj.rglob if recursive else path_obj.glob
            files.extend(glob(f"*{ext}"))
        return sorted(files)
    return [path_obj]
