"""
Bawbel Scanner — Tool pinning engine.

Hashes the content of skill files and MCP server manifests and stores
the hashes in .bawbel-pins.json at the project root. On subsequent scans
with --check-pins, any file whose hash has changed is flagged as a
potential rug pull — the content changed after you pinned it.

    Bawbel stores in .bawbel-pins.json committed to the repo — shows in
    git diff, reviewable in PRs, shared with the whole team automatically.

Pin file format (.bawbel-pins.json):
    {
      "version": "1",
      "pinned_at": "2026-05-01T12:00:00",
      "pinned_by": "Chak Saray <saray@bawbel.io>",
      "pins": {
        "skills/search.md": {
          "sha256": "abc123...",
          "size_bytes": 1234,
          "pinned_at": "2026-05-01T12:00:00"
        }
      }
    }
"""

import hashlib
import json
import subprocess  # nosec B404  # noqa: S404
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from scanner.utils import get_logger

log = get_logger(__name__)

PINS_FILE = ".bawbel-pins.json"
PINS_VERSION = "1"
SCANNABLE_EXT = {".md", ".yaml", ".yml", ".json", ".txt"}


# ── Git identity ──────────────────────────────────────────────────────────────


def _git_identity() -> str:
    """Resolve the current git user for audit trail."""
    try:
        name = subprocess.run(  # nosec B607  # noqa: S603 S607
            ["git", "config", "user.name"],
            capture_output=True,
            text=True,
            timeout=3,
        ).stdout.strip()
        email = subprocess.run(  # nosec B607  # noqa: S603 S607
            ["git", "config", "user.email"],
            capture_output=True,
            text=True,
            timeout=3,
        ).stdout.strip()
        if name and email:
            return f"{name} <{email}>"
        if name:
            return name
    except (OSError, subprocess.SubprocessError) as e:
        log.debug("git identity lookup failed: error_type=%s", type(e).__name__)
    return "unknown"


# ── File hashing ──────────────────────────────────────────────────────────────


def hash_file(path: Path) -> str:
    """SHA-256 hash of a file's content. Returns hex digest."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Pins file I/O ─────────────────────────────────────────────────────────────


def load_pins(root: Path) -> dict:
    """Load existing pins from .bawbel-pins.json. Returns empty dict if not found."""
    pins_path = root / PINS_FILE
    if not pins_path.exists():
        return {}
    try:
        return json.loads(pins_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        log.warning("Could not read %s: %s", pins_path, e)
        return {}


def save_pins(root: Path, data: dict) -> None:
    """Write pins to .bawbel-pins.json."""
    pins_path = root / PINS_FILE
    pins_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    log.debug("Pins saved to %s", pins_path)


# ── Collect files ─────────────────────────────────────────────────────────────


def collect_pinnable_files(path: Path, recursive: bool = True) -> list[Path]:
    """Collect all scannable files under a path."""
    if path.is_file():
        return [path] if path.suffix.lower() in SCANNABLE_EXT else []

    files: list[Path] = []
    glob = path.rglob if recursive else path.glob
    for ext in SCANNABLE_EXT:
        files.extend(glob(f"*{ext}"))

    # Skip hidden dirs and common non-skill dirs
    skip_segments = {".git", ".venv", "node_modules", "__pycache__", ".cache"}
    files = [f for f in files if not any(part in skip_segments for part in f.parts)]
    return sorted(files)


# ── Public API ────────────────────────────────────────────────────────────────


class PinResult:
    """Result of a pin operation."""

    def __init__(self) -> None:
        self.pinned: list[str] = []  # newly pinned or updated
        self.unchanged: list[str] = []  # already pinned, same hash
        self.root: Path = Path(".")


class DriftResult:
    """Result of a drift check."""

    def __init__(self) -> None:
        self.changed: list[dict] = []  # hash changed — rug pull candidate
        self.new: list[str] = []  # not in pins — new file
        self.missing: list[str] = []  # in pins but file gone
        self.clean: list[str] = []  # hash matches pin


def pin(path: str, recursive: bool = True, update: bool = False) -> PinResult:
    """
    Hash all skill files under path and save to .bawbel-pins.json.

    Args:
        path:      File or directory to pin
        recursive: Scan subdirectories (default True)
        update:    If True, update existing pins. If False, skip already-pinned files.

    Returns:
        PinResult with lists of pinned/unchanged files
    """
    path_obj = Path(path).resolve()
    root = path_obj if path_obj.is_dir() else path_obj.parent
    files = collect_pinnable_files(path_obj, recursive)
    result = PinResult()
    result.root = root

    existing = load_pins(root)
    pins = existing.get("pins", {})
    now = datetime.now(timezone.utc).isoformat()
    identity = _git_identity()

    for f in files:
        rel = str(f.relative_to(root))
        digest = hash_file(f)

        if rel in pins and not update and pins[rel]["sha256"] == digest:
            result.unchanged.append(rel)
            continue

        pins[rel] = {
            "sha256": digest,
            "size_bytes": f.stat().st_size,
            "pinned_at": now,
        }
        result.pinned.append(rel)
        log.debug("Pinned %s → %s", rel, digest[:12])

    save_pins(
        root,
        {
            "version": PINS_VERSION,
            "pinned_at": now,
            "pinned_by": identity,
            "pins": pins,
        },
    )

    return result


def check_pins(path: str, recursive: bool = True) -> tuple[DriftResult, Optional[str]]:
    """
    Compare current file hashes against .bawbel-pins.json.

    Returns (DriftResult, error_string). error_string is None on success.

    Changed files are rug pull candidates — the content changed after pinning.
    """
    path_obj = Path(path).resolve()
    root = path_obj if path_obj.is_dir() else path_obj.parent
    result = DriftResult()

    existing = load_pins(root)
    if not existing:
        return result, (f"No {PINS_FILE} found at {root}. " f"Run 'bawbel pin {path}' first.")

    pins = existing.get("pins", {})
    files = collect_pinnable_files(path_obj, recursive)
    seen: set[str] = set()

    for f in files:
        rel = str(f.relative_to(root))
        seen.add(rel)

        if rel not in pins:
            result.new.append(rel)
            continue

        current_hash = hash_file(f)
        pinned_hash = pins[rel]["sha256"]

        if current_hash != pinned_hash:
            result.changed.append(
                {
                    "file": rel,
                    "pinned_hash": pinned_hash,
                    "current_hash": current_hash,
                    "pinned_at": pins[rel].get("pinned_at", "unknown"),
                }
            )
        else:
            result.clean.append(rel)

    # Files in pins that no longer exist
    for rel in pins:
        if rel not in seen:
            result.missing.append(rel)

    return result, None
