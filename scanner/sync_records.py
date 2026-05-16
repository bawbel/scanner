"""
Sync AVE records from ave repository.

Run this script at deploy time to keep piranha-api in sync with the canonical
AVE records in github.com/bawbel/ave.

Usage:
    python sync_records.py

Environment:
    AVE_REPO_URL  - override the source repo (default: bawbel/ave raw URL)
    RECORDS_DIR   - override target directory (default: ./records)
    GITHUB_TOKEN  - optional, increases rate limit from 60 to 5000 req/hr
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

AVE_REPO_API = os.environ.get(
    "AVE_REPO_URL", "https://api.github.com/repos/bawbel/ave/contents/records"
)
RECORDS_DIR = Path(os.environ.get("RECORDS_DIR", "./records"))
RAW_BASE = "https://raw.githubusercontent.com/bawbel/ave/main/records"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")


def _headers() -> dict:
    h = {"User-Agent": "piranha-api/sync"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def fetch_json(url: str) -> dict | list:
    req = urllib.request.Request(url, headers=_headers())
    with urllib.request.urlopen(req, timeout=15) as r:  # nosec B310  # noqa: S310
        return json.loads(r.read())


def sync() -> int:
    """Sync records from GitHub. Returns count of records synced."""
    RECORDS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[sync] Fetching record list from {AVE_REPO_API} ...")
    try:
        contents = fetch_json(AVE_REPO_API)
    except Exception as e:
        print(f"[sync] ERROR fetching record list: {e}", file=sys.stderr)
        print(f"[sync] Falling back to bundled records in {RECORDS_DIR}", file=sys.stderr)
        return 0

    ave_files = sorted(
        item["name"]
        for item in contents
        if item["name"].startswith("AVE-") and item["name"].endswith(".json")
    )

    if not ave_files:
        print("[sync] WARNING: no AVE JSON files found in repo", file=sys.stderr)
        return 0

    print(f"[sync] Found {len(ave_files)} records in repo")

    synced = 0
    skipped = 0
    errors = 0

    for filename in ave_files:
        url = f"{RAW_BASE}/{filename}"
        dest = RECORDS_DIR / filename
        try:
            record = fetch_json(url)
            # Validate minimal required fields before writing
            if not record.get("ave_id"):
                raise ValueError("missing ave_id")
            with open(dest, "w") as f:
                json.dump(record, f, indent=2)
            attack_class = record.get("attack_class", "")[:40]
            score = record.get("aivss_score")
            print(f"[sync]   ✓ {filename}  cvss={score}  {attack_class}")
            synced += 1
        except Exception as e:
            errors += 1
            print(f"[sync]   ✗ {filename}: {e}", file=sys.stderr)
            # If destination already exists from a previous sync, keep it
            if dest.exists():
                skipped += 1
                print(f"[sync]   → keeping existing {filename}", file=sys.stderr)

    # Remove local records that no longer exist in the repo
    for local_file in RECORDS_DIR.glob("AVE-*.json"):
        if local_file.name not in ave_files:
            local_file.unlink()
            print(f"[sync]   - removed stale {local_file.name}")

    print(f"[sync] Done: {synced} synced, {errors} errors ({skipped} kept from cache)")
    return synced


if __name__ == "__main__":
    count = sync()
    sys.exit(0 if count > 0 else 1)
