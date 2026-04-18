#!/usr/bin/env python3
"""
Bawbel — Progress Log Updater

Stamps BAWBEL_PROGRESS_LOG.md with the current UTC date and time.

Usage:
    python scripts/update_log.py
    python scripts/update_log.py --message "Pushed bawbel-scanner v0.1.0"

The script:
  1. Updates the "Last modified" timestamp at the bottom of the log
  2. Optionally appends a one-line activity note under today's date heading
  3. Prints a confirmation so you know it ran
"""

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = Path(__file__).parent.parent / "BAWBEL_PROGRESS_LOG.md"


def now_utc() -> str:
    """Return current UTC time as a formatted string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def today_date() -> str:
    """Return today's date as YYYY-MM-DD."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def today_human() -> str:
    """Return today's date as 'April 17, 2026'."""
    return datetime.now(timezone.utc).strftime("%B %d, %Y").replace(" 0", " ")


def update_timestamp(src: str) -> str:
    """Update or add the Last modified timestamp."""
    timestamp = f"Last modified: {now_utc()}"
    pattern   = r"Last modified: \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC"

    if re.search(pattern, src):
        return re.sub(pattern, timestamp, src)

    # Not found — append to last *Updated* line
    return re.sub(
        r"(\*Updated:.*?\*)",
        lambda m: m.group(0).rstrip("*") + f" | {timestamp}*",
        src,
        count=1,
        flags=re.DOTALL,
    )


def append_activity(src: str, message: str) -> str:
    """
    Append a timestamped activity note under today's date heading.
    Creates the heading if it does not exist.
    """
    today    = today_date()
    human    = today_human()
    time_str = datetime.now(timezone.utc).strftime("%H:%M UTC")
    note     = f"- `{time_str}` — {message}"
    heading  = f"### Activity — {human}"

    if heading in src:
        # Insert note after the heading
        src = src.replace(heading, f"{heading}\n{note}")
    else:
        # Append a new section before the final *Updated* line
        src = re.sub(
            r"(\n---\n\n\*Updated:)",
            f"\n\n{heading}\n{note}\n\\1",
            src,
        )
    return src


def main() -> None:
    parser = argparse.ArgumentParser(description="Update Bawbel progress log")
    parser.add_argument(
        "--message", "-m",
        type=str,
        default=None,
        help="Optional activity note to append (e.g. 'Pushed bawbel-scanner v0.1.0')",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=LOG_PATH,
        help=f"Path to log file (default: {LOG_PATH})",
    )
    args = parser.parse_args()

    log_path: Path = args.log

    if not log_path.exists():
        print(f"Error: log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    src = log_path.read_text(encoding="utf-8")
    src = update_timestamp(src)

    if args.message:
        src = append_activity(src, args.message)

    log_path.write_text(src, encoding="utf-8")

    print(f"✓ Progress log updated: {now_utc()}")
    if args.message:
        print(f"  Note: {args.message}")


if __name__ == "__main__":
    main()
