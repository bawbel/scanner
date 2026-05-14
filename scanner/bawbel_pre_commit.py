#!/usr/bin/env python3
"""
bawbel-pre-commit - pre-commit hook entry point for Bawbel Scanner.

Called by pre-commit with a list of staged file paths as arguments.
Scans each file and exits non-zero if any findings meet or exceed
the configured severity threshold.

Exit codes:
    0  - all files clean (or only suppressed findings)
    1  - one or more findings at or above --fail-on-severity
    2  - scan error (file unreadable, engine crash, etc.)
"""

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Bawbel Scanner pre-commit hook")
    parser.add_argument(
        "filenames",
        nargs="*",
        help="Staged files to scan (passed by pre-commit)",
    )
    parser.add_argument(
        "--fail-on-severity",
        default="high",
        choices=["critical", "high", "medium", "low"],
        help="Minimum severity that causes a non-zero exit (default: high)",
    )
    parser.add_argument(
        "--no-ignore",
        action="store_true",
        default=False,
        help="Ignore all bawbel-ignore suppressions - audit mode",
    )
    args = parser.parse_args()

    if not args.filenames:
        return 0

    # Import here so the hook fails fast with a clear message if not installed
    try:
        from scanner.scanner import scan, SEVERITY_SCORES
    except ImportError:
        print(
            "bawbel-scanner not installed.\n" 'Run: pip install "bawbel-scanner>=1.0.1"',
            file=sys.stderr,
        )
        return 2

    threshold = SEVERITY_SCORES.get(args.fail_on_severity.upper(), 0)
    found: list[str] = []
    errors: list[str] = []

    for filename in args.filenames:
        path = Path(filename)
        if not path.exists():
            continue

        result = scan(str(path), no_ignore=args.no_ignore)

        if result.has_error:
            errors.append(f"  {filename}: {result.error}")
            continue

        # Check if any active finding meets the severity threshold
        for f in result.findings:
            from scanner.scanner import SEVERITY_SCORES as _ss

            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if _ss.get(sev, 0) >= threshold:
                found.append(filename)
                break  # one finding is enough to flag this file

    # Print results
    if found or errors:
        print("Bawbel Scanner")
        print("─" * 50)

    if errors:
        print("Scan errors:")
        for e in errors:
            print(e)

    if found:
        print(f"AVE vulnerabilities found ({args.fail_on_severity.upper()}+):")
        for filename in found:
            path = Path(filename)
            result = scan(str(path), no_ignore=args.no_ignore)
            for f in result.findings:
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                line = f"  line {f.line}" if f.line else ""
                print(f"  [{sev}] {f.ave_id or f.rule_id}  {filename}{line}")
        print()
        print(
            "Run 'bawbel report <file>' for remediation steps.\n"
            "Add '<!-- bawbel-ignore: rule_id -->' to suppress false positives.\n"
            "See: https://bawbel.io/docs/suppression"
        )

    if found:
        return 1
    if errors:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
