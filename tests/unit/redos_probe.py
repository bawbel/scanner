"""
Time regular expressions on adversarial single lines. Standard library only. Issue #198.

tests/unit/test_ingest_limits.py runs this file in a child process with a time limit. A pattern
that backtracks without end then fails the test after the limit, where in the same process it
would stall the whole suite, and a regular expression search cannot be interrupted portably.

    python3 -I redos_probe.py N < patterns.json      patterns.json is a JSON list of strings

Prints one JSON list: [seconds of the slowest search, name of the line, start of the pattern].
"""

import json
import re
import sys
import time


def adversarial(n: int) -> dict:
    """Single lines shaped to make a backtracking regular expression work hard."""
    return {
        "letters": "a" * n,
        "spaces": " " * n,
        "words": "ab " * (n // 3),
        "dashes": "ab-" * (n // 3),
        "hex": "0123456789abcdef" * (n // 16),
        "fetch": "curl " + "x" * n,
        "ignore": "ignore " + "all " * (n // 4),
        "label": "IMPORTANT: " * (n // 11),
        "json": '"description": "' + "a " * (n // 2),
        "url": "https://" + "a." * (n // 2),
        "tabs": ("\t" * 50 + "x") * (n // 51),
        "base64": "A" * n + "=",
        "unicode": "é" * n,
    }


def slowest(patterns: list, n: int) -> list:
    worst = [0.0, "", ""]
    for pattern in patterns:
        compiled = re.compile(pattern, re.IGNORECASE)
        for name, line in adversarial(n).items():
            start = time.perf_counter()
            compiled.search(line)
            elapsed = time.perf_counter() - start
            if elapsed > worst[0]:
                worst = [elapsed, name, pattern[:60]]
    return worst


if __name__ == "__main__":
    print(json.dumps(slowest(json.load(sys.stdin), int(sys.argv[1]))))
