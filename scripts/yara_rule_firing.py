#!/usr/bin/env python3
"""How many files each YARA rule of the scanner matches. Read only. Needs yara-python.

    python3 -I scripts/yara_rule_firing.py --yara-file FILE --corpus CORPUS.json \\
        --roots DIR [DIR ...] [--files-from LIST] [--rules NAME ...]

It compiles the YARA file it is given and matches every rule against the bytes of each file of three
sets, and prints, for each set, the number of files each rule matched:

  third-party   text files (.md .json .yaml .yml .txt .toml .markdown, up to 2,000,000 bytes) found
                under --roots. None of them is a skill or an attack: a match here is a false positive
  own           the files named in --files-from, one path per line (counts only, no names are printed)
  examples      each example_patterns entry of each active record of the AVE corpus, as one file;
                "own record" counts the examples of the record named in the rule's ave_id metadata

This is the YARA rule on its own, before the scanner's preprocessing and its false-positive pipeline,
so a count here is an upper bound of what a scan reports. Run it once with the YARA file before a
change and once after, and compare.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

import yara

EXTENSIONS = (".md", ".json", ".yaml", ".yml", ".txt", ".toml", ".markdown")
MAX_BYTES = 2_000_000
SKIP_DIRS = {".git", "node_modules", "__pycache__"}


def select_files(roots: list[str]) -> list[Path]:
    files = []
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                path = Path(dirpath) / name
                if not name.lower().endswith(EXTENSIONS):
                    continue
                try:
                    if path.stat().st_size <= MAX_BYTES:
                        files.append(path)
                except OSError:
                    continue
    return files


def count_files(rules, paths: list[Path]) -> tuple[int, dict[str, int]]:
    counts: dict[str, int] = {}
    read = 0
    for path in paths:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        read += 1
        for match in rules.match(data=data):
            counts[match.rule] = counts.get(match.rule, 0) + 1
    return read, counts


def count_examples(rules, corpus: list[dict]) -> tuple[int, dict[str, list[int]]]:
    """Per rule: [examples matched, of which the rule's own record's]."""
    counts: dict[str, list[int]] = {}
    total = 0
    for record in sorted(corpus, key=lambda r: r["ave_id"]):
        if record.get("status") != "active" or not isinstance(record.get("example_patterns"), list):
            continue
        for example in record["example_patterns"]:
            total += 1
            for match in rules.match(data=str(example).encode("utf-8")):
                entry = counts.setdefault(match.rule, [0, 0])
                entry[0] += 1
                if match.meta.get("ave_id") == record["ave_id"]:
                    entry[1] += 1
    return total, counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yara-file", required=True)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--roots", nargs="+", required=True)
    ap.add_argument("--files-from")
    ap.add_argument("--rules", nargs="*", default=[])
    args = ap.parse_args()

    yara_bytes = Path(args.yara_file).read_bytes()
    rules = yara.compile(filepath=args.yara_file)
    corpus_raw = Path(args.corpus).read_bytes()
    third_n, third = count_files(rules, select_files(args.roots))
    own_n, own = 0, {}
    if args.files_from:
        listed = [
            Path(p.strip()) for p in Path(args.files_from).read_text().splitlines() if p.strip()
        ]
        own_n, own = count_files(rules, listed)
    ex_n, ex = count_examples(rules, json.loads(corpus_raw))

    names = args.rules or sorted(set(third) | set(own) | set(ex))
    print(f"yara file sha256 {hashlib.sha256(yara_bytes).hexdigest()}")
    print(f"corpus sha256    {hashlib.sha256(corpus_raw).hexdigest()}")
    print(f"yara-python      {yara.__version__}")
    print(f"files: third-party {third_n}, own {own_n}, examples {ex_n}")
    print(f"{'rule':34} {'third-party':>11} {'own':>5} {'examples':>9} {'own record':>11}")
    for name in names:
        e = ex.get(name, [0, 0])
        print(f"{name:34} {third.get(name, 0):>11} {own.get(name, 0):>5} {e[0]:>9} {e[1]:>11}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
