#!/usr/bin/env python3
"""Run one scanner, in an offline mode, on each fixture directory and record what it said.

Standard library only. The scanner is a command line, run with no shell and no network of its own:
the caller runs this script inside a container started with `--network none`, so a tool that
needs a network either falls back or fails, and the failure is a result.

    python3 -I scripts/competitive_run.py --tool NAME --fixtures DIR --out results.json -- CMD ... {path} ...

`{path}` in CMD is replaced by each fixture directory. NAME picks how the output is read:

    bawbel       `bawbel scan {path} --format json`: a list of results, each with findings
    skillspector `skillspector scan {path} --no-llm --format json`
    cisco        `skill-scanner scan {path} --format json`

The result records, per fixture: exit code, seconds, whether the tool reported a finding, the rule
or check names it gave, and its highest severity word. No rule text and no tool output is kept.
"""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404
import sys
import time
from pathlib import Path


def _collect(node, found: list) -> None:
    """Every dict that has a rule-like and a severity-like key, anywhere in the output."""
    if isinstance(node, dict):
        keys = {k.lower() for k in node}
        if keys & {"rule_id", "rule", "id", "check", "check_id", "name"} and keys & {
            "severity",
            "level",
            "risk",
        }:
            found.append(node)
        for value in node.values():
            _collect(value, found)
    elif isinstance(node, list):
        for value in node:
            _collect(value, found)


def _name(item: dict) -> str:
    for key in ("rule_id", "check_id", "rule", "check", "id", "name"):
        if key in item and isinstance(item[key], (str, int)):
            return str(item[key])
    return "?"


def _severity(item: dict) -> str:
    for key in ("severity", "level", "risk"):
        if key in item and isinstance(item[key], (str, int, float)):
            return str(item[key]).upper()
    return "?"


def read_output(tool: str, stdout: str) -> dict:
    """What a tool reported. `flagged` is True if it listed at least one finding."""
    start = min((i for i in (stdout.find("{"), stdout.find("[")) if i >= 0), default=-1)
    if start < 0:
        return {"parsed": False, "flagged": None, "rules": [], "max_severity": None}
    try:
        data = json.JSONDecoder().raw_decode(stdout[start:])[0]
    except ValueError:
        return {"parsed": False, "flagged": None, "rules": [], "max_severity": None}

    if tool == "bawbel":
        findings = [f for result in data for f in result.get("findings", [])]
        rules = sorted({f["rule_id"] for f in findings})
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        top = next((s for s in order if any(f["severity"] == s for f in findings)), None)
        return {"parsed": True, "flagged": bool(findings), "rules": rules, "max_severity": top}

    if tool == "skillspector":
        issues = data.get("issues", [])
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        top = next(
            (s for s in order if any(str(i.get("severity")).upper() == s for i in issues)), None
        )
        completeness = data.get("analysis_completeness") or {}
        return {
            "parsed": True,
            "flagged": bool(issues),
            "rules": sorted({str(i.get("id")) for i in issues}),
            "max_severity": top,
            "risk_score": (data.get("risk_assessment") or {}).get("score"),
            "completeness": completeness.get("status"),
        }

    if tool == "cisco":
        findings = data.get("findings", [])
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        top = next(
            (s for s in order if any(str(f.get("severity")).upper() == s for f in findings)), None
        )
        return {
            "parsed": True,
            "flagged": bool(findings),
            "rules": sorted({str(f.get("rule_id")) for f in findings}),
            "max_severity": top,
            "analyzers": data.get("analyzers_used"),
        }

    found: list = []
    _collect(data, found)
    return {
        "parsed": True,
        "flagged": bool(found),
        "rules": sorted({_name(item) for item in found}),
        "max_severity": sorted({_severity(item) for item in found})[-1] if found else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", required=True, choices=("bawbel", "skillspector", "cisco"))
    ap.add_argument("--fixtures", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if not any("{path}" in part for part in command):
        ap.error("the command needs a {path} placeholder")

    root = Path(args.fixtures)
    results = []
    for directory in sorted(p for p in root.iterdir() if p.is_dir()):
        argv = [part.replace("{path}", str(directory)) for part in command]
        started = time.perf_counter()
        try:
            proc = subprocess.run(  # nosec B603
                argv, capture_output=True, text=True, check=False, timeout=args.timeout
            )
            code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            code, stdout, stderr = "timeout", "", ""
        seconds = round(time.perf_counter() - started, 3)
        entry = {"fixture": directory.name, "exit": code, "seconds": seconds}
        entry.update(read_output(args.tool, stdout))
        entry["stderr_chars"] = len(stderr)
        results.append(entry)
        print(f"{directory.name} exit={code} flagged={entry['flagged']} {seconds}s", flush=True)

    Path(args.out).write_text(
        json.dumps({"tool": args.tool, "command": command, "results": results}, indent=1),
        encoding="utf-8",
    )
    print(f"wrote {args.out}: {len(results)} fixtures", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
