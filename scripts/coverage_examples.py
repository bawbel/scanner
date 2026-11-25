"""Which of a record's own example_patterns do the current static rules flag?

Runs inside a container with the scanner source on PYTHONPATH. Each example is written as one
line of a SKILL.md file (the same shape tests/test_known_misses.py uses) and scanned in process
with the static engines. LLM and sandbox stages are off. Nothing is executed: the text is only
read by the scanner.

    python3 scripts/coverage_examples.py MATRIX.json OUT.json

Records that are out of scope (registry_metadata) are skipped: a file scanner is not the thing
that would see them.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

for key in (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "MISTRAL_API_KEY",
    "GROQ_API_KEY",
    "BAWBEL_LLM_MODEL",
):
    os.environ.pop(key, None)
os.environ["BAWBEL_LLM_ENABLED"] = "false"
os.environ["BAWBEL_SANDBOX_ENABLED"] = "false"
os.environ["BAWBEL_LOG_LEVEL"] = "WARNING"

from scanner.scanner import scan  # noqa: E402


def main() -> int:
    matrix = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out = {"engines_run_seen": [], "records": {}}
    seen: set[str] = set()
    with tempfile.TemporaryDirectory() as tmp:
        for row in matrix["rows"]:
            if row["status"] != "active" or row["can_see"] == "out of scope":
                continue
            results = []
            for n, example in enumerate(row["example_patterns"]):
                d = Path(tmp) / row["ave_id"] / str(n)
                d.mkdir(parents=True)
                f = d / "SKILL.md"
                f.write_text(example + "\n", encoding="utf-8")
                res = scan(str(f), no_ignore=True)
                seen.update(res.engines_run or [])
                findings = [
                    {"ave_id": x.ave_id, "rule_id": x.rule_id, "engine": x.engine}
                    for x in res.findings
                ]
                results.append(
                    {
                        "example": example,
                        "has_error": bool(res.has_error),
                        "own": sorted(
                            {x["rule_id"] for x in findings if x["ave_id"] == row["ave_id"]}
                        ),
                        "other": sorted(
                            {
                                f'{x["ave_id"]}:{x["rule_id"]}'
                                for x in findings
                                if x["ave_id"] != row["ave_id"]
                            }
                        ),
                    }
                )
            out["records"][row["ave_id"]] = results
            print(row["ave_id"], len(results), flush=True)
    out["engines_run_seen"] = sorted(seen)
    Path(sys.argv[2]).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
