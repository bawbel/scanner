#!/usr/bin/env python3
"""Coverage matrix of the active records of the pinned AVE corpus. Read only.

Standard library only. Reads the corpus file, the scanner's rule files and its tests, as text.
It imports no scanner code and writes nothing but the JSON file named by --out.

    python3 -I scripts/coverage_matrix.py --corpus FILE --src DIR --out matrix.json

Every number in the report comes from this script's output. Nothing is typed.

What each column means, and what it does not:

  layer, stage, component_type   the record's own fields, copied
  can see                        a rule of this script, see can_see(): from layer and stage only.
                                 It says whether the record's evidence is the kind of thing a
                                 file scanner reads. It says nothing about whether a rule works.
  rules                          every rule in the scanner's rule files that cites the record's
                                 ave_id (pattern, YARA, Semgrep, Magika, sandbox). "Cites" is
                                 not "detects": a rule can cite a record and still miss it.
  tests                          test functions under tests/ whose source names the rule id or
                                 the AVE id, plus the golden fixture. "Names" is not "asserts a
                                 positive detection". The test list is where to look, not proof.
  examples                       len(example_patterns) in the record
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

AVE_ID = r"AVE-\d{4}-\d{5}"

# A test "runs a scan" when its source calls one of these. Calls found by reading every
# tests/**/*.py: the public scan(), each engine's entry point, a CLI invoke, and the
# `_findings` helper in tests/test_known_misses.py.
SCAN_CALL = re.compile(
    r"(?<![\w.])(?:\w+\.)?(scan|run_pattern_scan|run_yara_scan|run_semgrep_scan|run_magika_scan"
    r"|_findings|invoke)\("
)
NEGATIVE_NAME = re.compile(
    r"no_fp|no_false|false_pos|not_|clean|negative|benign|ignore|does_not|never"
)


def load_sync(src: Path):
    """The repo's own parsing helpers, so rule files are read the way the README counts read them."""
    spec = importlib.util.spec_from_file_location(
        "sync_record_counts", src / "scripts/sync_record_counts.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["sync_record_counts"] = mod
    spec.loader.exec_module(mod)
    return mod


def rules_by_record(src: Path, sync) -> dict[str, list[dict]]:
    """ave_id -> [{engine, rule_id}] from the rule files."""
    out: dict[str, list[dict]] = {}

    def add(ave_id: str, engine: str, rule_id: str) -> None:
        out.setdefault(ave_id, []).append({"engine": engine, "rule_id": rule_id})

    # Pattern: PATTERN_RULES + PATTERN_RULES_V2, parsed by the repo's helper
    elements = sync._list_elements(
        sync._read(sync.PATTERN_RULES_FILE, src), "PATTERN_RULES", sync.PATTERN_RULES_FILE
    )
    n_pattern = 0
    for e in elements:
        rid, ave = sync._string_key(e, "rule_id"), sync._string_key(e, "ave_id")
        n_pattern += 1
        if ave:
            add(ave, "pattern", rid)

    # YARA: rule name and every ave_id in its block
    text = sync._read(sync.YARA_RULES_FILE, src)
    parts = re.split(r"(?m)^\s*rule\s+(\w+)", text)
    n_yara = 0
    for name, body in zip(parts[1::2], parts[2::2]):
        n_yara += 1
        for ave in re.findall(rf'ave_id\s*=\s*"({AVE_ID})"', body):
            add(ave, "yara", name)

    # Semgrep: "  - id:" then the next ave_id line
    text = sync._read(sync.SEMGREP_RULES_FILE, src)
    n_semgrep = 0
    current = None
    for line in text.splitlines():
        m = re.match(r"^  - id:\s*(\S+)", line)
        if m:
            current = m.group(1)
            n_semgrep += 1
            continue
        m = re.match(rf"^\s+ave_id:\s*[\"']?({AVE_ID})", line)
        if m and current:
            add(m.group(1), "semgrep", current)

    # Magika: the one engine rule id, and the ids it cites
    magika = sync._read(sync.MAGIKA_ENGINE_FILE, src)
    for ave in sorted(set(re.findall(rf'ave_id="({AVE_ID})"', magika))):
        for rid in sorted(set(re.findall(r'rule_id="([^"]+)"', magika))):
            add(ave, "magika", rid)

    # Sandbox: every AVE id the engine file names (runtime, opt-in, needs Docker)
    sandbox = (src / "scanner/engines/sandbox_engine.py").read_text(encoding="utf-8")
    for ave in sorted(set(re.findall(AVE_ID, sandbox))):
        add(ave, "sandbox", "sandbox-*")

    meta = {"pattern_rules": n_pattern, "yara_rules": n_yara, "semgrep_rules": n_semgrep}
    return out, meta


def test_index(src: Path, rule_ids: set[str]):
    """id (rule id or AVE id) -> test functions naming it; id -> files naming it outside a test."""
    named: dict[str, list[str]] = {}
    loose: dict[str, list[str]] = {}
    scanning: set[str] = set()
    token = re.compile(rf"{AVE_ID}")
    rid_res = {rid: re.compile(rf"(?<![\w-]){re.escape(rid)}(?![\w-])") for rid in rule_ids}

    for path in sorted((src / "tests").rglob("*.py")):
        rel = path.relative_to(src).as_posix()
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        lines = text.splitlines()
        covered: list[tuple[int, int]] = []

        def visit(node, prefix="", rel=rel, lines=lines, covered=covered):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    visit(child, prefix + child.name + "::", rel, lines, covered)
                elif isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef)
                ) and child.name.startswith("test"):
                    start = min([child.lineno] + [d.lineno for d in child.decorator_list])
                    end = child.end_lineno
                    covered.append((start, end))
                    seg = "\n".join(lines[start - 1 : end])
                    label = f"{rel}::{prefix}{child.name}"
                    if SCAN_CALL.search(seg):
                        scanning.add(label)
                    for ave in set(token.findall(seg)):
                        named.setdefault(ave, []).append(label)
                    for rid, rx in rid_res.items():
                        if rx.search(seg):
                            named.setdefault(rid, []).append(label)

        visit(tree)

        # Mentions outside any test function: module-level data, helpers, docstrings
        outside = "\n".join(
            line for n, line in enumerate(lines, 1) if not any(a <= n <= b for a, b in covered)
        )
        for ave in set(token.findall(outside)):
            loose.setdefault(ave, []).append(rel)
        for rid, rx in rid_res.items():
            if rx.search(outside):
                loose.setdefault(rid, []).append(rel)
    return named, loose, scanning


def golden_ids(src: Path) -> set[str]:
    out: set[str] = set()
    for p in sorted((src / "tests/fixtures/golden").glob("*.json")):
        text = p.read_text(encoding="utf-8")
        out |= set(re.findall(AVE_ID, text))
        out |= set(re.findall(r'"rule_id":\s*"([^"]+)"', text))
    return out


def can_see(rec: dict) -> tuple[str, str]:
    """(value, reason) from the record's layer and stage only."""
    layer, stage = rec.get("detection_layer"), str(rec.get("detection_stage"))
    if layer == "registry_metadata":
        return "out of scope", "layer registry_metadata: registry data, not file content"
    if layer == "runtime" or stage.startswith("runtime"):
        return "no (runtime)", f"layer {layer}, stage {stage}: evidence exists only while it runs"
    if layer in ("content", "server_card", "transport") and stage == "static_detection":
        return "yes", f"layer {layer}, stage static_detection: evidence is in a file"
    return "unclassified", f"layer {layer}, stage {stage}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--src", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    src = Path(args.src)
    raw = Path(args.corpus).read_bytes()
    records = json.loads(raw)
    sync = load_sync(src)

    by_rec, rule_meta = rules_by_record(src, sync)
    all_rule_ids = {x["rule_id"] for xs in by_rec.values() for x in xs if x["engine"] != "sandbox"}
    named, loose, scanning = test_index(src, all_rule_ids)
    golden = golden_ids(src)

    published = {r["ave_id"] for r in records}
    rows = []
    for r in sorted(records, key=lambda x: x["ave_id"]):
        ave = r["ave_id"]
        see, why = can_see(r)
        rules = by_rec.get(ave, [])
        static_rules = [x for x in rules if x["engine"] != "sandbox"]
        by_rule = {t for x in static_rules for t in named.get(x["rule_id"], [])}
        by_ave = set(named.get(ave, []))
        # evidence: a test that runs a scan and names the rule id (or, failing that, the AVE id)
        tests_rule = sorted(t for t in by_rule if t in scanning)
        tests_ave_only = sorted(t for t in by_ave if t in scanning and t not in by_rule)
        names_only = sorted((by_rule | by_ave) - scanning)
        tests = sorted(set(tests_rule) | set(tests_ave_only))
        neg = [t for t in tests if NEGATIVE_NAME.search(t.rsplit("::", 1)[-1])]
        file_mentions = sorted(
            set(loose.get(ave, []) + [f for x in static_rules for f in loose.get(x["rule_id"], [])])
        )
        ex = r.get("example_patterns")
        rows.append(
            {
                "ave_id": ave,
                "title": r.get("title"),
                "status": r.get("status"),
                "layer": r.get("detection_layer"),
                "stage": r.get("detection_stage"),
                "component_type": r.get("component_type"),
                "can_see": see,
                "can_see_reason": why,
                "rules": rules,
                "tests": tests,
                "tests_naming_a_rule_id": tests_rule,
                "tests_naming_only_the_ave_id": tests_ave_only,
                "negative_named_tests": neg,
                "tests_that_name_it_but_run_no_scan": names_only,
                "file_level_mentions": file_mentions,
                "in_golden": ave in golden or any(x["rule_id"] in golden for x in static_rules),
                "examples": len(ex) if isinstance(ex, list) else 0,
                "example_patterns": ex if isinstance(ex, list) else [],
            }
        )

    unknown = sorted({a for a in by_rec if a not in published})
    out = {
        "corpus_sha256": hashlib.sha256(raw).hexdigest(),
        "corpus_records": len(records),
        "rule_files": rule_meta,
        "ids_cited_by_rules_but_not_published": unknown,
        "rows": rows,
    }
    Path(args.out).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {args.out}: {len(rows)} records, corpus sha256 {out['corpus_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
