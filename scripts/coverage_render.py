"""Render the coverage matrix as markdown. Every number is computed here from the JSON files.

    python3 -I scripts/coverage_render.py MATRIX.json EXAMPLES.json --scanner-ref SHA > report.md

MATRIX.json is the output of coverage_matrix.py and EXAMPLES.json the output of
coverage_examples.py. For each record that has example_patterns, an example counts as "own" if
the record's own rule flagged it, "other" if only another record's rule did, and "none" if no
rule did.
"""

import argparse
import json
from collections import Counter
from pathlib import Path

_args = argparse.ArgumentParser(description=__doc__.splitlines()[0])
_args.add_argument("matrix")
_args.add_argument("examples")
_args.add_argument(
    "--scanner-ref", default="unknown", help="the scanner commit the rules were read at"
)
_cli = _args.parse_args()

matrix = json.loads(Path(_cli.matrix).read_text(encoding="utf-8"))
examples = json.loads(Path(_cli.examples).read_text(encoding="utf-8"))
for _row in matrix["rows"]:
    _results = examples["records"].get(_row["ave_id"])
    if _results is None:  # out of scope, or no example_patterns to run
        _row["ex_own"] = _row["ex_other_only"] = _row["ex_none"] = None
    else:
        _row["ex_own"] = sum(1 for x in _results if x["own"])
        _row["ex_other_only"] = sum(1 for x in _results if not x["own"] and x["other"])
        _row["ex_none"] = sum(1 for x in _results if not x["own"] and not x["other"])
rows = [r for r in matrix["rows"] if r["status"] == "active"]
rejected = [r for r in matrix["rows"] if r["status"] != "active"]
ENG = {"pattern": "P", "yara": "Y", "semgrep": "S", "magika": "M", "sandbox": "X"}


def static_rules(r):
    return [x for x in r["rules"] if x["engine"] != "sandbox"]


def category(r):
    if r["can_see"] == "out of scope":
        return "OUT"
    if r["can_see"].startswith("no"):
        return "RUNTIME_RULE" if static_rules(r) else "RUNTIME_NORULE"
    return "VISIBLE_RULE" if static_rules(r) else "VISIBLE_NORULE"


def rules_cell(r):
    return "; ".join(f"{ENG[x['engine']]} {x['rule_id']}" for x in r["rules"]) or "none"


def tests_cell(r):
    a, b, c = (
        len(r["tests_naming_a_rule_id"]),
        len(r["tests_naming_only_the_ave_id"]),
        len(r["negative_named_tests"]),
    )
    g = ", golden" if r["in_golden"] else ""
    return f"{a} / {b} / {c}{g}"


def ex_cell(r):
    if r["examples"] == 0:
        return "0"
    if r["ex_own"] is None:
        return f"{r['examples']} (not run)"
    return f"{r['examples']}: {r['ex_own']} own, {r['ex_other_only']} other, {r['ex_none']} none"


def gap(r):
    cat = category(r)
    if cat == "OUT":
        return "out of scope for a file scanner"
    if cat == "RUNTIME_NORULE":
        return "no rule; evidence appears only at runtime"
    if cat == "RUNTIME_RULE":
        t = (
            "no test names the rule"
            if not r["tests_naming_a_rule_id"] and not r["tests_naming_only_the_ave_id"]
            else "tested"
        )
        return f"static rule cites a runtime-stage record, it sees only the text form; {t}"
    if cat == "VISIBLE_NORULE":
        return "no rule"
    parts = []
    if not r["tests_naming_a_rule_id"] and not r["tests_naming_only_the_ave_id"]:
        parts.append("no test that runs a scan names the rule or the record")
    elif not r["tests_naming_a_rule_id"]:
        parts.append("tests name the record only, not a rule id")
    if r["examples"] and r["ex_own"] is not None and r["ex_own"] < r["examples"]:
        parts.append(
            f"{r['examples'] - r['ex_own']} of {r['examples']} example_patterns not flagged by its own rule"
        )
    if not parts:
        parts.append(
            "none found; the record has no example_patterns to check the rule against"
            if r["examples"] == 0
            else "none found by this matrix"
        )
    return "; ".join(parts)


def table(items):
    out = [
        "| Record | Title | Layer / stage / component | Rules (P pattern, Y YARA, S Semgrep, M Magika) | Tests: by rule id / by record id only / negative-named | example_patterns | Gap |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in items:
        title = (r["title"] or "").replace("|", "/").replace("\u2014", "-")
        title = title if len(title) <= 60 else title[:57] + "..."
        out.append(
            f"| {r['ave_id']} | {title} | {r['layer']} / {r['stage']} / {r['component_type'] or 'none'} "
            f"| {rules_cell(r)} | {tests_cell(r)} | {ex_cell(r)} | {gap(r)} |"
        )
    return "\n".join(out)


groups = {
    k: [r for r in rows if category(r) == k]
    for k in ("VISIBLE_NORULE", "VISIBLE_RULE", "RUNTIME_RULE", "RUNTIME_NORULE", "OUT")
}
c = Counter(category(r) for r in rows)
visible = c["VISIBLE_NORULE"] + c["VISIBLE_RULE"]
runtime = c["RUNTIME_NORULE"] + c["RUNTIME_RULE"]
untested = [
    r
    for r in groups["VISIBLE_RULE"]
    if not r["tests_naming_a_rule_id"] and not r["tests_naming_only_the_ave_id"]
]
untested_rt = [
    r
    for r in groups["RUNTIME_RULE"]
    if not r["tests_naming_a_rule_id"] and not r["tests_naming_only_the_ave_id"]
]
with_ex = [r for r in rows if r["examples"] and r["ex_own"] is not None]
tot = Counter()
for r in with_ex:
    tot["n"] += r["examples"]
    tot["own"] += r["ex_own"]
    tot["other"] += r["ex_other_only"]
    tot["none"] += r["ex_none"]

rej = ", ".join(f"{r['ave_id']} ({r['status']}, layer {r['layer']})" for r in rejected)
zero_ex = [r for r in rows if r["examples"] == 0]


def mark(name, value):
    """A generated count, in the marker form tests/unit/test_no_typed_counts.py treats as generated."""
    return f"<!-- count:{name} -->{value}<!-- /count -->"


doc = f"""# Coverage matrix: the active records in the pinned AVE corpus

Generated. Do not edit by hand: change the scripts or regenerate (see the end). Read only: no rule is added or changed by this document. Every number below is printed by the scripts; none is typed. A rule count sits in a `count` marker because the scripts write it.

**Corpus sha256:** `{matrix['corpus_sha256']}`. This is the file the README pins (the `counts:corpus` ref in README.md). It holds {matrix['corpus_records']} records: {len(rows)} active and {len(rejected)} not active ({rej}). Only active records are in the matrix.

**Scanner:** commit `{_cli.scanner_ref}`. Example run engines: {', '.join(examples['engines_run_seen'])}. Rule files read: {mark('pattern_rules', matrix['rule_files']['pattern_rules'])} pattern rules, {mark('yara_rules', matrix['rule_files']['yara_rules'])} YARA rules, {mark('semgrep_rules', matrix['rule_files']['semgrep_rules'])} Semgrep rules, the Magika engine, and the sandbox engine's record ids. Rules that cite an id the corpus does not publish: {len(matrix['ids_cited_by_rules_but_not_published'])}.

## Summary

| Group | Records |
|---|---|
| A. A file scanner can see the evidence, no rule cites the record | {c['VISIBLE_NORULE']} |
| B. A file scanner can see the evidence, a rule cites the record | {c['VISIBLE_RULE']} |
| C. Runtime-stage, a static rule cites the record | {c['RUNTIME_RULE']} |
| D. Runtime-stage, no rule | {c['RUNTIME_NORULE']} |
| E. Out of scope: layer `registry_metadata` | {c['OUT']} (a rule cites {sum(1 for r in groups['OUT'] if static_rules(r))} of them) |
| Total active | {len(rows)} |

- Groups A and B together are the {visible} records whose layer is `content` or `server_card` and whose stage is `static_detection`.
- In group B, {mark('group_b_rules_without_a_test', len(untested))} rules have no test that runs a scan and names the rule or the record. In group C, {len(untested_rt)} have none.
- {len(zero_ex)} active records have no `example_patterns` ({zero_ex[0]['ave_id']} to {zero_ex[-1]['ave_id']}), so their rules cannot be checked against the record's own examples.
- Of the {tot['n']} `example_patterns` in the {len(with_ex)} records that have them and are not out of scope, the current static rules flag {tot['own']} with the record's own rule, {tot['other']} only with another record's rule, and {tot['none']} not at all.

## How to read the columns

- **Layer / stage / component:** the record's own fields, copied.
- **Can see:** a rule of the script, from layer and stage only. `content` or `server_card` with stage `static_detection` is evidence in a file (groups A and B). Stage `runtime_observed` or `runtime_drift_detected` is evidence that exists only while something runs (groups C and D). `registry_metadata` is registry data, not file content, and is out of scope for a file scanner (group E). This says nothing about whether a rule works.
- **Rules:** every rule in the rule files whose `ave_id` is this record. "Cites" is not "detects". X is the sandbox engine, which needs Docker and is off by default, listed only where it names the record.
- **Tests:** three counts. By rule id: test functions whose source runs a scan and names one of the record's rule ids. By record id only: tests that run a scan and name the AVE id but no rule id. Negative-named: of those, tests whose function name suggests a negative case (a name-based guess). `golden` means the golden fixture names the record or its rule. Tests that name an id without running a scan (a range formatter, for example) are not counted. A count above zero shows where to look. It does not show the test asserts a detection.
- **example_patterns:** the number of examples the record carries. Where it was run: how many the current static rules flag with the record's own rule (own), only with another record's rule (other), or not at all (none). Each example was written as one line of a SKILL.md and scanned with the pattern, YARA and Semgrep engines. LLM and sandbox stages were off. A rule might flag an example in a different file type or with more context.
- **Gap:** derived from the columns, in a fixed order. It is not a judgement about the record.

""" + "\n".join(
    f"## {title} ({len(groups[k])})\n\n{table(groups[k])}\n"
    for k, title in (
        ("VISIBLE_NORULE", "A. A file scanner can see the evidence, no rule cites the record"),
        ("VISIBLE_RULE", "B. A file scanner can see the evidence, a rule cites the record"),
        ("RUNTIME_RULE", "C. Runtime-stage records that a static rule cites"),
        ("RUNTIME_NORULE", "D. Runtime-stage records no rule cites"),
        ("OUT", "E. Out of scope: layer registry_metadata"),
    )
)
tail = f"""
## Notes

- **Rules with no test that runs a scan and names them.** Group B: {", ".join(r["ave_id"] for r in untested)}. Group C: {", ".join(r["ave_id"] for r in untested_rt)}.
- **Rules that do not flag their own record's examples.** Records that have a rule and examples where fewer than all examples are flagged by the record's own rule: {", ".join(f"{r['ave_id']} ({r['ex_own']} of {r['examples']})" for r in with_ex if static_rules(r) and r["ex_own"] < r["examples"]) or "none"}.
- **Records in group A, by what the examples show.** {", ".join(f"{r['ave_id']} ({r['ex_other_only']} of {r['examples']} flagged by another record's rule)" for r in groups["VISIBLE_NORULE"] if r["ex_other_only"])}.
- **Display.** Titles are cut at 60 characters and an em dash in a title is shown as a hyphen. The corpus is not changed.

## What this does not show

- Whether a rule detects the attack its record describes. "Cites" means the rule's `ave_id` field names the record.
- Whether a test asserts a detection. A test counts when its source runs a scan and names the rule or the record.
- Anything about file types other than the one-line SKILL.md the examples were written into.
- Anything about the LLM or sandbox stages, which were off.

## Regenerate

```text
python3 -I scripts/coverage_matrix.py --corpus CORPUS.json --src . --out matrix.json
python3 scripts/coverage_examples.py matrix.json examples.json     # needs the pattern, YARA and Semgrep engines installed
python3 -I scripts/coverage_render.py matrix.json examples.json --scanner-ref "$(git rev-parse HEAD)" > docs/reports/COVERAGE-MATRIX.md
```

- `scripts/coverage_matrix.py`: reads the corpus file, the rule files and tests/ as text, writes the JSON.
- `scripts/coverage_examples.py`: scans each example with the static engines. Nothing is executed.
- `scripts/coverage_render.py`: prints this document.
"""
print(doc + tail)
