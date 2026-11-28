#!/usr/bin/env python3
"""Which Semgrep rules of the scanner ever fire. Read only on its inputs.

Standard library only. It runs the `semgrep` command line, the way the scanner's Semgrep engine
does (`--config <rules file> --json --quiet <target>`), plus `--metrics=off` and
`--disable-version-check`, on two sets of files, and counts the findings per rule.

    python3 -I scripts/semgrep_rule_firing.py measure --rules FILE --corpus FILE \\
        --roots DIR [DIR ...] --work DIR --out results.json
    python3 -I scripts/semgrep_rule_firing.py render --results results.json --src . --out report.md

The two sets:

  third-party   text files (.md .json .yaml .yml .txt .toml .markdown, up to 2,000,000 bytes) found
                under --roots, copied under flat names so that no path rule of Semgrep applies.
                None of them is a skill or an attack: it is the kind of set false-positive runs use
  examples      every example_patterns entry of every active record of the AVE corpus, one file
                each, under the same minimal frontmatter

Each rules file is run in two variants. "As written" is the file itself. "Either" is a scratch copy in
which a rule that lists several pattern-regex entries under `patterns:` (all of them must match) lists
them under `pattern-either:` (any may match). The second variant measures what fixing those rules
would cost. It is not a proposal, and no rule file in the repository is changed.

Every number in the report comes from this script's output. Nothing is typed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

EXTENSIONS = (".md", ".json", ".yaml", ".yml", ".txt", ".toml", ".markdown")
MAX_BYTES = 2_000_000
SKIP_DIRS = {".git", "node_modules", "__pycache__"}
FRONTMATTER = (
    "---\nname: {name}\ndescription: A fixture for a measurement. It does nothing.\n---\n\n"
)
FLAGS = [
    "--json",
    "--quiet",
    "--metrics=off",
    "--disable-version-check",
    "--no-git-ignore",
    f"--max-target-bytes={MAX_BYTES}",
]
LABELS = {
    "single": "one regex",
    "all-of": "several regexes under `patterns:` (all must match)",
    "either": "several regexes under `pattern-either:`",
}

# ── Reading the rules file, as text ───────────────────────────────────────────


def parse_rules(text: str) -> list[dict]:
    """One dict per rule: id, ave_id, entry counts, language, and how the regexes combine.

    kind is "single" (one regex), "all-of" (several under `patterns:`, all must match) or "either"
    (several under `pattern-either:`, any may match).
    """
    rules = []
    for block in re.split(r"\n(?=\s*- id:\s)", text):
        m = re.match(r"\s*- id:\s*(\S+)", block)
        if not m:
            continue
        regexes = len(re.findall(r"pattern-regex:", block))
        if "pattern-either:" in block:
            kind = "either" if regexes > 1 else "single"
        elif re.search(r"\n\s+patterns:\s*\n", block):
            kind = "all-of" if regexes > 1 else "single"
        else:
            kind = "single"
        ave = re.search(r"ave_id:\s*(AVE-\d{4}-\d{5})", block)
        rules.append(
            {
                "id": m.group(1),
                "ave_id": ave.group(1) if ave else None,
                "regexes": regexes,
                "plain_patterns": len(re.findall(r"(?m)^\s*(?:- )?pattern:", block)),
                "generic": bool(re.search(r"languages:\s*\[\s*generic\s*\]", block)),
                "kind": kind,
            }
        )
    return rules


def either_variant(text: str) -> str:
    """The rules file with every all-of rule rewritten as an either rule. For measurement only."""
    out = []
    for block in re.split(r"\n(?=\s*- id:\s)", text):
        if (
            re.match(r"\s*- id:", block)
            and len(re.findall(r"pattern-regex:", block)) > 1
            and re.search(r"\n(\s+)patterns:\s*\n", block)
        ):
            block = re.sub(r"\n(\s+)patterns:\s*\n", r"\n\1pattern-either:\n", block, count=1)
        out.append(block)
    return "\n".join(out)


# ── Building the two sets ─────────────────────────────────────────────────────


def build_third_party(roots: list[str], target: Path) -> dict:
    target.mkdir(parents=True)
    counts: dict[str, int] = {}
    n = 0
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                if not name.lower().endswith(EXTENSIONS):
                    continue
                ext = "." + name.rsplit(".", 1)[-1].lower()
                path = Path(dirpath) / name
                dest = target / f"f{n + 1:05d}{ext}"
                try:
                    if path.stat().st_size > MAX_BYTES:
                        continue
                    shutil.copyfile(path, dest)
                except OSError:
                    dest.unlink(missing_ok=True)  # a failed copy leaves nothing behind
                    continue
                n += 1
                counts[ext] = counts.get(ext, 0) + 1
    return {"files": n, "by_extension": dict(sorted(counts.items()))}


def build_examples(corpus: list[dict], target: Path) -> dict:
    target.mkdir(parents=True)
    fixtures = []
    for record in sorted(corpus, key=lambda r: r["ave_id"]):
        if record.get("status") != "active" or not isinstance(record.get("example_patterns"), list):
            continue
        for index, example in enumerate(record["example_patterns"]):
            fixture = f"{record['ave_id'].lower()}-{index}"
            body = FRONTMATTER.format(name=fixture) + str(example) + "\n"
            (target / f"{fixture}.md").write_text(body, encoding="utf-8")
            fixtures.append({"fixture": fixture, "ave_id": record["ave_id"]})
    return {"files": len(fixtures), "fixtures": fixtures}


# ── Running Semgrep ───────────────────────────────────────────────────────────


def semgrep_version() -> str:
    proc = subprocess.run(  # nosec B603 B607
        ["semgrep", "--version"], capture_output=True, text=True, check=False
    )
    return proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "unknown"


def run_semgrep(rules: Path, target: Path) -> dict:
    command = ["semgrep", "--config", str(rules), *FLAGS, str(target)]
    proc = subprocess.run(  # nosec B603 B607
        command, capture_output=True, text=True, check=False, timeout=7200
    )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": f"no JSON, exit {proc.returncode}", "results": [], "errors": []}
    paths = data.get("paths") or {}
    data["scanned_count"] = len(paths["scanned"]) if "scanned" in paths else None
    data["skipped_count"] = len(paths["skipped"]) if "skipped" in paths else None
    return data


def count_rules(data: dict, rules: list[dict], files_dir: Path) -> dict:
    """Per rule id: findings, and the names of the files with a finding."""
    ids = [r["id"] for r in rules]
    per = {rid: {"findings": 0, "files": set()} for rid in ids}
    for result in data.get("results", []):
        check = result.get("check_id", "")
        rid = next((i for i in ids if check == i or check.endswith("." + i)), None)
        if rid is None:
            continue
        per[rid]["findings"] += 1
        per[rid]["files"].add(Path(result.get("path", "")).name)
    return {rid: {"findings": v["findings"], "files": sorted(v["files"])} for rid, v in per.items()}


def measure(args) -> int:
    rules_path = Path(args.rules)
    rules_text = rules_path.read_text(encoding="utf-8")
    rules = parse_rules(rules_text)
    corpus_raw = Path(args.corpus).read_bytes()
    corpus = json.loads(corpus_raw)

    work = Path(args.work)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    third = build_third_party(args.roots, work / "third-party")
    examples = build_examples(corpus, work / "examples")
    (work / "either.yaml").write_text(either_variant(rules_text), encoding="utf-8")

    out = {
        "semgrep_version": semgrep_version(),
        "flags": FLAGS,
        "rules_file_sha256": hashlib.sha256(rules_text.encode("utf-8")).hexdigest(),
        "corpus_sha256": hashlib.sha256(corpus_raw).hexdigest(),
        "rules": rules,
        "third_party": third,
        "examples": {"files": examples["files"], "fixtures": examples["fixtures"]},
        "runs": {},
    }
    for variant, path in (("as_written", rules_path), ("either", work / "either.yaml")):
        for set_name in ("third-party", "examples"):
            data = run_semgrep(path, work / set_name)
            out["runs"][f"{variant}/{set_name}"] = {
                "per_rule": count_rules(data, rules, work / set_name),
                "scanned": data.get("scanned_count"),
                "skipped": data.get("skipped_count"),
                "errors": len(data.get("errors", [])),
                "error": data.get("error"),
            }
            print(f"{variant}/{set_name}: {len(data.get('results', []))} findings", file=sys.stderr)
    Path(args.out).write_text(json.dumps(out, indent=1), encoding="utf-8")
    return 0


# ── Public claims and records ─────────────────────────────────────────────────

CLAIM_WORDS = re.compile(r"semgrep", re.I)


def public_claims(src: Path) -> list[tuple[str, int, str]]:
    """Lines of README.md and docs/ that mention Semgrep together with the word rule(s)."""
    found = []
    files = [src / "README.md", *sorted((src / "docs").rglob("*.md"))]
    for path in files:
        if not path.is_file() or "reports" in path.parts:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if CLAIM_WORDS.search(line) and re.search(r"\brules?\b", line, re.I):
                found.append((path.relative_to(src).as_posix(), number, line.strip()[:200]))
    return found


def load_counter(src: Path):
    """The repository's own rule counter, loaded by path, so its reading of the rule files is used."""
    path = src / "scripts/sync_record_counts.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("sync_record_counts_for_firing", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["sync_record_counts_for_firing"] = module
    spec.loader.exec_module(module)
    return module


def semgrep_only_records(src: Path, rules: list[dict]) -> list[dict] | None:
    """Records cited by a Semgrep rule and by no pattern, YARA or Magika rule.

    One dict per record: the record, and the Semgrep rule ids that cite it. None if the counter of
    the repository is not in `src`.
    """
    counter = load_counter(src)
    if counter is None:
        return None
    _, pattern_ids = counter.pattern_rules(src)
    _, yara_ids = counter.yara_rules(src)
    elsewhere = pattern_ids | yara_ids | counter.magika_ids(src)
    records: dict[str, list[str]] = {}
    for rule in rules:
        if rule["ave_id"] and rule["ave_id"] not in elsewhere:
            records.setdefault(rule["ave_id"], []).append(rule["id"])
    return [{"record": k, "rules": v} for k, v in sorted(records.items())]


# ── The report ────────────────────────────────────────────────────────────────


def render(args) -> int:
    results = json.loads(Path(args.results).read_text(encoding="utf-8"))
    rules = results["rules"]
    runs = results["runs"]

    def fired(variant: str, set_name: str, rid: str) -> dict:
        return runs[f"{variant}/{set_name}"]["per_rule"][rid]

    def skipped(run: dict) -> str:
        return "no count" if run["skipped"] is None else str(run["skipped"])

    def own_examples(rule: dict) -> int:
        names = set(fired("as_written", "examples", rule["id"])["files"])
        return sum(
            1
            for f in results["examples"]["fixtures"]
            if f["ave_id"] == rule["ave_id"] and f"{f['fixture']}.md" in names
        )

    def ever(rs: list[dict], variant: str = "as_written") -> int:
        return sum(
            1
            for r in rs
            if fired(variant, "third-party", r["id"])["findings"]
            or fired(variant, "examples", r["id"])["findings"]
        )

    never = [r for r in rules if not ever([r])]
    by_kind: dict[str, list[dict]] = {}
    for r in rules:
        by_kind.setdefault(r["kind"], []).append(r)
    all_of = by_kind.get("all-of", [])
    generic = sum(1 for r in rules if r["generic"])
    regex_entries = sum(r["regexes"] for r in rules)
    plain_entries = sum(r["plain_patterns"] for r in rules)
    cited = {r["ave_id"] for r in rules if r["ave_id"]}
    with_examples = {f["ave_id"] for f in results["examples"]["fixtures"]}
    third_run = runs["as_written/third-party"]
    example_run = runs["as_written/examples"]
    ext = ", ".join(f"{v} {k}" for k, v in results["third_party"]["by_extension"].items())

    lines = [
        "# Which Semgrep rules ever fire",
        "",
        "Generated by `scripts/semgrep_rule_firing.py`. Do not edit by hand: change the script or "
        "regenerate (see the end). Read only: no rule is added or changed by this document. Every "
        "number below is printed by the script; none is typed.",
        "",
        f"**Semgrep:** `{results['semgrep_version']}`, one version only. Flags: "
        f"`{' '.join(results['flags'])}`. The rules file, sha256 `{results['rules_file_sha256']}`, "
        f"holds <!-- count:semgrep_rules -->{len(rules)}<!-- /count --> rules.",
        f"**AVE corpus:** sha256 `{results['corpus_sha256']}`.",
        "",
        "## What was run",
        "",
        f"- **Third-party:** {results['third_party']['files']} text files ({ext}) found under a "
        "Semgrep environment, the system Python packages and the shared data of the machine. None is "
        f"a skill or an attack. Semgrep reported {third_run['scanned']} files scanned, "
        f"{skipped(third_run)} skipped, {third_run['errors']} errors.",
        f"- **Examples:** {results['examples']['files']} files, one for each `example_patterns` entry of "
        f"each active record. Semgrep reported {example_run['scanned']} scanned, "
        f"{skipped(example_run)} skipped, {example_run['errors']} errors.",
        "- Semgrep was run on the rules file directly, as the scanner's engine does, without the "
        "scanner's preprocessing (fenced code is not blanked) and without its false-positive "
        "pipeline. A file can therefore flag here and not in a scan.",
        "",
        "## Summary",
        "",
        "| Structure | Rules | Fired at least once on either set, as written | Fired at least once in the either copy |",
        "|---|---|---|---|",
    ]
    for kind in ("single", "all-of", "either"):
        rs = by_kind.get(kind, [])
        lines.append(f"| {LABELS[kind]} | {len(rs)} | {ever(rs)} | {ever(rs, 'either')} |")
    lines += [
        "",
        f"Rules that fired on neither set, as written: {len(never)}.",
        "",
        f"Of the <!-- count:semgrep_all_of_rules -->{len(all_of)}<!-- /count --> rules with several "
        f"regexes under `patterns:`, {len(all_of) - ever(all_of)} fired on neither set as written, and "
        f"{ever(all_of, 'either')} fired in the either copy, on the same files. So the regexes of "
        "those rules match text in these files, and the rules as written do not fire: what stops "
        "them is that all of the regexes must match.",
        "",
        f"Mode: <!-- count:semgrep_generic_rules -->{generic}<!-- /count --> rules are written for "
        "Semgrep's `generic` mode, which matches text and builds no syntax tree. Their pattern entries "
        f"are <!-- count:semgrep_regex_entries -->{regex_entries}<!-- /count --> `pattern-regex` and "
        f"<!-- count:semgrep_plain_entries -->{plain_entries}<!-- /count --> plain `pattern`.",
        "",
        "## Per rule",
        "",
        'Findings (files with a finding). "Own" is the number of examples of the rule\'s own record '
        'that it flagged. "Either" is the scratch variant described at the end.',
        "",
        "| Rule | Record | Structure | Regexes | Third-party | Examples | Own | Either: third-party | Either: examples |",
        "|---|---|---|---|---|---|---|---|---|",
    ]

    def cell(d: dict) -> str:
        return f"{d['findings']} ({len(d['files'])})"

    for r in rules:
        lines.append(
            f"| `{r['id']}` | {r['ave_id'] or ''} | {LABELS[r['kind']].split(' (')[0]} | {r['regexes']} | "
            f"{cell(fired('as_written', 'third-party', r['id']))} | "
            f"{cell(fired('as_written', 'examples', r['id']))} | {own_examples(r)} | "
            f"{cell(fired('either', 'third-party', r['id']))} | "
            f"{cell(fired('either', 'examples', r['id']))} |"
        )
    lines += ["", "## Rules that fired on neither set, as written", ""]
    if never:
        lines += ["| Rule | Record | Structure |", "|---|---|---|"]
        lines += [
            f"| `{r['id']}` | {r['ave_id'] or ''} | {LABELS[r['kind']].split(' (')[0]} |"
            for r in never
        ]
    else:
        lines.append("None.")

    lines += ["", "## Public claims that count these rules", ""]
    claims = public_claims(Path(args.src))
    if claims:
        lines += [f"- `{path}:{number}`: {text}" for path, number, text in claims]
    else:
        lines.append("None found in `README.md` and `docs/`. Other repositories were not searched.")

    only = semgrep_only_records(Path(args.src), rules)
    lines += ["", "## Records whose only rule is a Semgrep rule", ""]
    if only is None:
        lines.append(
            "Not computed: the repository's counter (`scripts/sync_record_counts.py`) is not in `--src`."
        )
    else:
        lines += [
            "The README counts a record as having a detection rule when any rule cites it. This asks "
            "which records are cited by a Semgrep rule and by no pattern, YARA or Magika rule. "
            '"Fired" is on either set, as written.',
            "",
        ]
        if not only:
            lines.append(
                "None: every record that a Semgrep rule cites is also cited by a pattern, YARA or Magika "
                "rule, so the README's count of records with a detection rule does not rest on a "
                "Semgrep rule alone."
            )
        else:
            lines += ["| Record | Semgrep rules | Fired |", "|---|---|---|"]
            for item in only:
                fired_any = any(ever([r]) for r in rules if r["id"] in item["rules"])
                names = ", ".join(f"`{rid}`" for rid in item["rules"])
                lines.append(f"| {item['record']} | {names} | {'yes' if fired_any else 'no'} |")

    lines += [
        "",
        "## What this does not say",
        "",
        "- A rule that fired on a file fired on text that is in that file. This is not a rate of "
        "detection on real attacks, and a rule that never fired here may fire on text this run did "
        "not contain.",
        "- The examples are written by the AVE project, one sentence each, and the third-party "
        f"files are not skills. Of the {len(cited)} records that these rules cite, {len(cited & with_examples)} "
        "have at least one example.",
        "- One Semgrep version. Another version may read `patterns:` differently.",
        '- "Either" is a measurement in a scratch copy. It is not a proposal, and it is not a claim '
        "that the rule would be right if written that way.",
        "",
        "## Regenerate",
        "",
        "```text",
        "python3 -I scripts/semgrep_rule_firing.py measure --rules scanner/rules/semgrep/ave_rules.yaml \\",
        "    --corpus CORPUS.json --roots DIR [DIR ...] --work WORKDIR --out results.json",
        "python3 -I scripts/semgrep_rule_firing.py render --results results.json --src . --out report.md",
        "```",
        "",
    ]
    Path(args.out).write_text("\n".join(lines), encoding="utf-8")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)
    m = sub.add_parser("measure")
    m.add_argument("--rules", required=True)
    m.add_argument("--corpus", required=True)
    m.add_argument("--roots", nargs="+", required=True)
    m.add_argument("--work", required=True)
    m.add_argument("--out", required=True)
    r = sub.add_parser("render")
    r.add_argument("--results", required=True)
    r.add_argument("--src", required=True)
    r.add_argument("--out", required=True)
    args = ap.parse_args()
    return measure(args) if args.command == "measure" else render(args)


if __name__ == "__main__":
    raise SystemExit(main())
