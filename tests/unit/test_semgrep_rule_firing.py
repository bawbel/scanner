"""
scripts/semgrep_rule_firing.py: which Semgrep rules ever fire. Issue #210.

The script runs the `semgrep` command line on two sets of files and counts findings per rule. These
tests do not need Semgrep: the plumbing is run with a stand-in `semgrep` that prints a fixed result.
What they check:

  - the rules file is read the way the repository's own counter reads it, and each rule is put in
    the right structure: one regex, all of several (`patterns:`), or any of several (`pattern-either:`)
  - the "either" copy changes exactly the rules that list several regexes under `patterns:`
  - the two sets are built from the right files: only active records with examples, flat names,
    nothing over the size limit, and a failed copy leaves no file behind
  - findings are counted per rule whatever path prefix Semgrep puts on a rule id
  - records cited only by a Semgrep rule are found with the repository's own counter
  - the report names the rules that never fired, carries the count markers, and ranks nothing

Run: pytest tests/unit/test_semgrep_rule_firing.py -q
"""

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "scanner/rules/semgrep/ave_rules.yaml"


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


firing = load("semgrep_rule_firing", "scripts/semgrep_rule_firing.py")

SAMPLE = """rules:
  - id: one-regex
    pattern-regex: '(?i)alpha'
    message: "AVE-2026-00001: one"
    languages: [generic]
    severity: ERROR
    metadata:
      ave_id: AVE-2026-00001

  - id: all-of
    patterns:
      - pattern-regex: '(?i)beta'
      - pattern-regex: '(?i)gamma'
    message: "AVE-2026-00002: two"
    languages: [generic]
    severity: ERROR
    metadata:
      ave_id: AVE-2026-00002

  - id: one-under-patterns
    patterns:
      - pattern-regex: '(?i)delta'
    message: "AVE-2026-00003: three"
    languages: [generic]
    severity: ERROR
    metadata:
      ave_id: AVE-2026-00003

  - id: any-of
    pattern-either:
      - pattern-regex: '(?i)epsilon'
      - pattern-regex: '(?i)zeta'
    message: "AVE-2026-00004: four"
    languages: [generic]
    severity: ERROR
    metadata:
      ave_id: AVE-2026-00004
"""


# ── Reading the rules file ────────────────────────────────────────────────────


def test_each_rule_is_put_in_its_structure():
    rules = {r["id"]: r for r in firing.parse_rules(SAMPLE)}
    assert {k: v["kind"] for k, v in rules.items()} == {
        "one-regex": "single",
        "all-of": "all-of",
        "one-under-patterns": "single",
        "any-of": "either",
    }
    assert rules["all-of"]["regexes"] == 2 and rules["all-of"]["ave_id"] == "AVE-2026-00002"
    assert all(r["generic"] for r in rules.values())


def test_the_real_rules_file_has_the_number_of_rules_the_repository_counts():
    sync = load("sync_record_counts_for_firing_test", "scripts/sync_record_counts.py")
    counted, _ = sync.semgrep_rules(ROOT)
    rules = firing.parse_rules(RULES.read_text(encoding="utf-8"))
    assert len(rules) == counted
    assert all(r["ave_id"] for r in rules)


def test_the_either_copy_changes_exactly_the_all_of_rules():
    changed = firing.either_variant(SAMPLE)
    kinds = {r["id"]: r["kind"] for r in firing.parse_rules(changed)}
    assert kinds == {
        "one-regex": "single",
        "all-of": "either",
        "one-under-patterns": "single",
        "any-of": "either",
    }
    assert "patterns:\n      - pattern-regex: '(?i)delta'" in changed  # one regex: left alone
    assert changed.count("pattern-either:") == 2


def test_the_either_copy_of_the_real_file_changes_only_the_all_of_rules():
    text = RULES.read_text(encoding="utf-8")
    before = {r["id"]: r["kind"] for r in firing.parse_rules(text)}
    after = {r["id"]: r["kind"] for r in firing.parse_rules(firing.either_variant(text))}
    assert before.keys() == after.keys()
    for rule_id, kind in before.items():
        assert after[rule_id] == ("either" if kind == "all-of" else kind), rule_id


# ── The two sets ──────────────────────────────────────────────────────────────


def test_the_examples_come_only_from_active_records_that_have_examples(tmp_path):
    corpus = [
        {"ave_id": "AVE-2026-00002", "status": "active", "example_patterns": ["one", "two"]},
        {"ave_id": "AVE-2026-00001", "status": "active", "example_patterns": ["zero"]},
        {"ave_id": "AVE-2026-00003", "status": "rejected", "example_patterns": ["no"]},
        {"ave_id": "AVE-2026-00004", "status": "active"},
        {"ave_id": "AVE-2026-00005", "status": "active", "example_patterns": "not a list"},
    ]
    built = firing.build_examples(corpus, tmp_path / "examples")
    assert [f["fixture"] for f in built["fixtures"]] == [
        "ave-2026-00001-0",
        "ave-2026-00002-0",
        "ave-2026-00002-1",
    ]
    text = (tmp_path / "examples" / "ave-2026-00002-1.md").read_text(encoding="utf-8")
    assert text.endswith("two\n") and text.startswith("---\nname: ave-2026-00002-1\n")


def test_the_third_party_set_keeps_text_files_under_the_limit_with_flat_names(tmp_path):
    root = tmp_path / "root"
    (root / "a" / "node_modules").mkdir(parents=True)
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "one.MD").write_text("x", encoding="utf-8")
    (root / "a" / "b" / "two.json").write_text("{}", encoding="utf-8")
    (root / "a" / "b" / "code.py").write_text("print(1)", encoding="utf-8")
    (root / "a" / "node_modules" / "skip.md").write_text("x", encoding="utf-8")
    (root / "big.txt").write_bytes(b"x" * (firing.MAX_BYTES + 1))
    built = firing.build_third_party([str(root)], tmp_path / "third")
    names = sorted(p.name for p in (tmp_path / "third").iterdir())
    assert built == {"files": 2, "by_extension": {".json": 1, ".md": 1}}
    assert names == ["f00001.md", "f00002.json"]


@pytest.mark.skipif(sys.platform == "win32", reason="file modes work differently on Windows")
def test_a_file_that_cannot_be_copied_leaves_nothing_behind(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.md").write_text("a", encoding="utf-8")
    unreadable = root / "b.md"
    unreadable.write_text("b", encoding="utf-8")
    (root / "c.md").write_text("c", encoding="utf-8")
    unreadable.chmod(0)
    blocked = not os.access(unreadable, os.R_OK)  # false when the tests run as root
    try:
        built = firing.build_third_party([str(root)], tmp_path / "third")
    finally:
        unreadable.chmod(stat.S_IRUSR | stat.S_IWUSR)
    names = sorted(p.name for p in (tmp_path / "third").iterdir())
    expected = 2 if blocked else 3
    assert built["files"] == expected
    assert names == [f"f{n:05d}.md" for n in range(1, expected + 1)]  # no gap, no partial file
    assert all(p.stat().st_size == 1 for p in (tmp_path / "third").iterdir())


# ── Counting ──────────────────────────────────────────────────────────────────


def test_findings_are_counted_per_rule_whatever_the_path_prefix(tmp_path):
    rules = firing.parse_rules(SAMPLE)
    data = {
        "results": [
            {"check_id": "some.dir.scanner.rules.semgrep.all-of", "path": "/x/f1.md"},
            {"check_id": "all-of", "path": "/x/f1.md"},
            {"check_id": "x.one-regex", "path": "/x/f2.md"},
            {"check_id": "x.not-a-rule", "path": "/x/f3.md"},
        ]
    }
    counted = firing.count_rules(data, rules, tmp_path)
    assert counted["all-of"] == {"findings": 2, "files": ["f1.md"]}
    assert counted["one-regex"] == {"findings": 1, "files": ["f2.md"]}
    assert counted["any-of"] == {"findings": 0, "files": []}


# ── Records whose only rule is a Semgrep rule ─────────────────────────────────


def test_records_cited_only_by_a_semgrep_rule_are_found_with_the_repositorys_own_counter():
    rules = firing.parse_rules(RULES.read_text(encoding="utf-8"))
    only = firing.semgrep_only_records(ROOT, rules)
    sync = load("sync_record_counts_for_only", "scripts/sync_record_counts.py")
    _, pattern_ids = sync.pattern_rules(ROOT)
    _, yara_ids = sync.yara_rules(ROOT)
    _, semgrep_ids = sync.semgrep_rules(ROOT)
    expected = semgrep_ids - pattern_ids - yara_ids - sync.magika_ids(ROOT)
    assert [o["record"] for o in only] == sorted(expected)
    assert all(o["rules"] for o in only)


def test_without_the_repositorys_counter_the_records_are_not_computed(tmp_path):
    assert firing.semgrep_only_records(tmp_path, []) is None


# ── The whole plumbing, with a stand-in for semgrep ───────────────────────────

STAND_IN = """#!/bin/sh
case "$1" in
  --version) echo "9.9.9"; exit 0 ;;
esac
# the target is the last argument; the second argument is the rules file
for last; do :; done
case "$2" in
  *either.yaml) VARIANT=either ;;
  *) VARIANT=written ;;
esac
case "$last" in
  */examples)
    if [ "$VARIANT" = either ]; then
      echo '{"results":[{"check_id":"tmp.one-regex","path":"/w/examples/ave-2026-00001-0.md"},{"check_id":"tmp.all-of","path":"/w/examples/ave-2026-00002-0.md"}],"errors":[],"paths":{"scanned":["a","b"]}}'
    else
      echo '{"results":[{"check_id":"tmp.one-regex","path":"/w/examples/ave-2026-00001-0.md"}],"errors":[],"paths":{"scanned":["a","b"]}}'
    fi ;;
  *)
    if [ "$VARIANT" = either ]; then
      echo '{"results":[{"check_id":"tmp.all-of","path":"/w/third-party/f00001.md"},{"check_id":"tmp.all-of","path":"/w/third-party/f00001.md"}],"errors":[],"paths":{"scanned":["a"]}}'
    else
      echo '{"results":[],"errors":[],"paths":{"scanned":["a"]}}'
    fi ;;
esac
"""


@pytest.mark.skipif(sys.platform == "win32", reason="the stand-in is a shell script")
def test_measure_and_render_with_a_stand_in(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    tool = bin_dir / "semgrep"
    tool.write_text(STAND_IN, encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")

    rules = tmp_path / "rules.yaml"
    rules.write_text(SAMPLE, encoding="utf-8")
    corpus = tmp_path / "corpus.json"
    corpus.write_text(
        json.dumps(
            [
                {"ave_id": "AVE-2026-00001", "status": "active", "example_patterns": ["alpha"]},
                {
                    "ave_id": "AVE-2026-00002",
                    "status": "active",
                    "example_patterns": ["beta gamma"],
                },
            ]
        ),
        encoding="utf-8",
    )
    root = tmp_path / "third"
    root.mkdir()
    (root / "t.md").write_text("text", encoding="utf-8")
    results = tmp_path / "results.json"
    out = tmp_path / "report.md"
    src = tmp_path / "src"
    (src / "docs").mkdir(parents=True)
    (src / "README.md").write_text(
        "The scanner has Semgrep rules for AVE records.\n", encoding="utf-8"
    )

    class Args:
        pass

    a = Args()
    a.rules, a.corpus, a.roots = str(rules), str(corpus), [str(root)]
    a.work, a.out = str(tmp_path / "w"), str(results)
    assert firing.measure(a) == 0
    data = json.loads(results.read_text(encoding="utf-8"))
    assert data["semgrep_version"] == "9.9.9"
    assert data["runs"]["as_written/examples"]["per_rule"]["one-regex"]["findings"] == 1
    assert data["runs"]["either/examples"]["per_rule"]["all-of"]["findings"] == 1
    assert data["runs"]["either/third-party"]["per_rule"]["all-of"] == {
        "findings": 2,
        "files": ["f00001.md"],
    }

    b = Args()
    b.results, b.src, b.out = str(results), str(src), str(out)
    assert firing.render(b) == 0
    report = out.read_text(encoding="utf-8")
    assert "<!-- count:semgrep_rules -->4<!-- /count -->" in report
    assert "<!-- count:semgrep_all_of_rules -->1<!-- /count -->" in report
    never = report.split("## Rules that fired on neither set, as written")[1].split("##")[0]
    assert "`all-of`" in never and "`any-of`" in never and "`one-regex`" not in never
    assert "`README.md:1`" in report
    assert "Not computed: the repository's counter" in report
    for word in ("better", "best", "worse", "rank", "winner", "beats", "safe", "secure"):
        assert word not in report.lower().replace("never fired", ""), word
    assert chr(0x2014) not in report
