"""
scripts/yara_rule_firing.py: how many files each YARA rule matches. Issue #216.

The script is the measurement behind the before and after counts of the YARA condition fixes. These
tests use a tiny rule and tiny files: files are selected by extension and size, a file is counted
once per rule, the examples split into those of the rule's own record and of other records, and the
table is printed. Skipped when yara-python is not installed.

Run: pytest tests/unit/test_yara_rule_firing.py -q
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

yara = pytest.importorskip("yara")

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "yara_rule_firing", ROOT / "scripts/yara_rule_firing.py"
)
firing = importlib.util.module_from_spec(spec)
sys.modules["yara_rule_firing"] = firing
spec.loader.exec_module(firing)

RULE = """rule Alpha
{
    meta:
        ave_id = "AVE-2026-00001"
    strings:
        $a = "alpha" nocase
    condition:
        $a
}
rule Beta
{
    meta:
        ave_id = "AVE-2026-00002"
    strings:
        $b = "beta"
    condition:
        $b
}
"""


@pytest.fixture
def rules():
    return yara.compile(source=RULE)


def test_files_are_selected_by_extension_and_size_and_skip_directories(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.md").write_text("alpha", encoding="utf-8")
    (tmp_path / "a.md").write_text("alpha", encoding="utf-8")
    (tmp_path / "b.JSON").write_text("{}", encoding="utf-8")
    (tmp_path / "c.py").write_text("alpha", encoding="utf-8")
    (tmp_path / "big.txt").write_bytes(b"x" * (firing.MAX_BYTES + 1))
    assert sorted(p.name for p in firing.select_files([str(tmp_path)])) == ["a.md", "b.JSON"]


def test_a_file_is_counted_once_per_rule(rules, tmp_path):
    (tmp_path / "one.md").write_text("alpha ALPHA alpha", encoding="utf-8")
    (tmp_path / "two.md").write_text("alpha and beta", encoding="utf-8")
    (tmp_path / "three.md").write_text("nothing", encoding="utf-8")
    read, counts = firing.count_files(rules, firing.select_files([str(tmp_path)]))
    assert read == 3 and counts == {"Alpha": 2, "Beta": 1}


def test_a_missing_file_is_not_counted(rules, tmp_path):
    read, counts = firing.count_files(rules, [tmp_path / "missing.md"])
    assert read == 0 and counts == {}


def test_examples_split_into_the_rules_own_record_and_the_others(rules):
    corpus = [
        {"ave_id": "AVE-2026-00001", "status": "active", "example_patterns": ["alpha one", "beta"]},
        {"ave_id": "AVE-2026-00002", "status": "active", "example_patterns": ["alpha two"]},
        {"ave_id": "AVE-2026-00003", "status": "rejected", "example_patterns": ["alpha"]},
        {"ave_id": "AVE-2026-00004", "status": "active"},
    ]
    total, counts = firing.count_examples(rules, corpus)
    assert total == 3
    assert counts == {"Alpha": [2, 1], "Beta": [1, 0]}


def test_main_prints_a_table_with_the_named_rules(rules, tmp_path, capsys, monkeypatch):
    yara_file = tmp_path / "rules.yar"
    yara_file.write_text(RULE, encoding="utf-8")
    corpus = tmp_path / "corpus.json"
    corpus.write_text(
        json.dumps(
            [{"ave_id": "AVE-2026-00001", "status": "active", "example_patterns": ["alpha"]}]
        ),
        encoding="utf-8",
    )
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.md").write_text("alpha", encoding="utf-8")
    argv = ["prog", "--yara-file", str(yara_file), "--corpus", str(corpus), "--roots", str(root)]
    monkeypatch.setattr(sys, "argv", argv + ["--rules", "Alpha"])
    assert firing.main() == 0
    out = capsys.readouterr().out
    assert "files: third-party 1, own 0, examples 1" in out
    row = next(line for line in out.splitlines() if line.startswith("Alpha"))
    assert row.split() == ["Alpha", "1", "0", "1", "1"]
    assert "Beta" not in out
