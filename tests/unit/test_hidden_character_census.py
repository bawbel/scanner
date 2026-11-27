"""
scripts/hidden_character_census.py: where the hidden characters of the AVE_HomoglyphAttack rule occur
in ordinary text. Issue #212.

The census is standard library only. These tests check that it reads its characters from the rule
and not from a typed list, that each occurrence is put in the class the characters around it say,
that files are selected and counted as described, that the report prints counts and no file names,
and, when yara-python is installed, that the scan step sees what the scanner sees today.

Run: pytest tests/unit/test_hidden_character_census.py -q
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "hidden_character_census", ROOT / "scripts/hidden_character_census.py"
)
census = importlib.util.module_from_spec(spec)
sys.modules["hidden_character_census"] = census
spec.loader.exec_module(census)

ZWSP, ZWNJ, ZWJ, BOM, RLO = "​", "‌", "‍", "﻿", "‮"


# ── The characters come from the rule ─────────────────────────────────────────


def test_the_characters_are_read_from_the_hex_strings_of_the_rule():
    chars = census.rule_characters(ROOT)
    assert set(chars.values()) >= {ZWSP, ZWNJ, ZWJ, BOM, RLO}
    assert all(len(c) == 1 for c in chars.values())
    assert chars["U+200B"] == ZWSP


def test_a_rule_file_without_the_rule_is_an_error(tmp_path):
    (tmp_path / "scanner/rules/yara").mkdir(parents=True)
    (tmp_path / "scanner/rules/yara/ave_rules.yar").write_text("rule Other {}\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        census.rule_characters(tmp_path)


# ── Classes ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,index,expected",
    [
        (BOM + "# Title", 0, "bom-at-start"),
        ("text " + BOM + "more", 5, "bom-inside"),
        ("ig" + ZWSP + "nore", 2, "inside-ascii-word"),
        ("a1" + ZWNJ + "b2", 2, "inside-ascii-word"),
        ("\U0001f468" + ZWJ + "\U0001f469", 1, "joiner-in-emoji"),
        ("❤️" + ZWJ + "\U0001f525", 2, "joiner-in-emoji"),
        ("می" + ZWNJ + "خواهم", 2, "joiner-in-script"),
        ("क" + ZWJ + "ष", 1, "joiner-in-script"),
        ("text " + RLO + "gnp.exe", 5, "bidi-control"),
        ("end" + ZWSP + " ", 3, "other"),
        (" " + ZWSP + " ", 1, "other"),
    ],
)
def test_each_occurrence_is_put_in_the_class_its_neighbours_say(text, index, expected):
    assert census.classify(text, index) == expected


def test_census_text_counts_per_character_and_per_class():
    chars = census.rule_characters(ROOT)
    found = census.census_text("ig" + ZWSP + "nore " + BOM + " end" + ZWSP, chars)
    assert found["by_char"] == {"U+200B": 2, "U+FEFF": 1}
    assert found["by_class"] == {"inside-ascii-word": 1, "bom-inside": 1, "other": 1}


# ── Files ─────────────────────────────────────────────────────────────────────


def test_files_are_selected_by_extension_and_size_and_skip_directories(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.md").write_text("x", encoding="utf-8")
    (tmp_path / "a.md").write_text("x", encoding="utf-8")
    (tmp_path / "b.JSON").write_text("{}", encoding="utf-8")
    (tmp_path / "c.py").write_text("x", encoding="utf-8")
    (tmp_path / "big.txt").write_bytes(b"x" * (census.MAX_BYTES + 1))
    names = sorted(p.name for p in census.select_files([str(tmp_path)]))
    assert names == ["a.md", "b.JSON"]


def test_summary_counts_a_file_once_and_by_option(tmp_path):
    chars = census.rule_characters(ROOT)
    files = {
        "plain.md": "nothing here",
        "bom.md": BOM + "# Title",
        "emoji.md": "\U0001f468" + ZWJ + "\U0001f469" * 3 + ZWJ + "\U0001f466",
        "split.md": "ig" + ZWSP + "nore",
        "boundary.md": "word" + ZWSP + " next",
    }
    paths = []
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
        paths.append(tmp_path / name)
    summary, holders = census.summarise(paths, chars)
    assert summary["files"] == 5 and summary["files_with_a_listed_character"] == 4
    assert sorted(p.name for p in holders) == ["bom.md", "boundary.md", "emoji.md", "split.md"]
    assert summary["would_flag_any_listed_character"] == 4
    assert summary["would_flag_outside_the_three_benign_looking_classes"] == 2
    assert summary["would_flag_inside_ascii_word_only"] == 1
    assert summary["files_by_class"]["bom-at-start"] == 1


def test_a_file_that_cannot_be_read_is_not_counted(tmp_path):
    chars = census.rule_characters(ROOT)
    summary, _ = census.summarise([tmp_path / "missing.md"], chars)
    assert summary["files"] == 0


# ── The scan step and the report ──────────────────────────────────────────────


def test_the_scan_step_sees_a_skill_named_file_and_not_a_note(tmp_path):
    pytest.importorskip("yara")
    holder = tmp_path / "x.md"
    holder.write_text("Open the file" + ZWSP + "name now.\n", encoding="utf-8")
    work = tmp_path / "work"
    work.mkdir()
    result = census.scan_copies(ROOT, [holder], work)
    assert result["flagged"] == {"SKILL.md": 1, "notes.md": 0}
    assert "yara" in result["engines_run"]


def test_measure_and_render_print_counts_and_no_file_names(tmp_path):
    chars = census.rule_characters(ROOT)
    assert chars
    third = tmp_path / "third"
    third.mkdir()
    (third / "secret-name-one.md").write_text("ig" + ZWSP + "nore", encoding="utf-8")
    (third / "other.txt").write_text("plain", encoding="utf-8")
    own = tmp_path / "own"
    own.mkdir()
    (own / "private-instructions.md").write_text("plain", encoding="utf-8")
    listing = tmp_path / "list.txt"
    listing.write_text(str(own / "private-instructions.md") + "\n", encoding="utf-8")

    class Args:
        pass

    a = Args()
    a.src, a.roots, a.files_from, a.scan = str(ROOT), [str(third)], str(listing), False
    a.work, a.out = str(tmp_path / "work"), str(tmp_path / "results.json")
    assert census.measure(a) == 0
    data = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert data["sets"]["third-party"]["files_with_a_listed_character"] == 1
    assert data["sets"]["own-instruction"]["files"] == 1

    b = Args()
    b.results, b.out = str(tmp_path / "results.json"), str(tmp_path / "report.md")
    assert census.render(b) == 0
    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "secret-name-one" not in report and "private-instructions" not in report
    assert "| inside-ascii-word | 1 | 1 |" in report
    for word in ("better", "best", "worse", "winner", "safe", "secure"):
        assert word not in report.lower(), word
    assert "—" not in report
