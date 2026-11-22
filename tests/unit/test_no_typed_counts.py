"""
No rule or engine count is typed as prose in README.md or docs/**/*.md.

Issue #152. A count typed by hand drifts, and this is the third round: #120 and #121 generated
the README's record, rule and chain counts, and #145 found counts in the README and the docs
outside any marker that were wrong or typed by hand. `scripts/sync_record_counts.py --check`
guards only text inside `<!-- count:NAME -->` markers, so this test guards the rest.

A number is fine inside a marker, because the generator writes it and `--check` keeps it true.
Outside a marker, do one of these instead:

  - delete the number ("the engines", "all rules")
  - link to the live source (the generated README table, or `bawbel version`)
  - generate it: put it in a marker that `scripts/sync_record_counts.py` fills

Run: pytest tests/unit/test_no_typed_counts.py -q
"""

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# "Outside generator markers" means the way the generator itself reads a marker, so there is one
# definition of it. The generator is a script, not a package, so it is loaded by path.
_spec = importlib.util.spec_from_file_location(
    "sync_record_counts", ROOT / "scripts" / "sync_record_counts.py"
)
_generator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_generator)
MARKER = _generator.COUNT_RE

_WORDS = "one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve"
_RULE_KINDS = "regex|pattern|YARA|Semgrep|built-in|detection|structural|behavioral"

# What is flagged. Each is a number, then at most some adjectives, then the noun.
#   "40 regex rules", "15 rules", "40+ rules", "15 built-in pattern rules"
#   "six engines", "5 detection engines", "All 5 engines", "all five engines"
# The engine pattern takes the plural only, so "one engine" in "runs one engine of six" is fine.
PATTERNS = (
    ("a rule count", re.compile(rf"\b\d+\+?\s+(?:(?:{_RULE_KINDS})\s+)*rules?\b", re.IGNORECASE)),
    (
        "an engine count",
        re.compile(rf"\b(?:\d+|{_WORDS})\s+(?:(?:detection|analysis)\s+)?engines\b", re.IGNORECASE),
    ),
)

HOW_TO_FIX = (
    "Delete the number, link to the live source (the generated README table or `bawbel version`), "
    "or generate it with a count marker (scripts/sync_record_counts.py)."
)


def find_typed_counts(text: str) -> list[tuple[int, str, str]]:
    """(line, kind, text) for each rule or engine count in `text` that is not in a marker."""
    found = []
    # A marker sits on one line, so removing it keeps every line number.
    for number, line in enumerate(MARKER.sub("", text).split("\n"), start=1):
        for kind, pattern in PATTERNS:
            for match in pattern.finditer(line):
                found.append((number, kind, match.group(0)))
    return found


def guarded_files() -> list[Path]:
    return [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]


# ── The matcher ───────────────────────────────────────────────────────────────


class TestFlagged:
    @pytest.mark.parametrize(
        "text, kind",
        [
            ("| Pattern | 40 regex rules | Always on |", "a rule count"),
            ("The built-in engine runs 15 rules", "a rule count"),
            ("It loads 40+ rules", "a rule count"),
            ("15 built-in pattern rules cover these classes", "a rule count"),
            ("39 YARA rules", "a rule count"),
            ("41 Semgrep rules, one per record", "a rule count"),
            ("1 rule matched", "a rule count"),
            ("Six engines run across the pipeline.", "an engine count"),
            ("The pipeline has five detection engines.", "an engine count"),
            ("All 5 engines explained", "an engine count"),
            ("runs all five engines in turn", "an engine count"),
            ("Bawbel runs 6 analysis engines", "an engine count"),
            ("SIX ENGINES", "an engine count"),
        ],
    )
    def test_a_count_typed_as_prose(self, text, kind):
        found = find_typed_counts(text)
        assert found and found[0][1] == kind, text

    def test_it_reports_the_line_and_the_text(self):
        text = "# Title\n\nNothing here.\nIt has 40 regex rules and six engines.\n"
        assert find_typed_counts(text) == [
            (4, "a rule count", "40 regex rules"),
            (4, "an engine count", "six engines"),
        ]

    def test_a_count_outside_a_marker_is_flagged_even_with_a_marker_on_the_line(self):
        text = "<!-- count:yara_rules -->39<!-- /count --> YARA rules and 6 engines"
        assert find_typed_counts(text) == [(1, "an engine count", "6 engines")]


class TestAllowed:
    @pytest.mark.parametrize(
        "text",
        [
            # What the generator writes is kept true by --check.
            "| Pattern | <!-- count:pattern_rules -->40<!-- /count --> regex rules | Always on |",
            "<!-- count:yara_rules -->39<!-- /count --> rules and "
            "<!-- count:semgrep_rules -->41<!-- /count --> rules",
            # No count.
            "The engines run across the pipeline.",
            "Pattern rules are regular expressions.",
            "All rules cite AVE IDs.",
            "A core-only install runs one engine and prints the same result.",
            "No rule matched. This is not proof of anything.",
            "Add a rule to PATTERN_RULES, then run the writing-rules guide.",
            # A number that is not a count of rules or engines.
            "89 published records, 43 of them have a detection rule",
            "Python 3.10 or higher",
            "Step 2 of the rule guide, then step 3",
            "AVE-2026-00040 is cited by a rule",
            "exit code 3 when a named engine did not run",
        ],
    )
    def test_text_that_states_no_count(self, text):
        assert find_typed_counts(text) == [], text

    def test_an_unclosed_marker_hides_nothing_it_does_not_enclose(self):
        # Not a marker, because it has no closing comment, so the number is prose.
        assert find_typed_counts("<!-- count:x -->40 rules") == [(1, "a rule count", "40 rules")]


# ── The documents ─────────────────────────────────────────────────────────────


class TestTheDocuments:
    def test_the_guard_covers_the_readme_and_the_docs(self):
        files = [path.relative_to(ROOT).as_posix() for path in guarded_files()]
        assert "README.md" in files
        assert "docs/guides/engines.md" in files
        assert "docs/guides/getting-started.md" in files

    def test_no_rule_or_engine_count_is_typed_as_prose(self):
        problems = []
        for path in guarded_files():
            text = path.read_text(encoding="utf-8")
            for number, kind, snippet in find_typed_counts(text):
                problems.append(
                    f"{path.relative_to(ROOT).as_posix()}:{number}: {kind}: {snippet!r}"
                )
        assert not problems, (
            "A count typed as prose goes stale (issues #120, #145, #152).\n  "
            + "\n  ".join(problems)
            + f"\n{HOW_TO_FIX}"
        )
