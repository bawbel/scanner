"""
No-findings output never gives a verdict.
Issue #118: the scanner printed "CLEAN", "passed all AVE checks", and "It is safe to install
and use" when no rule matched. No match proves nothing: only some engines run, and only some
AVE records have a detection engine.

Run: pytest tests/unit/test_no_findings_wording.py -q
"""

import json
import re

import pytest
from click.testing import CliRunner

from scanner.cli import cli
from scanner.config import EXIT_CODE_CLEAN
from scanner.messages import Info

BENIGN = "# Notes\n\nThis skill formats a date as ISO 8601.\n"

# Words that read as a verdict. "safe" is allowed only inside "not proof ... safe" and
# "not a safety verdict", so it is checked separately.
VERDICT_WORDS = re.compile(r"\bCLEAN\b|passed|cleared|No vulnerabilities", re.IGNORECASE)


@pytest.fixture
def benign_file(tmp_path):
    p = tmp_path / "skill.md"
    p.write_text(BENIGN, encoding="utf-8")
    return p


def _run(args):
    result = CliRunner().invoke(cli, args)
    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    return result


def _assert_no_verdict(output: str) -> None:
    assert not VERDICT_WORDS.search(output), output
    assert "safe to install" not in output.lower(), output
    for line in output.splitlines():
        if "safe" in line.lower():
            assert "not proof" in line or "not a safety verdict" in line, line


class TestInfoStrings:
    def test_strings_make_no_claim(self):
        for s in (Info.CLEAN_COMPONENT, Info.CLEAN_DESCRIPTION, Info.CLEAN_RISK_SCORE):
            _assert_no_verdict(s)

    def test_risk_line_says_it_is_not_a_verdict(self):
        assert Info.CLEAN_RISK_SCORE.startswith("0.0 / 10")
        assert "not a safety verdict" in Info.CLEAN_RISK_SCORE


class TestScanOutput:
    def test_single_file(self, benign_file):
        result = _run(["scan", str(benign_file)])
        assert result.exit_code == EXIT_CODE_CLEAN
        assert Info.CLEAN_COMPONENT in result.output
        assert Info.CLEAN_DESCRIPTION in result.output
        assert Info.CLEAN_RISK_SCORE in result.output
        _assert_no_verdict(result.output)

    def test_directory(self, benign_file):
        result = _run(["scan", str(benign_file.parent), "--recursive"])
        assert result.exit_code == EXIT_CODE_CLEAN
        assert Info.CLEAN_COMPONENT in result.output
        _assert_no_verdict(result.output)

    def test_json_contract_unchanged(self, benign_file):
        result = _run(["scan", str(benign_file), "--format", "json"])
        assert result.exit_code == EXIT_CODE_CLEAN
        data = json.loads(result.output)
        record = data[0] if isinstance(data, list) else data
        assert record["findings"] == []
        assert record["risk_score"] == 0.0


class TestReportOutput:
    def test_report(self, benign_file):
        result = _run(["report", str(benign_file)])
        assert result.exit_code == EXIT_CODE_CLEAN
        assert Info.CLEAN_COMPONENT in result.output
        assert Info.CLEAN_RISK_SCORE in result.output
        _assert_no_verdict(result.output)
