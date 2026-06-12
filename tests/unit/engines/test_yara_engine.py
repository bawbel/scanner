"""
Unit tests for scanner/engines/yara_engine.py

Tests error paths: missing rules file, temp file OSError, YARA compile errors.
"""

import sys
from unittest.mock import MagicMock, patch

from scanner.engines.yara_engine import run_yara_scan


def _make_mock_yara(compile_side_effect=None):
    """Create a mock yara module with a real SyntaxError class."""
    mock = MagicMock()
    mock.SyntaxError = type("SyntaxError", (Exception,), {})
    if compile_side_effect is not None:
        mock.compile.side_effect = compile_side_effect
    return mock


class TestRunYaraScanMissingRules:

    def test_missing_rules_file_returns_empty(self, tmp_path):
        """If YARA_RULES_PATH does not exist, skip silently and return []."""
        f = tmp_path / "skill.md"
        f.write_text("content")
        mock_yara = _make_mock_yara()
        nonexistent = tmp_path / "nonexistent.yar"
        with (
            patch.dict(sys.modules, {"yara": mock_yara}),
            patch("scanner.engines.yara_engine.YARA_RULES_PATH", nonexistent),
        ):
            result = run_yara_scan(str(f))
        assert result == []
        mock_yara.compile.assert_not_called()


class TestRunYaraScanTempFileError:

    def test_oserror_on_temp_write_falls_back_to_original(self, tmp_path):
        """OSError writing stripped_content to temp file → scan original file."""
        f = tmp_path / "skill.md"
        f.write_text("safe content")
        mock_yara = _make_mock_yara()
        mock_rules = MagicMock()
        mock_rules.match.return_value = []
        mock_yara.compile.return_value = mock_rules

        with (
            patch.dict(sys.modules, {"yara": mock_yara}),
            patch("tempfile.mkstemp", side_effect=OSError("disk full")),
        ):
            result = run_yara_scan(str(f), stripped_content="stripped")

        assert result == []
        # compile was still called (fell back to original path)
        mock_yara.compile.assert_called_once()


class TestRunYaraScanCompileErrors:

    def test_yara_syntax_error_returns_empty(self, tmp_path):
        """yara.SyntaxError during compile → log error, return []."""
        f = tmp_path / "skill.md"
        f.write_text("content")
        mock_yara = _make_mock_yara()
        mock_yara.compile.side_effect = mock_yara.SyntaxError("bad rule syntax")

        with patch.dict(sys.modules, {"yara": mock_yara}):
            result = run_yara_scan(str(f))

        assert result == []

    def test_yara_syntax_error_with_temp_file_cleans_up(self, tmp_path):
        """Temp file is cleaned up when SyntaxError occurs during compile."""
        f = tmp_path / "skill.md"
        f.write_text("content")
        mock_yara = _make_mock_yara()
        mock_yara.compile.side_effect = mock_yara.SyntaxError("bad rule syntax")

        with patch.dict(sys.modules, {"yara": mock_yara}):
            result = run_yara_scan(str(f), stripped_content="stripped content")

        assert result == []

    def test_general_exception_returns_empty(self, tmp_path):
        """Unexpected exception during compile → log error, return []."""
        f = tmp_path / "skill.md"
        f.write_text("content")
        mock_yara = _make_mock_yara(compile_side_effect=RuntimeError("unexpected failure"))

        with patch.dict(sys.modules, {"yara": mock_yara}):
            result = run_yara_scan(str(f))

        assert result == []

    def test_general_exception_with_temp_file_cleans_up(self, tmp_path):
        """Temp file is cleaned up when a general exception occurs."""
        f = tmp_path / "skill.md"
        f.write_text("content")
        mock_yara = _make_mock_yara(compile_side_effect=RuntimeError("io error"))

        with patch.dict(sys.modules, {"yara": mock_yara}):
            result = run_yara_scan(str(f), stripped_content="stripped content")

        assert result == []
