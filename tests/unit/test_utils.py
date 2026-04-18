"""
Unit tests for scanner/utils.py

Tests each utility class independently.
"""

import pytest
from pathlib import Path

from scanner.utils import (
    Logger,
    PathValidator,
    FileReader,
    SubprocessRunner,
    JsonParser,
    TextSanitiser,
    Timer,
    # function aliases
    get_logger,
    resolve_path,
    is_safe_path,
    read_file_safe,
    parse_json_safe,
    parse_severity,
    parse_cvss,
    truncate_match,
)


class TestLogger:
    def test_get_returns_logger(self):
        log = Logger.get("test")
        assert log is not None

    def test_get_logger_alias_works(self):
        log = get_logger("test")
        assert log is not None

    def test_namespaced_under_bawbel(self):
        import logging
        log = Logger.get("mymodule")
        assert log.name == "bawbel.mymodule"

    def test_same_name_returns_same_instance(self):
        a = Logger.get("same")
        b = Logger.get("same")
        assert a is b


class TestPathValidator:
    def test_resolve_valid_path(self, tmp_path):
        f = tmp_path / "skill.md"
        f.write_text("content")
        path, err = PathValidator.resolve(str(f))
        assert err is None
        assert path is not None
        assert path.is_absolute()

    def test_resolve_rejects_symlink(self, tmp_path):
        real = tmp_path / "real.md"
        real.write_text("content")
        link = tmp_path / "link.md"
        link.symlink_to(real)
        path, err = PathValidator.resolve(str(link))
        assert path is None
        assert "E005" in err

    def test_resolve_invalid_path_string(self):
        path, err = PathValidator.resolve("\x00invalid")
        assert path is None
        assert err is not None

    def test_resolve_alias_works(self, tmp_path):
        f = tmp_path / "skill.md"
        f.write_text("content")
        path, err = resolve_path(str(f))
        assert err is None

    def test_validate_valid_file(self, tmp_path):
        f = tmp_path / "skill.md"
        f.write_text("content")
        path = f.resolve()
        ok, err = PathValidator.validate(path)
        assert ok is True
        assert err is None

    def test_validate_missing_file(self, tmp_path):
        path = (tmp_path / "missing.md").resolve()
        ok, err = PathValidator.validate(path)
        assert ok is False
        assert "E003" in err

    def test_validate_directory(self, tmp_path):
        ok, err = PathValidator.validate(tmp_path.resolve())
        assert ok is False
        assert "E004" in err

    def test_validate_oversized_file(self, tmp_path, monkeypatch):
        f = tmp_path / "big.md"
        f.write_text("x")
        monkeypatch.setattr(
            "config.default.MAX_FILE_SIZE_BYTES", 0
        )
        ok, err = PathValidator.validate(f.resolve())
        assert ok is False
        assert "E006" in err

    def test_is_safe_path_alias_works(self, tmp_path):
        f = tmp_path / "skill.md"
        f.write_text("content")
        ok, err = is_safe_path(f.resolve())
        assert ok is True


class TestFileReader:
    def test_reads_text_file(self, tmp_path):
        f = tmp_path / "skill.md"
        f.write_text("hello world")
        content, err = FileReader.read_text(f)
        assert err is None
        assert content == "hello world"

    def test_handles_invalid_utf8(self, tmp_path):
        f = tmp_path / "binary.md"
        f.write_bytes(b"valid\xff\xfeinvalid")
        content, err = FileReader.read_text(f)
        assert err is None     # errors="ignore" — should not fail
        assert content is not None

    def test_read_file_safe_alias(self, tmp_path):
        f = tmp_path / "skill.md"
        f.write_text("content")
        content, err = read_file_safe(f)
        assert err is None
        assert content == "content"


class TestJsonParser:
    def test_parses_valid_json(self):
        data, err = JsonParser.parse('{"results": []}')
        assert err is None
        assert data == {"results": []}

    def test_returns_none_none_for_empty(self):
        data, err = JsonParser.parse("")
        assert data is None
        assert err is None

    def test_returns_error_for_invalid_json(self):
        data, err = JsonParser.parse("{invalid json}")
        assert data is None
        assert err is not None

    def test_parse_json_safe_alias(self):
        data, err = parse_json_safe('{"key": "value"}')
        assert err is None
        assert data == {"key": "value"}


class TestTextSanitiser:
    def test_truncate_none_returns_none(self):
        assert TextSanitiser.truncate(None, 80) is None

    def test_truncate_short_string_unchanged(self):
        assert TextSanitiser.truncate("hello", 80) == "hello"

    def test_truncate_long_string(self):
        result = TextSanitiser.truncate("x" * 200, 80)
        assert len(result) == 80

    def test_truncate_strips_whitespace(self):
        result = TextSanitiser.truncate("  hello  ", 80)
        assert result == "hello"

    def test_truncate_match_alias(self):
        assert truncate_match("hello", 80) == "hello"
        assert truncate_match(None, 80) is None

    def test_parse_severity_valid(self):
        assert TextSanitiser.parse_severity("HIGH")     == "HIGH"
        assert TextSanitiser.parse_severity("critical")  == "CRITICAL"
        assert TextSanitiser.parse_severity("medium")    == "MEDIUM"

    def test_parse_severity_invalid_returns_fallback(self):
        assert TextSanitiser.parse_severity("UNKNOWN") == "HIGH"
        assert TextSanitiser.parse_severity("")         == "HIGH"

    def test_parse_severity_alias(self):
        assert parse_severity("HIGH") == "HIGH"

    def test_parse_cvss_valid_float(self):
        assert TextSanitiser.parse_cvss(9.4)   == 9.4
        assert TextSanitiser.parse_cvss("7.5") == 7.5

    def test_parse_cvss_clamped(self):
        assert TextSanitiser.parse_cvss(99.9)  == 10.0
        assert TextSanitiser.parse_cvss(-1.0)  == 0.0

    def test_parse_cvss_invalid_returns_fallback(self):
        assert TextSanitiser.parse_cvss("bad") == 5.0
        assert TextSanitiser.parse_cvss(None)  == 5.0

    def test_parse_cvss_alias(self):
        assert parse_cvss(8.0) == 8.0


class TestTimer:
    def test_measures_elapsed_time(self):
        import time
        with Timer() as t:
            time.sleep(0.01)
        assert t.elapsed_ms >= 10

    def test_elapsed_ms_is_int(self):
        with Timer() as t:
            pass
        assert isinstance(t.elapsed_ms, int)

    def test_zero_elapsed_on_no_work(self):
        with Timer() as t:
            pass
        assert t.elapsed_ms >= 0
