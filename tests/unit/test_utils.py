"""
Unit tests for scanner.utils
"""

from scanner.utils import (
    resolve_path,
    is_safe_path,
    read_file_safe,
    parse_json_safe,
    parse_severity,
    parse_cvss,
    truncate_match,
    get_logger,
    Timer,
)


class TestResolvedPath:

    def test_valid_path_returns_path(self, tmp_path):
        f = tmp_path / "skill.md"
        f.write_text("content")
        path, err = resolve_path(str(f))
        assert err is None
        assert path is not None
        assert path.is_absolute()

    def test_symlink_rejected(self, tmp_path):
        real = tmp_path / "real.md"
        real.write_text("content")
        link = tmp_path / "link.md"
        link.symlink_to(real)
        path, err = resolve_path(str(link))
        assert path is None
        assert err is not None
        assert "symlink" in err.lower()

    def test_invalid_path_returns_error(self):
        path, err = resolve_path("\x00invalid")
        assert path is None
        assert err is not None


class TestIsSafePath:

    def test_valid_file_is_safe(self, tmp_path):
        f = tmp_path / "skill.md"
        f.write_text("content")
        ok, err = is_safe_path(f)
        assert ok is True
        assert err is None

    def test_nonexistent_file_not_safe(self, tmp_path):
        f = tmp_path / "nonexistent.md"
        ok, err = is_safe_path(f)
        assert ok is False
        assert err is not None

    def test_directory_not_safe(self, tmp_path):
        ok, err = is_safe_path(tmp_path)
        assert ok is False
        assert err is not None


class TestReadFileSafe:

    def test_reads_utf8(self, tmp_path):
        f = tmp_path / "skill.md"
        f.write_text("# Hello\n", encoding="utf-8")
        content, err = read_file_safe(f)
        assert err is None
        assert content == "# Hello\n"

    def test_reads_with_invalid_bytes(self, tmp_path):
        f = tmp_path / "binary.md"
        f.write_bytes(b"hello \xff world")
        content, err = read_file_safe(f)
        assert err is None
        assert content is not None
        assert "hello" in content

    def test_nonexistent_returns_error(self, tmp_path):
        f = tmp_path / "missing.md"
        content, err = read_file_safe(f)
        assert content is None
        assert err is not None


class TestParseJsonSafe:

    def test_valid_json_dict(self):
        data, err = parse_json_safe('{"key": "value"}')
        assert err is None
        assert data == {"key": "value"}

    def test_valid_json_list(self):
        data, err = parse_json_safe("[1, 2, 3]")
        assert err is None
        assert data == [1, 2, 3]

    def test_empty_string(self):
        data, err = parse_json_safe("")
        assert data is None
        assert err is None

    def test_invalid_json(self):
        data, err = parse_json_safe("{broken: }")
        assert data is None
        assert err is not None

    def test_whitespace_only(self):
        data, err = parse_json_safe("   ")
        assert data is None
        assert err is None


class TestParseSeverity:

    def test_valid_severities(self):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert parse_severity(sev) == sev

    def test_lowercase_normalised(self):
        assert parse_severity("high") == "HIGH"
        assert parse_severity("critical") == "CRITICAL"

    def test_invalid_returns_fallback(self):
        assert parse_severity("UNKNOWN") == "HIGH"
        assert parse_severity("INVALID", fallback="MEDIUM") == "MEDIUM"

    def test_empty_returns_fallback(self):
        assert parse_severity("") == "HIGH"


class TestParseCvss:

    def test_float_passthrough(self):
        assert parse_cvss(7.5) == 7.5

    def test_string_parsed(self):
        assert parse_cvss("8.0") == 8.0

    def test_clamped_to_max(self):
        assert parse_cvss(15.0) == 10.0

    def test_clamped_to_min(self):
        assert parse_cvss(-1.0) == 0.0

    def test_none_returns_fallback(self):
        assert parse_cvss(None) == 5.0

    def test_invalid_string_returns_fallback(self):
        assert parse_cvss("notanumber") == 5.0

    def test_custom_fallback(self):
        assert parse_cvss(None, fallback=7.0) == 7.0


class TestTruncateMatch:

    def test_short_string_unchanged(self):
        assert truncate_match("short", 100) == "short"

    def test_long_string_truncated(self):
        result = truncate_match("A" * 300, 100)
        assert len(result) == 100

    def test_strips_whitespace(self):
        assert truncate_match("  hello  ", 100) == "hello"

    def test_none_returns_none(self):
        assert truncate_match(None, 100) is None


class TestTimer:

    def test_elapsed_ms_set_after_context(self):
        import time

        with Timer() as t:
            time.sleep(0.01)
        assert t.elapsed_ms >= 5

    def test_elapsed_ms_zero_before_exit(self):
        t = Timer()
        assert t.elapsed_ms == 0


class TestGetLogger:

    def test_returns_logger(self):
        import logging

        log = get_logger("test.module")
        assert isinstance(log, logging.Logger)

    def test_logger_namespaced(self):
        log = get_logger("test.module")
        assert log.name.startswith("bawbel.")
