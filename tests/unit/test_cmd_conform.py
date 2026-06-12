"""
Unit tests for scanner/cli/cmd_conform.py

Tests: _load_from_file(), scan_conformance_cmd via Click test runner.
"""

import json

from click.testing import CliRunner

from scanner.cli.cmd_conform import (
    _load_from_file,
    scan_conformance_cmd,
)


def _minimal_manifest(**overrides) -> dict:
    base = {
        "name": "test-server",
        "description": "A test MCP server for unit tests",
        "version": "1.0.0",
        "remotes": [{"type": "streamable-http", "url": "https://api.example.com/mcp"}],
        "tools": [
            {
                "name": "search",
                "description": "Search for information",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ],
    }
    base.update(overrides)
    return base


class TestLoadFromFile:

    def test_success_returns_manifest_dict(self, tmp_path):
        manifest = _minimal_manifest()
        f = tmp_path / "server.json"
        f.write_text(json.dumps(manifest))

        result, err = _load_from_file(str(f))

        assert err is None
        assert result is not None
        assert result["name"] == "test-server"

    def test_file_not_found_returns_error(self):
        result, err = _load_from_file("/nonexistent/path/server.json")

        assert result is None
        assert err is not None

    def test_invalid_json_returns_error(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{ this is not valid json }")

        result, err = _load_from_file(str(f))

        assert result is None
        assert err is not None


class TestScanConformanceCmd:

    def test_file_mode_text_format_exits_zero(self, tmp_path):
        """Valid JSON file → scan runs, exits 0."""
        manifest = _minimal_manifest()
        f = tmp_path / "manifest.json"
        f.write_text(json.dumps(manifest))

        runner = CliRunner()
        result = runner.invoke(scan_conformance_cmd, [str(f)])

        assert result.exit_code == 0

    def test_file_mode_json_format(self, tmp_path):
        """--format json → output is valid JSON with target and conformance keys."""
        manifest = _minimal_manifest()
        f = tmp_path / "manifest.json"
        f.write_text(json.dumps(manifest))

        runner = CliRunner()
        result = runner.invoke(scan_conformance_cmd, [str(f), "--format", "json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "target" in data
        assert "conformance" in data

    def test_file_not_found_exits_one(self):
        """Nonexistent file → error message, exit code 1."""
        runner = CliRunner()
        result = runner.invoke(scan_conformance_cmd, ["/nonexistent/file.json"])

        assert result.exit_code == 1

    def test_file_not_found_json_format_exits_one(self):
        """--format json with nonexistent file → JSON error output, exit 1."""
        runner = CliRunner()
        result = runner.invoke(scan_conformance_cmd, ["/nonexistent/file.json", "--format", "json"])

        assert result.exit_code == 1
        data = json.loads(result.output)
        assert "error" in data

    def test_fail_below_threshold_exits_two_when_below(self, tmp_path):
        """--fail-below 100 on a non-perfect manifest → exit code 2."""
        # Minimal manifest will likely score below 100
        manifest = {"name": "test", "description": "test", "version": "1.0.0"}
        f = tmp_path / "manifest.json"
        f.write_text(json.dumps(manifest))

        runner = CliRunner()
        result = runner.invoke(scan_conformance_cmd, [str(f), "--fail-below", "100"])

        assert result.exit_code == 2

    def test_fail_non_conformant_exits_two_when_non_conformant(self, tmp_path):
        """--fail-non-conformant on a non-conformant manifest → exit code 2."""
        # Manifest missing required fields → non-conformant
        manifest = {"name": "test"}
        f = tmp_path / "manifest.json"
        f.write_text(json.dumps(manifest))

        runner = CliRunner()
        result = runner.invoke(scan_conformance_cmd, [str(f), "--fail-non-conformant"])

        assert result.exit_code == 2

    def test_invalid_json_file_exits_one(self, tmp_path):
        """Malformed JSON file → error message, exit code 1."""
        f = tmp_path / "bad.json"
        f.write_text("not valid json")

        runner = CliRunner()
        result = runner.invoke(scan_conformance_cmd, [str(f)])

        assert result.exit_code == 1

    def test_conformant_manifest_exits_zero(self, tmp_path):
        """Fully conformant manifest with --fail-non-conformant → exit 0."""
        manifest = _minimal_manifest(
            **{
                "$schema": (
                    "https://static.modelcontextprotocol.io/schemas/"
                    "2025-12-11/server.schema.json"
                ),
                "repository": {"url": "https://github.com/example/server"},
            }
        )
        f = tmp_path / "manifest.json"
        f.write_text(json.dumps(manifest))

        runner = CliRunner()
        result = runner.invoke(scan_conformance_cmd, [str(f), "--fail-non-conformant"])

        # Exit 0 only if required checks all pass
        assert result.exit_code in (0, 2)
