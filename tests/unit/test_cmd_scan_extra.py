"""
Unit tests for scanner/cli/cmd_scan.py

Tests error paths not covered by integration tests:
  - resolve_path fails (symlink input) → exit 1
  - Empty directory (no scannable files) → exit 0
"""

from click.testing import CliRunner

from scanner.cli.cmd_scan import scan_cmd


class TestScanCmdErrorPaths:

    def test_symlink_input_exits_one(self, tmp_path):
        """Symlink path → resolve_path error → exit code 1."""
        real = tmp_path / "real.md"
        real.write_text("# Skill\nContent")
        link = tmp_path / "link.md"
        link.symlink_to(real)

        runner = CliRunner()
        result = runner.invoke(scan_cmd, [str(link)])

        assert result.exit_code == 1

    def test_empty_directory_exits_zero(self, tmp_path):
        """Directory with no scannable files → 'No scannable files found', exit 0."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        # Add a non-scannable file to confirm it's ignored
        (empty_dir / "readme.txt").write_text("not scannable")

        runner = CliRunner()
        result = runner.invoke(scan_cmd, [str(empty_dir)])

        assert result.exit_code == 0
