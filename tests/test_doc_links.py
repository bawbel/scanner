"""
Documentation URLs the CLI prints.
Issue #133: the pre-commit hook printed a bawbel.io page that returns 404, and nothing
checked any documentation URL.

These tests are offline. The network check for the URLs is scripts/check_doc_links.py,
which runs weekly in .github/workflows/doc-links.yml.

Run: pytest tests/test_doc_links.py -q
"""

import io
import json
import re
import sys
from pathlib import Path

from click.testing import CliRunner
from rich.console import Console

from scanner import docs_urls
from scanner.docs_urls import (
    AVE_STANDARD,
    DOCS_HOME,
    MCP_SPECIFICATION,
    SUPPRESSION_GUIDE,
    WEBSITE,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = REPO_ROOT / "scanner"
MALICIOUS = REPO_ROOT / "tests" / "fixtures" / "skills" / "malicious" / "malicious_skill.md"
BLOB_MAIN = "https://github.com/bawbel/scanner/blob/main/"

# A documentation URL written outside docs_urls.py: a page of the website docs, or a page of
# this repository.
STRAY = re.compile(
    r"https?://(?:www\.)?bawbel\.io/docs|https://github\.com/bawbel/scanner/(?:blob|tree)/"
)


def missing_repo_files(urls: dict[str, str]) -> list[str]:
    """Return the repository paths that a URL points at and that do not exist."""
    missing = []
    for url in urls.values():
        if url.startswith(BLOB_MAIN):
            path = url.removeprefix(BLOB_MAIN)
            if not (REPO_ROOT / path).is_file():
                missing.append(path)
    return missing


def stray_urls(root: Path) -> list[str]:
    """Return 'file:line' for each documentation URL written outside docs_urls.py."""
    found = []
    for path in sorted(root.rglob("*.py")):
        if path.name == "docs_urls.py":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for number, line in enumerate(text.splitlines(), start=1):
            if STRAY.search(line):
                found.append(f"{path.relative_to(root).as_posix()}:{number}")
    return found


class TestDocsUrls:
    def test_constants_are_https_urls_without_whitespace(self):
        urls = docs_urls.all_urls()
        assert urls
        for name, url in urls.items():
            assert re.fullmatch(r"https://\S+", url), name

    def test_at_least_one_url_points_into_this_repository(self):
        # Without this the file check below could pass with nothing to check.
        assert any(u.startswith(BLOB_MAIN) for u in docs_urls.all_urls().values())

    def test_repository_urls_map_to_files_that_exist(self):
        assert missing_repo_files(docs_urls.all_urls()) == []

    def test_a_renamed_file_is_detected(self):
        fake = {"RENAMED": BLOB_MAIN + "docs/guides/renamed-away.md"}
        assert missing_repo_files(fake) == ["docs/guides/renamed-away.md"]

    def test_suppression_guide_explains_the_marker_the_hook_names(self):
        assert SUPPRESSION_GUIDE.startswith(BLOB_MAIN)
        guide = REPO_ROOT / SUPPRESSION_GUIDE.removeprefix(BLOB_MAIN)
        assert "bawbel-ignore" in guide.read_text(encoding="utf-8")


class TestNoStrayUrls:
    def test_no_documentation_url_outside_docs_urls(self):
        assert stray_urls(PACKAGE) == []

    def test_a_stray_url_is_detected(self, tmp_path):
        (tmp_path / "other.py").write_text(
            'HINT = "See: https://bawbel.io/docs/suppression"\n', encoding="utf-8"
        )
        (tmp_path / "docs_urls.py").write_text(
            'HOME = "https://bawbel.io/docs"\n', encoding="utf-8"
        )
        assert stray_urls(tmp_path) == ["other.py:1"]


class TestPrintedUrls:
    def test_hook_points_at_the_suppression_guide(self, monkeypatch, capsys):
        from scanner.bawbel_pre_commit import main

        monkeypatch.setattr(sys, "argv", ["bawbel-pre-commit", str(MALICIOUS)])
        assert main() == 1
        out = capsys.readouterr().out
        assert f"See: {SUPPRESSION_GUIDE}" in out.splitlines()  # the whole line, not a prefix
        assert "bawbel.io/docs/suppression" not in out

    def test_version_links_the_documentation_and_the_standard(self, monkeypatch):
        from scanner.cli import cli
        from scanner.cli import cmd_version

        buffer = io.StringIO()
        recorder = Console(file=buffer, force_terminal=True, legacy_windows=False, width=200)
        monkeypatch.setattr(cmd_version, "console", recorder)
        result = CliRunner().invoke(cli, ["version"])
        assert result.exit_code == 0, result.output
        out = buffer.getvalue()
        assert DOCS_HOME in out
        assert AVE_STANDARD in out

    def test_sarif_uses_the_constants(self, capsys):
        from scanner.cli.shared.formatters import print_sarif
        from scanner.scanner import scan

        print_sarif([scan(str(MALICIOUS))])
        driver = json.loads(capsys.readouterr().out)["runs"][0]["tool"]["driver"]
        assert driver["informationUri"] == WEBSITE
        assert driver["rules"]
        assert all(rule["helpUri"] == AVE_STANDARD for rule in driver["rules"])

    def test_conformance_check_data_carries_the_specification_url(self):
        from scanner.conformance.checks import CHECKS_BY_ID

        assert MCP_SPECIFICATION in CHECKS_BY_ID["uses-streamable-http"].remediation
