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

from scanner import config, docs_urls
from scanner.docs_urls import (
    AVE_STANDARD,
    DOCS_HOME,
    MCP_SPECIFICATION,
    SUPPRESSION_GUIDE,
    WEBSITE,
    display_text,
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


class TestSingleSource:
    """WEBSITE and AVE_STANDARD are scanner.config values, named here for the link check."""

    def test_website_is_the_configured_project_homepage(self):
        assert WEBSITE == config.PROJECT_HOMEPAGE_URL

    def test_ave_standard_is_the_configured_ave_project_url(self):
        assert AVE_STANDARD == config.AVE_PROJECT_URL

    def test_every_url_is_listed_once(self):
        values = list(docs_urls.all_urls().values())
        assert len(values) == len(set(values))

    def test_the_imported_config_names_are_not_listed_as_urls(self):
        names = docs_urls.all_urls()
        assert "AVE_PROJECT_URL" not in names
        assert "PROJECT_HOMEPAGE_URL" not in names

    def test_all_urls_lists_only_public_https_constants(self, monkeypatch):
        # The link check fetches whatever all_urls() returns, so its filter is a contract.
        monkeypatch.setattr(docs_urls, "ONLY_TEXT", "hello", raising=False)
        monkeypatch.setattr(docs_urls, "PLAIN_HTTP", "http://example.invalid/", raising=False)
        monkeypatch.setattr(docs_urls, "_PRIVATE", "https://example.invalid/p", raising=False)
        monkeypatch.setattr(docs_urls, "lowercase", "https://example.invalid/l", raising=False)
        monkeypatch.setattr(docs_urls, "NOT_TEXT", 7, raising=False)
        monkeypatch.setattr(docs_urls, "PUBLIC", "https://example.invalid/ok", raising=False)
        urls = docs_urls.all_urls()
        assert urls["PUBLIC"] == "https://example.invalid/ok"
        for hidden in ("ONLY_TEXT", "PLAIN_HTTP", "_PRIVATE", "lowercase", "NOT_TEXT"):
            assert hidden not in urls

    def test_display_text_drops_the_scheme_and_a_trailing_slash(self):
        assert display_text("https://github.com/aveproject/ave") == "github.com/aveproject/ave"
        assert display_text("https://bawbel.io/") == "bawbel.io"
        assert display_text("https://bawbel.io/docs") == "bawbel.io/docs"


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
        assert "github.com/bawbel/ave" not in out

    def test_version_shows_text_that_matches_each_link_target(self, monkeypatch):
        from scanner.cli import cli
        from scanner.cli import cmd_version

        buffer = io.StringIO()
        # No terminal: rich prints the visible text only, with no link escape sequence.
        # A link target contains the label as a substring, so only this form can tell them apart.
        plain = Console(file=buffer, force_terminal=False, width=200)
        monkeypatch.setattr(cmd_version, "console", plain)
        result = CliRunner().invoke(cli, ["version"])
        assert result.exit_code == 0, result.output
        lines = [line.strip() for line in buffer.getvalue().splitlines()]
        assert f"AVE Standard:  {display_text(AVE_STANDARD)}" in lines
        assert f"Documentation: {display_text(DOCS_HOME)}" in lines

    def test_report_links_the_standard_with_matching_text(self, monkeypatch):
        from scanner.cli import cmd_report
        from scanner.scanner import scan

        result = scan(str(MALICIOUS))
        linked = io.StringIO()
        monkeypatch.setattr(
            cmd_report,
            "console",
            Console(file=linked, force_terminal=True, legacy_windows=False, width=200),
        )
        cmd_report._render_report(result)
        assert AVE_STANDARD in linked.getvalue()

        plain = io.StringIO()
        monkeypatch.setattr(
            cmd_report, "console", Console(file=plain, force_terminal=False, width=200)
        )
        cmd_report._render_report(result)
        lines = [line.strip() for line in plain.getvalue().splitlines()]
        assert f"AVE Standard: {display_text(AVE_STANDARD)}" in lines

    def test_sarif_uses_the_constants(self, capsys):
        from scanner.cli.shared.formatters import print_sarif
        from scanner.scanner import scan

        print_sarif([scan(str(MALICIOUS))])
        driver = json.loads(capsys.readouterr().out)["runs"][0]["tool"]["driver"]
        assert driver["informationUri"] == WEBSITE
        assert driver["rules"]
        # helpUri is a per-finding record URL, with AVE_STANDARD as the fallback. Its
        # shape is tested in tests/unit/test_ave_record_urls.py.

    def test_conformance_check_data_carries_the_specification_url(self):
        from scanner.conformance.checks import CHECKS_BY_ID

        assert MCP_SPECIFICATION in CHECKS_BY_ID["uses-streamable-http"].remediation
