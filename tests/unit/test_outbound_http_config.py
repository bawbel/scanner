"""
Tests for outbound HTTP settings: one place (scanner/config), overridable from the
environment, validated, with a User-Agent built from the package version.
"""

import io
import json
import logging
from contextlib import redirect_stdout
from unittest.mock import patch

import pytest

from scanner import __version__
from scanner.cli.cmd_conform import _load_from_registry
from scanner.cli.shared.formatters import print_sarif
from scanner.config import AVE_PROJECT_URL, HTTP_TIMEOUT_SEC, MCP_REGISTRY_URL
from scanner.config.default import env_int
from scanner.models import Severity
from scanner.models.finding import Finding
from scanner.models.result import ScanResult
from scanner.utils import ave_record_url, user_agent


class TestEnvInt:
    def test_unset_uses_default(self, monkeypatch):
        monkeypatch.delenv("BAWBEL_TEST_INT", raising=False)
        assert env_int("BAWBEL_TEST_INT", 10) == 10

    def test_valid_value(self, monkeypatch):
        monkeypatch.setenv("BAWBEL_TEST_INT", " 25 ")
        assert env_int("BAWBEL_TEST_INT", 10) == 25

    @pytest.mark.parametrize("value", ["abc", "0", "-3", "1.5"])
    def test_invalid_value_falls_back_with_a_warning(self, monkeypatch, caplog, value):
        monkeypatch.setenv("BAWBEL_TEST_INT", value)
        with caplog.at_level(logging.WARNING):
            assert env_int("BAWBEL_TEST_INT", 10) == 10
        assert "BAWBEL_TEST_INT" in caplog.text


def test_user_agent_carries_the_package_version():
    assert user_agent().startswith(f"bawbel-scanner/{__version__} ")


def test_registry_lookup_uses_config_url_timeout_and_user_agent():
    with patch("urllib.request.urlopen", side_effect=OSError("offline")) as urlopen:
        data, err = _load_from_registry("io.github.example/server")
    assert data is None and err
    req = urlopen.call_args.args[0]
    assert req.full_url.startswith(f"{MCP_REGISTRY_URL}/v0/servers/")
    assert req.get_header("User-agent") == user_agent()
    assert urlopen.call_args.kwargs["timeout"] == HTTP_TIMEOUT_SEC


def test_sarif_rule_help_links_to_its_ave_record():
    with_id = Finding(
        rule_id="bawbel-a",
        ave_id="AVE-2026-00004",
        title="A",
        description="A.",
        severity=Severity.HIGH,
        aivss_score=7.0,
    )
    without_id = Finding(
        rule_id="bawbel-b",
        ave_id=None,
        title="B",
        description="B.",
        severity=Severity.LOW,
        aivss_score=2.0,
    )
    result = ScanResult(
        file_path="skill.md", component_type="skill", findings=[with_id, without_id]
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        print_sarif([result])
    rules = {r["id"]: r for r in json.loads(buf.getvalue())["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["bawbel-a"]["helpUri"] == ave_record_url("AVE-2026-00004")
    assert rules["bawbel-b"]["helpUri"] == AVE_PROJECT_URL
