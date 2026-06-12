"""
Unit tests for scanner/engines/llm_engine.py

Tests: _resolve_model() env-var paths, _call_llm() import/exception paths,
_parse_findings() edge cases, run_llm_scan() with model configured.
"""

import json
import sys
from unittest.mock import MagicMock, patch

from scanner.engines.llm_engine import (
    _parse_findings,
    _resolve_model,
    _call_llm,
    run_llm_scan,
)
from scanner.models import Severity


class TestResolveModel:

    def test_returns_explicit_model_from_env(self, monkeypatch):
        """BAWBEL_LLM_MODEL env var takes priority over API key auto-detect."""
        monkeypatch.setenv("BAWBEL_LLM_MODEL", "ollama/mistral")
        for key in [
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "GEMINI_API_KEY",
            "MISTRAL_API_KEY",
            "COHERE_API_KEY",
            "GROQ_API_KEY",
        ]:
            monkeypatch.delenv(key, raising=False)

        with patch("scanner.engines.llm_engine.LLM_ENABLED", True):
            result = _resolve_model()

        assert result == "ollama/mistral"

    def test_returns_default_model_from_api_key(self, monkeypatch):
        """Known API key present → return its default model."""
        monkeypatch.delenv("BAWBEL_LLM_MODEL", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-key")
        for key in [
            "OPENAI_API_KEY",
            "GEMINI_API_KEY",
            "MISTRAL_API_KEY",
            "COHERE_API_KEY",
            "GROQ_API_KEY",
        ]:
            monkeypatch.delenv(key, raising=False)

        with patch("scanner.engines.llm_engine.LLM_ENABLED", True):
            result = _resolve_model()

        assert result == "claude-haiku-4-5-20251001"

    def test_returns_none_when_llm_disabled(self):
        """LLM_ENABLED=False → always return None."""
        with patch("scanner.engines.llm_engine.LLM_ENABLED", False):
            result = _resolve_model()
        assert result is None


class TestCallLlm:

    def test_returns_none_when_litellm_not_installed(self):
        """ImportError on litellm import → returns None, never raises."""
        with patch.dict(sys.modules, {"litellm": None}):
            result = _call_llm("gpt-4o", "content")
        assert result is None

    def test_returns_response_content_on_success(self):
        """Successful litellm call → returns the text content."""
        mock_litellm = MagicMock()
        mock_response = MagicMock()
        mock_response.choices[0].message.content = '["finding"]'
        mock_litellm.completion.return_value = mock_response

        with patch.dict(sys.modules, {"litellm": mock_litellm}):
            result = _call_llm("gpt-4o", "some content")

        assert result == '["finding"]'

    def test_returns_none_on_exception(self):
        """Exception during litellm.completion → returns None, never raises."""
        mock_litellm = MagicMock()
        mock_litellm.completion.side_effect = RuntimeError("API quota exceeded")

        with patch.dict(sys.modules, {"litellm": mock_litellm}):
            result = _call_llm("gpt-4o", "some content")

        assert result is None


class TestParseFindings:

    def test_returns_empty_for_non_list_json(self):
        """JSON object (not array) → log warning, return []."""
        result = _parse_findings('{"not": "a list"}')
        assert result == []

    def test_skips_non_dict_items(self):
        """Non-dict items in array → skipped silently."""
        result = _parse_findings('[1, "string", null, true]')
        assert result == []

    def test_mixed_valid_and_invalid_items(self):
        """Mix of non-dict and dict items → only dict items become findings."""
        raw = json.dumps(
            [
                "not a dict",
                {
                    "rule_id": "llm-injection",
                    "title": "Prompt Injection",
                    "description": "Malicious instruction found",
                    "severity": "HIGH",
                    "aivss_score": 7.0,
                    "confidence": "HIGH",
                },
            ]
        )
        result = _parse_findings(raw)
        assert len(result) == 1
        assert result[0].rule_id == "llm-injection"

    def test_severity_falls_back_to_medium_on_invalid(self, monkeypatch):
        """parse_severity returning an unmapped value → fallback to MEDIUM."""
        monkeypatch.setattr("scanner.engines.llm_engine.parse_severity", lambda x: "NOTREAL")

        raw = json.dumps(
            [
                {
                    "rule_id": "llm-test",
                    "title": "Test",
                    "description": "Desc",
                    "severity": "BIZARRE",
                    "aivss_score": 5.0,
                    "confidence": "HIGH",
                }
            ]
        )
        result = _parse_findings(raw)
        assert len(result) == 1
        assert result[0].severity == Severity.MEDIUM

    def test_exception_in_item_parse_continues(self, monkeypatch):
        """Exception while building a Finding → item skipped, loop continues."""

        def _bad_finding(**kwargs):
            raise TypeError("unexpected field")

        monkeypatch.setattr("scanner.engines.llm_engine.Finding", _bad_finding)

        raw = json.dumps(
            [
                {
                    "rule_id": "llm-test",
                    "title": "Test",
                    "description": "Desc",
                    "severity": "HIGH",
                    "aivss_score": 7.0,
                    "confidence": "HIGH",
                }
            ]
        )
        result = _parse_findings(raw)
        assert result == []


class TestRunLlmScan:

    def test_returns_findings_when_model_configured(self):
        """run_llm_scan() calls _call_llm and parses results."""
        mock_raw = json.dumps(
            [
                {
                    "rule_id": "llm-goal-override",
                    "title": "Goal Override Detected",
                    "description": "The skill overrides the agent goal",
                    "severity": "HIGH",
                    "aivss_score": 8.0,
                    "confidence": "HIGH",
                }
            ]
        )

        with (
            patch("scanner.engines.llm_engine._resolve_model", return_value="gpt-4o"),
            patch("scanner.engines.llm_engine._call_llm", return_value=mock_raw),
        ):
            result = run_llm_scan("some malicious content here")

        assert len(result) == 1
        assert result[0].engine == "llm"
        assert result[0].rule_id == "llm-goal-override"

    def test_returns_empty_when_call_llm_returns_none(self):
        """If _call_llm returns None (failure), run_llm_scan returns []."""
        with (
            patch("scanner.engines.llm_engine._resolve_model", return_value="gpt-4o"),
            patch("scanner.engines.llm_engine._call_llm", return_value=None),
        ):
            result = run_llm_scan("content")
        assert result == []

    def test_truncates_long_content(self):
        """Content longer than LLM_MAX_CHARS is truncated before sending."""
        captured = []

        def capture_call(model, content):
            captured.append(content)
            return "[]"

        with (
            patch("scanner.engines.llm_engine._resolve_model", return_value="gpt-4o"),
            patch("scanner.engines.llm_engine._call_llm", side_effect=capture_call),
            patch("scanner.engines.llm_engine.LLM_MAX_CHARS", 10),
        ):
            run_llm_scan("x" * 100)

        assert len(captured) == 1
        assert len(captured[0]) == 10
